# Roadmap

Open work, and where the detail for each item already lives. This file is an
index plus the items that had nowhere else to go; it does not restate the
reasoning in the documents it points at.

Nothing here is scheduled. Order within a section is rough priority, not a plan.

---

## Hardening regressions from the retired prototype

Retiring the esp-idf crate dropped two `sdkconfig` settings that had no
bare-metal equivalent. `docs/ARCHITECTURE.md` records where the settings table
used to be; this is the tracking entry.

### Memory protection (was `CONFIG_ESP_SYSTEM_MEMPROT_FEATURE`)

**Status: absent, no upstream support.**

On the ESP32-S3 this is the PMS block, reached through the `SENSITIVE`
peripheral. That peripheral exists as a singleton in `esp-metadata-generated`,
so the registers are addressable — but **esp-hal 1.1.2 ships no memprot or PMS
driver**, and nothing in `esp-hal/src` references it.

Two routes, neither cheap:

- Drive the `SENSITIVE` registers directly from the firmware. Fastest to a
  working result, and it means owning a chunk of undocumented-in-Rust register
  programming that upstream will eventually duplicate.
- Contribute a driver to esp-hal. Slower, but this is exactly the kind of gap
  the migration to esp-hal was supposed to close rather than route around.

Worth sizing before choosing. The security value is real but bounded: it makes
regions non-writable or non-executable, which mitigates code injection on a
device whose threat model already concedes physical access and reflashing
(`THREAT_MODEL.md`).

### Stack canaries (was `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG`)

**Status: partly covered already, by an esp-hal default nobody chose.**

esp-hal places a sentinel 60 bytes from the stack's end and watches it with a
data watchpoint. `ESP_HAL_CONFIG_STACK_GUARD_MONITORING` defaults to `true` and
the firmware does not override it, so this is live today — a write past the
guard panics with "Detected a write to the stack guard value".

That is **stack-overflow detection, not what the ESP-IDF setting did.**
`CONFIG_COMPILER_STACK_CHECK_MODE_STRONG` is GCC's `-fstack-protector-strong`:
a canary per function frame, catching a smash *within* the stack rather than a
run off the end of it.

So the remaining gap is per-frame canaries, and the honest question is whether
they are worth it here:

- Rust's equivalent is `-Z stack-protector`, which is nightly-only. The `esp`
  toolchain is a nightly fork and the crate already sets `[unstable] build-std`,
  so it is plausibly reachable — **untested**, and worth ten minutes to find out
  before any of this is argued further.
- The attack `-fstack-protector-strong` defends against is a buffer overflow in
  C. This firmware has no `unsafe` outside the entropy driver and no parsing of
  attacker-supplied input at all — the device only ever signs data it
  constructed itself. The value here is lower than the prototype's config
  implied.

Two things to do before deciding: confirm `-Z stack-protector` builds under the
`esp` toolchain, and record the code-size cost. If it is free, take it; if it
is not, this is arguably a setting the prototype carried without needing it.

---

## Cooldown must survive deep sleep

**Application-layer. Not gate-blocked** — this touches neither §7, the token
protocol, nor D12, so it can be scheduled whenever. The decision is ours, not the
reviewer's.

### The finding

Deep sleep on the ESP32-S3 is effectively a reset: RAM goes, including
`icesickle_core::cooldown`'s state. A device woken repeatedly — sleep, wake,
attest, sleep — starts each cycle with an empty cooldown, so the rate limit
evaporates every cycle. **A rate limit that resets on every wake is not a rate
limit**, and the failure is silent: nothing logs, nothing fails, the device just
stops limiting.

It is a direct consequence of the power design. The same deep sleep that gets us
toward the standby target is what erases the state, so the two requirements pull
against each other and something has to persist across the reset.

Surfaced by the Brief 3 scaffolding and recorded in
`firmware/nostd/src/bin/sleep_bench.rs`, which is where whoever moves the real
firmware to deep sleep will meet it first.

### Persisting the value is not enough — the clock has to survive too

This is the part most likely to produce a fix that looks right and does nothing.

The cooldown compares a stored timestamp against `now_ms`. Today that comes from
`Instant::now()`, which is the system timer and **restarts at zero after deep
sleep**. Persist the last-attestation timestamp without changing the time base
and every wake compares a large saved value against a counter that just reset —
`checked_sub` returns `None`, the cooldown fails open by design
(`cooldown.rs`), and the rate limit is exactly as absent as before, now behind
code that appears to address it.

So any fix is two changes, not one: **persist the state, and move the time base
to a clock that survives the reset.**

### Two stores

**1. RTC-backed memory.** The ESP32-S3 keeps an RTC domain powered through deep
sleep. esp-hal exposes `#[ram(unstable(persistent))]` for variables that survive
it, and `Rtc::time_since_power_up()` for a counter measured from power-up rather
than from boot — which is the matching time base. Cheapest option, and both
halves are already available.

Its limit is exactly its name: it survives deep sleep, not a power loss or a
battery pull.

**2. A battery-backed external RTC.** Survives full power loss, which matters
under the seizure and duress threat model where an adversary may simply cycle
power. Store the last-attestation time and compute the cooldown against real
wall-clock time on wake.

**D13 resolved this.** The clock is confirmed intended hardware, so option 2 is
available — and since it survives a battery pull it is the stronger store. The
recommendation below is superseded on that point; what stands is that the fix is
still *two* changes, and that the clock stores time and nothing else.

### The recommendation

Option 1, unless the cooldown must survive a battery pull.

The argument for option 2 is real — an adversary who can pull the battery can
reset the rate limit — but so can an adversary who can reflash, which the threat
model already concedes. Both require the same physical access. Option 1 closes
the accidental case (a device that sleeps normally) without adding a component,
and the deliberate case was never closed by either option.

### An external RTC is not in this repo, and would change more than the cooldown

Flagged because it was proposed as already present: **there is no DS3231, no I2C,
no coin cell, and no external clock anywhere in this repository** — no
dependency, no driver, no mention in any document. If one is planned, it lives in
the `.docx` narrative documents this file's siblings still need reconciling with.

That matters well beyond this item, because the device having no trusted clock is
a load-bearing premise in decisions that are already merged:

- `VERIFIER_MODEL.md` §1 states plainly that `timestamp_ms` is milliseconds since
  boot, meaningless across a power cycle and meaningless to a third party because
  nothing anchors what "boot" was.
- §3.2's preloaded beacon and §3.3's ingest co-signature exist **specifically
  because** the device cannot be trusted to say what time it is. A real clock
  would not make them redundant — the device could still lie — but it would
  change the argument for why they are shaped as they are.
- D10 leans on the same asymmetry when it gives verifiers a clock for certificate
  expiry and denies the device one.

So if a battery-backed RTC is genuinely in the hardware plan, **it should be
recorded as a decision in its own right and those sections revisited** — not
adopted sideways as an implementation detail of a rate limit.

### Already handled

A trigger held at boot would wake the device continuously, turning standby into
an always-on duty cycle and destroying the power budget. The Brief 3 scaffold
reads the pin before consuming it as a wake source and warns. No further action
unless bench testing shows the warning is insufficient.

## The DS3231: codec and transport done, wiring next

D13 confirmed the clock as intended hardware and left "no I2C driver exists" as
real work. It exists now.

**Done:** `crates/icesickle-core/src/clock.rs` — the register codec. Registers
`0x00`–`0x06` and the status byte in, Unix milliseconds out, with the reads that
must not be believed rejected rather than decoded: a raised oscillator-stop flag
(the coin cell died and the registers are stale but well-formed), a floating bus
reading `0xFF`, a chip left in 12-hour mode, and impossible dates including the
2100-02-29 the DS3231's own leap-year rule will eventually produce. Host-tested
on stable, no hardware, following the same seam as `button` and `cooldown`.

**Also done:** the transport, split the way
[issue #24](https://github.com/Mezo-oz/IceSickle/issues/24) settled it. The
`RegisterBus` trait, `read_clock` and `set_clock` are in the core crate;
`firmware/nostd/src/clock.rs` is a ~12-line implementation that forwards bytes
and decides nothing.

The split was chosen over a CI source guard for a reason that only turned up
while sizing it: **it moves the ordering rules into reach of a host test.** The
stop flag must be read before the time registers mean anything, and the clock
must be set before that flag is acknowledged — and a driver holding those rules
holds them where nothing can check them, since `firmware/nostd` can host no
tests at all. A mock bus now covers both on stable. That was worth more than the
register ban the trait was designed around.

**Not done, in order:**

1. **Wiring it into the firmware.** `firmware/nostd/src/bin/main.rs:62` still
   defines `now_ms()` as `Instant::now()`, and line 156 still prints
   `"ms since boot"`. Until that changes the firmware cannot produce the Unix
   `timestamp_ms` that D13 made mandatory and that `TOKEN_PROTOCOL.md` §5,
   `VERIFIER_MODEL.md` §1 and `AttestationPayload` already document — **the
   docs and the code currently disagree on main, and the §6 step 8 arrival
   check is unimplementable until they stop.**

   Two things the wiring has to answer that the transport did not: which GPIOs
   carry SDA and SCL (a board fact, currently written down nowhere), and what a
   device does when the clock is absent or its cell is dead. The second is not a
   detail — **QEMU models no DS3231**, so whatever the firmware does on a failed
   read is what the emulator job will exercise on every run.
2. **Cooldown persistence**, below, which needs a time base that survives the
   reset and now has one.

**A rule the hardware does not enforce, so the code does.** D13 says the clock
stores time and nothing else. It is tempting to treat that as closed by the part
choice, since the DS3231 has no general-purpose NVRAM the way a DS1307 does. It
is not: the alarm registers are writable, battery-backed, unused, and seven
bytes wide, which is a scratchpad under another name. The aging offset is
another byte.

`clock.rs` therefore makes a write to those eight bytes **unrepresentable**
rather than merely discouraged. `RegisterWrite` has private fields and no public
constructor, so the only writes that can exist are the two the module builds,
and `every_register_is_classified` requires all three register sets — permitted,
scratchpad, unused — to partition `0x00..=0x12` exactly once each. Using a
battery-backed register means moving it out of the scratchpad set in a diff,
rather than simply not noticing the rule.

Two limits worth keeping in view:

- **This does not stop raw I2C.** Firmware can still drive the bus directly, and
  no type in a host crate can prevent that. The driver's write path does take a
  `RegisterWrite` rather than a `(register, bytes)` pair, so the seam the ban
  could have leaked through is closed; what remains is that `Ds3231::new`
  **consumes** the `I2c` peripheral, so no raw handle survives elsewhere and the
  only code that can reach the part is two method bodies. That is a surface
  small enough to read, not a proof. **Any future change that hands the
  peripheral out again reopens this**, and #24 records it as an acceptance
  criterion rather than a preference.
- **Do not substitute a DS3234.** The SPI sibling of this part carries 256 bytes
  of battery-backed SRAM, which would turn a rule that is currently easy to keep
  into one that is easy to break.

---

## Already documented elsewhere

Pointers, not summaries. Each of these is developed where it is linked.

**v2 token protocol** — `docs/TOKEN_PROTOCOL.md` §11 is the live list:

- ~~Issuer key distribution.~~ **Settled** as D10: verifiers pin a long-lived
  operator root key and accept epoch keys by certificate, rather than pinning
  the epoch keys themselves. `TOKEN_PROTOCOL.md` §10 has the format and the
  check.
- ~~Epoch length.~~ **Settled** as D11: a 7-day beacon round and a 28-day key
  epoch, split apart because `beacon_round` and `key_id` were always separate
  payload fields answering different questions.
- ~~Is the payload sealed, or in the clear?~~ **Answered** by D12: a cleartext
  genuineness layer the Verifier checks, a sealed content layer only the Sink
  opens. D12 is **provisional pending the security gate**.
- **The sealed content layer does not fit the frame.** Arithmetic, not judgement:
  24 bytes of `P` must stay cleartext for §6, leaving 40 against a sealed box's
  48 bytes of overhead. D12 lists four routes and picks none. Blocks the content
  layer; the genuineness layer is unaffected.
- Beacon source — external (drand) versus verifier-signed.
- Entropy re-scoping — v2 moves key generation from press time to provisioning
  time, so `docs/NOSTD_ENTROPY_SPIKE.md` guards the right secret at the wrong
  moment.
- **Cryptographic review — a hard gate, not a task.** §7 is a sketch by a
  non-specialist and says so, and D10, D11 and D12 now all rest on it. Tracked as
  [issue #16](https://github.com/Mezo-oz/IceSickle/issues/16), which also carries
  the D12 binding-composition and `T`-key-reuse questions. **No security-relevant
  decision after D12 may be built until it closes**, and it does not close by
  non-specialist agreement.

**Hardware validation** — `docs/NOSTD_ENTROPY_SPIKE.md`, Status. Every item
needs silicon; no emulator can substitute, because QEMU's RNG returns host
randomness regardless of whether the SAR-ADC path is live.

- Statistical validation of TRNG output. The spike proves the source is
  *enabled*, never that it is good.
- Power and timing cost of holding the SAR ADC on continuously.

**Feature ideas** — `docs/ARCHITECTURE.md`, Future Extensions:
challenge-response, a persistent counter, more event types, batch signing. These
are sketches, not commitments, and some conflict with the v2 payload budget.
