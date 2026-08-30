//! IceSickle no_std firmware.
//!
//! Boot sequence, in order:
//!
//! 1. Demonstrate that `Trng` is unavailable before an entropy source exists
//!    (the gate).
//! 2. Bring up the SAR-ADC entropy source explicitly.
//! 3. Bring up the DS3231 and report what it says, or why it cannot be read.
//! 4. Enter the event loop: a debounced button press, gated by the cooldown,
//!    produces one attestation whose key was derived from that source and whose
//!    timestamp came from that clock.
//!
//! Step 4 replaces the spike's unconditional sign-at-boot. A device that
//! attests without a physical event is attesting to nothing, and the whole
//! claim of the payload is that a person did something. The entropy prints in
//! steps 1 and 2 stay: they are the only evidence the gate held, and the only
//! thing the emulator can observe.
//!
//! # Two clocks, and why they are not one
//!
//! There are two time bases here and they are not interchangeable:
//!
//! - [`uptime_ms`] is `Instant::now()`: monotonic, millisecond resolution,
//!   meaningless the moment the device power-cycles. It drives the **debounce
//!   and the cooldown**.
//! - The DS3231 is wall-clock: Unix milliseconds, survives a power cycle,
//!   **one-second resolution**. It supplies `timestamp_ms`, and nothing else.
//!
//! It is tempting to read `docs/ROADMAP.md`'s "move the time base to a clock
//! that survives the reset" as replacing `uptime_ms` outright. That would break
//! the device quietly. The debounce window is 50 ms and the part counts whole
//! seconds, so a debounce driven by the DS3231 sees the same instant for twenty
//! consecutive polls and every press either passes unfiltered or never
//! resolves; the 1000 ms cooldown would quantize to somewhere between 0 and
//! 1000 ms depending on where in the second the press landed. Neither failure
//! prints anything.
//!
//! So the split is the design, not a stepping stone. What the roadmap item is
//! really about — a cooldown that survives deep sleep — needs the wall clock
//! for the part that crosses the sleep boundary, and still wants `uptime_ms`
//! for the part that does not.
//!
//! # What happens without a clock
//!
//! The device stays alive and refuses to attest, naming the specific reason.
//! D13 made `timestamp_ms` Unix wall-clock time and the verifier's arrival
//! check (`TOKEN_PROTOCOL.md` §6 step 8) compares it against a real clock, so
//! there is no honest fallback: substituting uptime here would emit a number
//! that is the right type, the wrong quantity, and indistinguishable from a
//! real timestamp downstream — precisely the failure `icesickle_core::clock`
//! spends three separate checks refusing to make.
//!
//! Refusing is not the whole of it. **Which** failure it was decides what the
//! holder should do — a dead coin cell is a part from any supermarket, a
//! floating bus is not a field repair — so the cause travels from the register
//! that failed all the way to the console, and never collapses into "clock
//! error" on the way. See [`report_clock_failure`].

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::sync::atomic::{AtomicU32, Ordering};

use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout};
use esp_hal::main;
use esp_hal::time::{Duration, Instant};
use esp_println::println;

use icesickle_core::button::Edge;
use icesickle_core::clock::{CivilTime, ReadError, read_clock_civil};
use icesickle_core::cooldown::{Cooldown, DEFAULT_COOLDOWN_MS};
use icesickle_core::{Attestation, AttestationEvent};
use icesickle_nostd::button::Button;
use icesickle_nostd::clock::Ds3231;
use icesickle_nostd::entropy::{EntropySource, trng_available};

// This creates a default app-descriptor required by the esp-idf bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

/// GPIO the trigger is wired to, and the number the payload records.
///
/// GPIO0 is the BOOT button on most ESP32-S3 devkits. Unlike the esp-idf
/// prototype, this constant is not a second source of truth: the pin is taken
/// from `Peripherals` below and this only labels it, but the two still have to
/// agree, because esp-hal pins are distinct types and the number cannot be
/// recovered from one.
const BUTTON_PIN: u8 = 0;

/// I2C pins for the DS3231.
///
/// **UNCONFIRMED. These are a guess with a good pedigree, not a board fact.**
/// GPIO8/GPIO9 is Espressif's conventional S3 pairing and what the devkit
/// examples use, which makes it the right default and no more than that. The
/// schematic is what settles it, and nothing in this repository is the
/// schematic.
///
/// They are named here, next to `BUTTON_PIN`, so that correcting them is one
/// visible line rather than a hunt through `main` — but as with `BUTTON_PIN`,
/// esp-hal pins are distinct types, so the constants label the peripherals
/// taken below and the two have to be changed together.
///
/// # Why this is not just a comment
///
/// A doc comment saying "unconfirmed" is true the day it is written and skimmed
/// past every day after. This assumption has to survive being *forgotten*, not
/// merely being read, because the failure it produces is the least diagnosable
/// one this firmware has: wrong pins give a clock that never answers, which is
/// reported — correctly, and uselessly — as a hardware fault on a device where
/// the hardware is fine.
///
/// So it announces itself three ways, and [`PINS_UNCONFIRMED`] is the one that
/// matters: **the device says it out loud at every boot**, in front of whoever
/// is holding a board the first time they power it on. `TODO(pins)` below makes
/// it greppable, and a CI step fails the build if the marker is still here while
/// the boot line is gone — so the assumption cannot quietly stop announcing
/// itself. Removing all three together is what confirming the pins looks like.
///
/// TODO(pins): GPIO8/GPIO9 UNCONFIRMED — verify against the schematic before
/// hardware bring-up, then delete `PINS_UNCONFIRMED` and its boot line.
const SDA_PIN: u8 = 8;
const SCL_PIN: u8 = 9;

/// Printed at boot for as long as [`SDA_PIN`] and [`SCL_PIN`] are a guess.
///
/// Delete this constant and the `println!` that uses it in the same change that
/// confirms the pins — not before, and not separately. Its whole value is that
/// it is impossible to power on a unit without being told, so a build that has
/// stopped saying it is claiming the pins are known.
const PINS_UNCONFIRMED: &str = "note: I2C pins are UNCONFIRMED against the schematic";

/// How often the button is sampled. Well inside the 50 ms debounce window, so
/// no press can be slept through.
const POLL_INTERVAL_MS: u32 = 10;

/// Longest any single I2C transaction may take before it is abandoned.
///
/// esp-hal defaults `SoftwareTimeout` to `None`, which is wrong for this
/// device. The DS3231 is the one part that may legitimately be missing in the
/// field — a dead cell, a broken solder joint, a unit assembled without it —
/// and with no pull-ups holding the lines, an absent part can leave SDA low
/// rather than cleanly NAKing. A blocking driver with no timeout then waits
/// forever, at boot, before anything has printed.
///
/// That converts the one failure this firmware is built to report clearly into
/// a device that looks dead and says nothing. 50 ms is far longer than the
/// ~2 ms a nine-byte transfer needs at 100 kHz, and far shorter than a person
/// waiting to see whether the thing switched on.
const I2C_TIMEOUT_MS: u64 = 50;

/// Monotonic counter. Resets on power cycle, like the cooldown.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Milliseconds since boot: monotonic, and reset by any power cycle.
///
/// This is the debounce and cooldown time base and **not** the attestation
/// timestamp — see the module docs on why the two cannot be the same function.
/// The name says `uptime` rather than `now` for that reason: `now_ms()` read as
/// "the current time" is exactly the misreading that puts a since-boot counter
/// into a signed payload.
fn uptime_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

#[allow(
    clippy::large_stack_frames,
    reason = "the signing path keeps a seed, an expanded key, a signature and fixed hex buffers on the stack; with no allocator that is the point, not an oversight"
)]
#[main]
fn main() -> ! {
    // Output goes through `println!` rather than the `log` facade on purpose:
    // an attestation is the device's product, not a diagnostic, and it should
    // not disappear because a logger was misconfigured or filtered out.
    //
    // Printed before esp_hal::init so that a hang or fault inside init is
    // distinguishable from a console that is not wired up at all.
    println!("IceSickle no_std firmware");

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    println!("esp_hal::init done");

    // 1. The gate. Before any TrngSource exists, esp-hal refuses to hand out a
    //    Trng at all. This is the property the migration is buying, and the
    //    esp-idf prototype had no equivalent -- esp_fill_random() would have
    //    happily returned pseudo-random bytes here with no indication.
    if trng_available() {
        println!("UNEXPECTED: true entropy reported available before TrngSource exists");
    } else {
        println!("gate holds: no true entropy available before TrngSource exists");
    }

    // 2. Enable the SAR-ADC entropy source. Consumes RNG and ADC1 for good.
    //    The RF subsystem stays off: this device is radio-silent by identity,
    //    which is exactly why the ADC path has to carry the entropy claim.
    let entropy_source = EntropySource::new(peripherals.RNG, peripherals.ADC1);
    println!("TrngSource live: SAR-ADC entropy enabled, radio off");

    if trng_available() {
        println!("gate open: true entropy available");
    } else {
        println!("UNEXPECTED: TrngSource is live but true entropy is unavailable");
    }

    // 3. The clock. `Ds3231::new` consumes the I2C peripheral, so from here on
    //    the only code in this binary that can reach the bus is the two method
    //    bodies in `icesickle_nostd::clock` -- which is the ownership half of
    //    the scratchpad ban (issue #24), and the reason the peripheral is not
    //    kept around for anything else.
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_software_timeout(SoftwareTimeout::Transaction(
            Duration::from_millis(I2C_TIMEOUT_MS),
        )),
    )
    // Nothing here comes from the field: the frequency is the default and the
    // timeout is a constant above, so a rejection is this file being wrong
    // rather than the hardware being absent. It is not the failure the clock
    // reporting below exists for, and dressing it up as one would put a build
    // bug behind a message telling someone to buy a battery.
    .expect("I2C config is built from constants; a rejection here is a bug in main.rs")
    .with_sda(peripherals.GPIO8)
    .with_scl(peripherals.GPIO9);
    let mut clock = Ds3231::new(i2c);

    // Said before the first read, not after it, so it is on screen whether or
    // not the read succeeds. Wrong pins and an absent part produce the identical
    // symptom, and this is the line that tells the two apart.
    println!("{PINS_UNCONFIRMED}: SDA=GPIO{SDA_PIN} SCL=GPIO{SCL_PIN}");

    // Read it once, now, so a dead cell is discovered at power-on rather than
    // at the moment somebody needs to attest. This read is a report and nothing
    // depends on it: the value is deliberately not cached, because a clock that
    // was healthy at boot is not evidence about a clock at press time, and every
    // attestation below reads it again.
    match read_clock_civil(&mut clock) {
        Ok(time) => println!("clock: OK   {} ({} ms)", IsoTime(time), time.unix_ms()),
        Err(error) => report_clock_failure("clock", &error),
    }

    // 4. The event loop.
    let delay = Delay::new();
    let mut button = Button::new(peripherals.GPIO0, uptime_ms());
    let mut cooldown = Cooldown::new(DEFAULT_COOLDOWN_MS);

    if button.is_pressed() {
        println!("note: trigger held at boot; a press requires releasing it first");
    }
    println!("ready: press GPIO{BUTTON_PIN} to attest");

    loop {
        let uptime = uptime_ms();

        if button.poll(uptime) == Some(Edge::Pressed) {
            // The clock is read *before* the cooldown is gated, and the order is
            // load-bearing in a way that is easy to get backwards.
            //
            // `Cooldown::gate` records on success, so gating first would consume
            // the cooldown for an attestation that then never happened. On a
            // device with a dead cell every press after the first would be
            // answered "cooldown: 900 ms remaining" -- true, useless, and
            // hiding the only fact worth reporting. The real cause would be
            // visible on the first press of each second and masked on the rest.
            //
            // Reading first costs nothing that the old ordering protected. The
            // reason the gate came early was that a rejected press must not
            // spend entropy or key material, and it still does not: the draw is
            // inside `attest`, after both checks.
            let timestamp_ms = match read_clock_civil(&mut clock) {
                Ok(time) => time.unix_ms(),
                Err(error) => {
                    report_clock_failure("attestation refused", &error);
                    delay.delay_millis(POLL_INTERVAL_MS);
                    continue;
                }
            };

            match cooldown.gate(uptime) {
                Ok(()) => attest(&entropy_source, timestamp_ms),
                Err(remaining_ms) => println!("cooldown: {remaining_ms} ms remaining"),
            }
        }

        delay.delay_millis(POLL_INTERVAL_MS);
    }
}

/// Print why the clock could not be read, and what to do about it.
///
/// Three lines rather than one, because they answer three different questions
/// and get used by different people: `cause` is what is wrong, `action` is what
/// the holder does next, `detail` is the register or the HAL error a bench
/// diagnosis starts from.
///
/// **The cause and the action are not composed here.** Both come from
/// `icesickle_core::clock`, where a host test holds them pairwise distinct
/// (`causes_are_pairwise_distinct`) and every variant accounted for
/// (`every_cause_is_listed`). Written out in this file they would be
/// unverifiable — `firmware/nostd` can host no tests — and the obvious
/// shortcut, one `println!("clock error")` for every arm, would be a working
/// firmware that has quietly stopped distinguishing a five-minute fix from a
/// dead unit.
fn report_clock_failure<E: core::fmt::Debug>(context: &str, error: &ReadError<E>) {
    println!("{context}: clock unavailable");
    println!("  cause:  {}", error.cause());
    println!("  action: {}", error.remedy().advice());
    match error {
        ReadError::Bus(e) => {
            println!("  detail: I2C error on SDA=GPIO{SDA_PIN} SCL=GPIO{SCL_PIN}: {e:?}")
        }
        ReadError::Clock(e) => println!("  detail: {e:?}"),
    }
}

/// A `CivilTime` as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// A `Display` wrapper rather than a formatting function because there is no
/// allocator to build a string in, and no fixed buffer worth carrying on the
/// stack for something that goes straight to the console.
///
/// The fields are printed exactly as the part reported them. There is no
/// arithmetic here on purpose: converting back from Unix milliseconds would
/// mean writing the civil-from-days algorithm a second time, inverted, on the
/// side of the boundary that nothing can test — which is why
/// `read_clock_civil` hands back the decoded fields at all.
struct IsoTime(CivilTime);

impl core::fmt::Display for IsoTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let t = &self.0;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
        )
    }
}

/// Draw a key from the live entropy source, sign, and print.
///
/// Takes `&EntropySource` rather than a `Trng`: the reference is itself the
/// proof the source is live, and the handle it yields cannot outlive it. There
/// is no way to reach `Attestation::create` without one.
///
/// `timestamp_ms` is **Unix milliseconds**, read from the DS3231 by the caller.
/// It is a `u64` like every other millisecond count in this firmware, which is
/// exactly why the caller reads the clock rather than this function taking
/// whatever time is nearest: nothing in the type distinguishes a wall clock
/// from a since-boot counter, so the distinction has to be kept by the one
/// place that can — the call site, which has both and passes one.
#[allow(
    clippy::large_stack_frames,
    reason = "same as main: the signing path is deliberately stack-only"
)]
fn attest(entropy_source: &EntropySource, timestamp_ms: u64) {
    let entropy = entropy_source.entropy();
    let event = AttestationEvent::ButtonPress { gpio: BUTTON_PIN };

    // The two hardware inputs, made explicit. Everything downstream of them is
    // deterministic, which is what lets icesickle-core be tested on a host.
    // `create` zeroizes `seed` before returning.
    let mut seed = [0u8; 32];
    entropy.read(&mut seed);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    match Attestation::create(&mut seed, event, timestamp_ms, counter) {
        Ok(attestation) => {
            println!("=== ATTESTATION ===");
            println!("event:     {:?}", attestation.event());
            // Unix milliseconds, not "ms since boot" -- D13, and the reason
            // this whole path exists. The verifier reads the number; the
            // parenthesised form is for whoever is reading the console.
            println!("timestamp: {} (Unix ms)", attestation.timestamp_ms());
            println!("payload:   {}", attestation.signed_payload_hex());
            println!("pubkey:    {}", attestation.public_key_hex());
            println!("signature: {}", attestation.signature_hex());
        }
        Err(e) => println!("attestation failed: {e:?}"),
    }
}
