//! DS3231 register codec: battery-backed wall-clock time, decoded and checked.
//!
//! D13 settled that the device **has** a clock and that its readings are **not
//! trusted for verification**. This module is the first half of that: the part
//! that turns seven bytes off an I2C bus into Unix milliseconds. The second
//! half — the reason nobody may believe the answer — lives in
//! `docs/DECISIONS_V2_1.md` D13 and `docs/VERIFIER_MODEL.md` §3.
//!
//! No hardware here, and no clock of its own. The firmware reads the registers
//! and passes them in, exactly as it passes `now_ms` to [`crate::cooldown`] and
//! a seed to [`crate::Attestation::create`]. That is what makes a chip we do not
//! own testable on a host that does not have one.
//!
//! # What this module is actually defending against
//!
//! Not an adversary — D13 already concedes that a seized device can be set to
//! any time, and no amount of decoding fixes that. This defends against
//! **a wrong reading that looks like a right one**.
//!
//! Three ways that happens, all of them silent:
//!
//! - **The coin cell died.** The DS3231 raises [`OSCILLATOR_STOP_FLAG`] when its
//!   oscillator has stopped since the flag was last cleared. The time registers
//!   then hold whatever they held when the power went, which is a perfectly
//!   well-formed date that is simply false. [`read_unix_ms`] checks the flag
//!   before it reads anything else, and this is the only reason the status byte
//!   is a parameter.
//! - **The part is not there.** An absent or unpowered device leaves the bus
//!   floating and the master reads `0xFF` for every byte. `0xFF` is not BCD, and
//!   every register on this part has reserved bits that must read zero, so junk
//!   fails on two independent grounds rather than decoding to a plausible 2065.
//! - **The chip is in 12-hour mode.** Bit 6 of the hours register selects it.
//!   Read as 24-hour, a 12-hour reading is wrong by up to twelve hours and wrong
//!   in a way nothing downstream can notice. See [`ClockError::TwelveHourMode`]
//!   for why this is rejected rather than supported.
//!
//! Every one of those produces a timestamp that is internally consistent, passes
//! any range check, and is false. Fail loud is the whole design.
//!
//! # Resolution is one second
//!
//! The DS3231 counts seconds. [`CivilTime::unix_ms`] therefore always returns a
//! multiple of 1000, and `timestamp_ms` carries a millisecond field with second
//! precision. That is not a leak — every device behaves identically, so there is
//! no distinguisher in it — but it is worth knowing before anyone reads meaning
//! into the low digits.
//!
//! # The part choice does not enforce D13's "no identifier" rule
//!
//! D13 requires that the clock store time and nothing else, on the reasoning
//! that battery-backed storage is exactly where a device identity accumulates by
//! accident ([`crate::auth`]). It is tempting to call that closed by hardware:
//! the DS3231 has no general-purpose NVRAM, unlike the DS1307's 56 bytes.
//!
//! **It is not closed.** The alarm registers (`0x07`–`0x0D`) are writable, are
//! kept alive by the same cell, and are seven bytes that nothing in this
//! firmware uses — which is to say seven bytes of persistent scratch space
//! wearing a different name. The aging offset at `0x10` is another. So the rule
//! stays a rule: this module reads `0x00`–`0x06` and `0x0F` and touches nothing
//! else, and the alarms stay unused because using them is where a serial number
//! would end up living.
//!
//! Related: **do not substitute a DS3234.** It is the SPI sibling of this part
//! and it carries 256 bytes of battery-backed SRAM, which would turn a rule that
//! is currently easy to keep into one that is easy to break.
//!
//! # Range, and the chip's own century bug
//!
//! Two BCD digits of year plus the century bit in the month register gives
//! 2000–2199. Inside that span the DS3231 tracks leap years itself — and gets
//! 2100 wrong, because its rule is "divisible by four" and 2100 is not a leap
//! year under the Gregorian one.
//!
//! This decoder uses the Gregorian rule. If a chip ever rolls into
//! 2100-02-29, [`decode_time`] rejects it as [`ClockError::OutOfRange`] rather
//! than quietly handing back a date one day out for the rest of the century.
//! Failing is the right outcome: the alternative is a silent off-by-one-day in
//! every timestamp after that point.

/// I2C address. Fixed in silicon; the DS3231 has no address pins.
pub const I2C_ADDRESS: u8 = 0x68;

/// First timekeeping register. Read [`TIME_REGISTER_COUNT`] bytes from here.
pub const REG_SECONDS: u8 = 0x00;

/// Status register, holding [`OSCILLATOR_STOP_FLAG`].
pub const REG_STATUS: u8 = 0x0F;

/// How many registers [`decode_time`] expects: seconds through year.
pub const TIME_REGISTER_COUNT: usize = 7;

/// Bit 7 of [`REG_STATUS`]: the oscillator has stopped since this was last
/// cleared, so the time registers are meaningless.
pub const OSCILLATOR_STOP_FLAG: u8 = 0x80;

/// Earliest representable year. Two BCD digits plus the century bit start here.
pub const MIN_YEAR: u16 = 2000;

/// Latest representable year.
pub const MAX_YEAR: u16 = 2199;

/// Highest register the DS3231 implements.
pub const MAX_REGISTER: u8 = 0x12;

/// The registers this project touches: the seven timekeeping bytes and the
/// status byte.
pub const PERMITTED_REGISTERS: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F];

/// Battery-backed, writable, and useless to this design — which is exactly what
/// makes them dangerous.
///
/// The two alarm blocks (`0x07`–`0x0D`) and the aging offset (`0x10`) are eight
/// bytes that survive a power cycle, that nothing here reads, and that would
/// hold a serial number perfectly well. D13 says the clock stores time and
/// nothing else; this is the list of places that rule is actually about, and
/// [`RegisterWrite`] is what stops the rule being merely written down.
pub const SCRATCHPAD_REGISTERS: [u8; 8] = [0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10];

/// Real registers this design has no use for, and which are not storage:
/// control (`0x0E`) and the two temperature bytes (`0x11`–`0x12`, read-only).
///
/// Kept as a named set rather than left implicit so that
/// `every_register_is_classified` can prove the three lists account for the
/// whole map. Adding a register to none of them is then a test failure rather
/// than an oversight.
///
/// Control is deliberately not in [`SCRATCHPAD_REGISTERS`]. Every bit in it
/// changes observable behaviour — oscillator enable, square-wave output, alarm
/// interrupts — so it is configuration rather than a hiding place, and a
/// provisioning step may one day have a real reason to write it. If something
/// starts writing it for a reason that is *not* one of those bits, that is the
/// moment to look hard.
pub const UNUSED_REGISTERS: [u8; 3] = [0x0E, 0x11, 0x12];

/// Longest transaction this module builds: a register pointer plus the seven
/// timekeeping bytes.
const MAX_WRITE_LEN: usize = 1 + TIME_REGISTER_COUNT;

/// Bit 6 of the hours register: 12-hour mode.
const HOURS_12_HOUR_MODE: u8 = 0x40;

/// Bit 7 of the month register: add 100 years.
const MONTH_CENTURY: u8 = 0x80;

/// Why a register read could not be believed.
///
/// Every variant names the register that failed, using the DS3231's own
/// addresses, so a log line points at a datasheet page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    /// [`OSCILLATOR_STOP_FLAG`] was set: the oscillator stopped at some point
    /// since the flag was last cleared, so the time registers hold a stale
    /// value from before the power loss. Well-formed, and false.
    ///
    /// The fix is to set the clock and only then clear the flag — see
    /// [`clear_oscillator_stop_flag`], which explains why that order matters.
    OscillatorStopped,

    /// A nibble held a value above 9, so the byte is not BCD at all. The
    /// ordinary cause is a floating bus reading `0xFF`, meaning the part is
    /// absent or unpowered rather than wrong.
    NotBcd { register: u8 },

    /// A bit the datasheet fixes at zero was set. Same cause as
    /// [`ClockError::NotBcd`] and checked separately, because a junk pattern
    /// that happens to be valid BCD in both nibbles still fails here.
    ReservedBitSet { register: u8 },

    /// Valid BCD, impossible value: a 13th month, a 61st second, or a
    /// February 30th. Also what a chip rolling into 2100-02-29 produces.
    OutOfRange { register: u8 },

    /// The hours register selects 12-hour mode.
    ///
    /// Rejected rather than decoded, which is a deliberate trade. Supporting it
    /// is a handful of lines and would make the module more forgiving; what it
    /// would also do is accept a chip that something other than this firmware
    /// configured, since [`CivilTime::to_registers`] only ever writes 24-hour
    /// mode. On a part whose register state after first power-up is undefined,
    /// "someone else set this up" is a fact worth surfacing rather than
    /// absorbing.
    TwelveHourMode,
}

/// A wall-clock instant as the DS3231 stores it: seconds, no zone, no
/// sub-second part.
///
/// Every value that exists has been validated — the constructor is the only way
/// to make one, and it rejects impossible dates. So [`CivilTime::unix_ms`]
/// cannot fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl CivilTime {
    /// Validate and build. `year` is absolute ([`MIN_YEAR`]–[`MAX_YEAR`]),
    /// `month` and `day` are 1-based.
    ///
    /// Leap years use the Gregorian rule, not the DS3231's — see the module
    /// docs on 2100.
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, ClockError> {
        if year < MIN_YEAR || year > MAX_YEAR {
            return Err(ClockError::OutOfRange { register: 0x06 });
        }
        if month < 1 || month > 12 {
            return Err(ClockError::OutOfRange { register: 0x05 });
        }
        if day < 1 || day > days_in_month(year, month) {
            return Err(ClockError::OutOfRange { register: 0x04 });
        }
        if hour > 23 {
            return Err(ClockError::OutOfRange { register: 0x02 });
        }
        if minute > 59 {
            return Err(ClockError::OutOfRange { register: 0x01 });
        }
        // No leap seconds: the DS3231 does not count them and Unix time does not
        // represent them, so 60 is simply out of range rather than a special case.
        if second > 59 {
            return Err(ClockError::OutOfRange { register: 0x00 });
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    pub const fn year(&self) -> u16 {
        self.year
    }

    pub const fn month(&self) -> u8 {
        self.month
    }

    pub const fn day(&self) -> u8 {
        self.day
    }

    pub const fn hour(&self) -> u8 {
        self.hour
    }

    pub const fn minute(&self) -> u8 {
        self.minute
    }

    pub const fn second(&self) -> u8 {
        self.second
    }

    /// Milliseconds since the Unix epoch, UTC.
    ///
    /// Always a multiple of 1000; the part has no sub-second counter. This is
    /// the value `AttestationPayload::timestamp_ms` carries in v2 — an input a
    /// verifier anchors, never one it believes (D13).
    pub const fn unix_ms(&self) -> u64 {
        let days = days_from_civil(self.year, self.month, self.day);
        let seconds =
            days * 86_400 + self.hour as i64 * 3_600 + self.minute as i64 * 60 + self.second as i64;
        // `year >= MIN_YEAR` is a constructor invariant and MIN_YEAR is well
        // after 1970, so this is positive and the cast cannot wrap.
        seconds as u64 * 1_000
    }

    /// The seven bytes to write back starting at [`REG_SECONDS`], to set the
    /// clock.
    ///
    /// Always 24-hour mode. The day-of-week register is computed from the date
    /// rather than left blank, because a register that must read 1–7 is only a
    /// junk detector if something valid is actually in it — see [`decode_time`]
    /// on why the value is never cross-checked on the way back.
    pub const fn to_registers(&self) -> [u8; TIME_REGISTER_COUNT] {
        let (century, year_of_century) = if self.year >= 2100 {
            (MONTH_CENTURY, self.year - 2100)
        } else {
            (0, self.year - 2000)
        };
        [
            to_bcd(self.second),
            to_bcd(self.minute),
            to_bcd(self.hour),
            self.weekday() + 1,
            to_bcd(self.day),
            to_bcd(self.month) | century,
            to_bcd(year_of_century as u8),
        ]
    }

    /// Days since Sunday, 0–6. Used only to fill the day-of-week register.
    const fn weekday(&self) -> u8 {
        // 1970-01-01 was a Thursday, so shifting by 4 puts Sunday at 0. The day
        // count is positive across the whole representable range, so a plain
        // remainder is enough.
        ((days_from_civil(self.year, self.month, self.day) + 4) % 7) as u8
    }
}

/// Whether the status byte says the oscillator has stopped.
pub const fn oscillator_stopped(status: u8) -> bool {
    status & OSCILLATOR_STOP_FLAG != 0
}

/// The status byte to write back to acknowledge a stop, preserving every other
/// bit.
///
/// **Set the time first, then clear this.** The flag is the only durable record
/// that the registers are stale; clearing it before writing a real time turns a
/// detectable fault into an undetectable one, and the device then reports a
/// confidently wrong date with nothing left to say otherwise. Read the status
/// register, pass it here, write it back — the read-modify-write is not
/// decoration, since the low bits carry the 32 kHz enable and the alarm flags.
pub const fn clear_oscillator_stop_flag(status: u8) -> u8 {
    status & !OSCILLATOR_STOP_FLAG
}

/// Whether a register is one of the battery-backed bytes D13's rule is about.
///
/// Exists so a driver can gate on it, and so the ban has a name that appears in
/// a stack trace rather than only in prose.
pub const fn is_scratchpad_register(register: u8) -> bool {
    let mut i = 0;
    while i < SCRATCHPAD_REGISTERS.len() {
        if SCRATCHPAD_REGISTERS[i] == register {
            return true;
        }
        i += 1;
    }
    false
}

/// An I2C write this crate sanctions: a register pointer followed by its bytes.
///
/// # Why this is a type and not a pair of arguments
///
/// D13 requires that the clock hold time and nothing else, and the module docs
/// explain why the part does not enforce that for us — the alarm registers are
/// seven bytes of persistent scratch space wearing a different name.
///
/// A rule in a doc comment is a rule until someone in a hurry needs eight bytes
/// of storage and notices the clock has some going spare. So the rule is a type
/// instead. The fields are private and there is no public constructor: the only
/// `RegisterWrite` values that can exist are the ones the associated functions
/// below build, and neither of them can target [`SCRATCHPAD_REGISTERS`]. A write
/// to an alarm register is not forbidden here, it is **unrepresentable**.
///
/// # What this does not do
///
/// It does not make raw I2C impossible. Firmware that wants to can still hand a
/// bus driver its own byte slice, and no type in this crate can reach across and
/// stop it. What the type buys is that the sanctioned path is obvious, is the
/// path of least resistance, and that stepping off it has to be done on purpose
/// and looks like it — which, absent a mechanism the silicon does not offer, is
/// the realistic ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterWrite {
    /// Register pointer first, then payload. Fixed-size, so no allocator.
    buffer: [u8; MAX_WRITE_LEN],
    len: u8,
}

impl RegisterWrite {
    /// Set the clock. Targets [`REG_SECONDS`] and writes all seven timekeeping
    /// registers in one transaction, which is how the datasheet says to avoid
    /// tearing across a seconds rollover.
    pub fn set_time(time: &CivilTime) -> Self {
        let regs = time.to_registers();
        let mut buffer = [0u8; MAX_WRITE_LEN];
        buffer[0] = REG_SECONDS;
        let mut i = 0;
        while i < TIME_REGISTER_COUNT {
            buffer[1 + i] = regs[i];
            i += 1;
        }
        Self {
            buffer,
            len: MAX_WRITE_LEN as u8,
        }
    }

    /// Acknowledge a stop, preserving every other status bit.
    ///
    /// **Order matters and the API cannot enforce it.** Issue
    /// [`RegisterWrite::set_time`] first: the stop flag is the only durable
    /// record that the registers are stale, so clearing it before a real time is
    /// written converts a detectable fault into a confidently wrong date. See
    /// [`clear_oscillator_stop_flag`].
    pub fn acknowledge_oscillator_stop(status: u8) -> Self {
        let mut buffer = [0u8; MAX_WRITE_LEN];
        buffer[0] = REG_STATUS;
        buffer[1] = clear_oscillator_stop_flag(status);
        Self { buffer, len: 2 }
    }

    /// The register this write targets.
    pub const fn register(&self) -> u8 {
        self.buffer[0]
    }

    /// The whole transaction: register pointer followed by payload. Hand this
    /// straight to an I2C `write` at [`I2C_ADDRESS`].
    pub fn bytes(&self) -> &[u8] {
        &self.buffer[..self.len as usize]
    }

    /// Just the payload, without the leading register pointer.
    pub fn payload(&self) -> &[u8] {
        &self.buffer[1..self.len as usize]
    }
}

/// Decode registers `0x00`–`0x06`.
///
/// Does **not** look at the status register, so it cannot tell a live reading
/// from one preserved across a dead cell. [`read_unix_ms`] is the entry point
/// that checks both; this one exists for callers holding the two reads apart.
///
/// The day-of-week register is range-checked and then discarded. Its mapping to
/// actual weekdays is chosen by whoever set the clock — the datasheet fixes only
/// that it counts 1 to 7 and rolls over — so cross-checking it against the date
/// would reject a chip set by any stock tool during bring-up, in exchange for
/// catching a corruption the reserved-bit and BCD checks already catch.
pub fn decode_time(regs: &[u8; TIME_REGISTER_COUNT]) -> Result<CivilTime, ClockError> {
    let second = bcd_field(regs[0], 0x7F, 0x80, 0x00)?;
    let minute = bcd_field(regs[1], 0x7F, 0x80, 0x01)?;

    if regs[2] & HOURS_12_HOUR_MODE != 0 {
        return Err(ClockError::TwelveHourMode);
    }
    let hour = bcd_field(regs[2], 0x3F, 0x80, 0x02)?;

    // Day of week is a 1-of-7 count, not BCD, so it gets its own check.
    if regs[3] & 0xF8 != 0 {
        return Err(ClockError::ReservedBitSet { register: 0x03 });
    }
    if regs[3] == 0 {
        return Err(ClockError::OutOfRange { register: 0x03 });
    }

    let day = bcd_field(regs[4], 0x3F, 0xC0, 0x04)?;

    let century = regs[5] & MONTH_CENTURY != 0;
    let month = bcd_field(regs[5], 0x1F, 0x60, 0x05)?;

    let year_of_century = bcd_field(regs[6], 0xFF, 0x00, 0x06)?;
    let year = MIN_YEAR + if century { 100 } else { 0 } + year_of_century as u16;

    CivilTime::new(year, month, day, hour, minute, second)
}

/// The whole read: status byte, then registers `0x00`–`0x06`, to Unix
/// milliseconds.
///
/// Checks the stop flag **first**. The time registers are well-formed after a
/// power loss, so validating them proves nothing about whether they are current,
/// and an order that decoded first would let a stale date past on any path that
/// forgot to look at the flag.
pub fn read_unix_ms(status: u8, regs: &[u8; TIME_REGISTER_COUNT]) -> Result<u64, ClockError> {
    if oscillator_stopped(status) {
        return Err(ClockError::OscillatorStopped);
    }
    Ok(decode_time(regs)?.unix_ms())
}

/// Check that the reserved bits are zero, then decode the value bits as BCD.
///
/// Both halves matter. The reserved-bit check catches a floating bus reading
/// `0xFF`; the BCD check catches a pattern that survives the mask but holds a
/// nibble above 9.
///
/// `reserved` is passed rather than derived as `!value`, because the two are not
/// complements on every register: the month register's bit 7 is the century
/// flag, meaningful and consumed elsewhere, and treating it as reserved would
/// reject every date after 2099.
fn bcd_field(raw: u8, value: u8, reserved: u8, register: u8) -> Result<u8, ClockError> {
    debug_assert!(value & reserved == 0, "a bit cannot be both");
    if raw & reserved != 0 {
        return Err(ClockError::ReservedBitSet { register });
    }
    from_bcd(raw & value).ok_or(ClockError::NotBcd { register })
}

/// Packed BCD to binary, or `None` if either nibble is above 9.
const fn from_bcd(byte: u8) -> Option<u8> {
    let tens = byte >> 4;
    let units = byte & 0x0F;
    if tens > 9 || units > 9 {
        return None;
    }
    Some(tens * 10 + units)
}

/// Binary to packed BCD. Callers are constructor-validated, so no value above
/// 99 reaches this.
const fn to_bcd(value: u8) -> u8 {
    debug_assert!(value <= 99);
    ((value / 10) << 4) | (value % 10)
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1970-01-01 to the given date, by Howard Hinnant's
/// `days_from_civil`.
///
/// Kept in its general form — including the negative-year branch this crate can
/// never reach — because it is a published algorithm with a published proof, and
/// a specialised copy is a copy nobody can check against the original.
const fn days_from_civil(year: u16, month: u8, day: u8) -> i64 {
    let y = year as i32 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = (y - era * 400) as u32; // [0, 399]
    let shifted_month = if month > 2 {
        month as u32 - 3
    } else {
        month as u32 + 9
    }; // March is 0
    let day_of_year = (153 * shifted_month + 2) / 5 + day as u32 - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era as i64 * 146_097 + day_of_era as i64 - 719_468
}

// ---------------------------------------------------------------------------
// The transport seam
// ---------------------------------------------------------------------------

/// Everything the firmware must supply to talk to the clock, and nothing more.
///
/// # Why the seam is here and not in the firmware
///
/// [`RegisterWrite`] makes a write to [`SCRATCHPAD_REGISTERS`] unrepresentable,
/// but a type only guards the code that has to go through it. A driver whose
/// write path took `(register, bytes)` — the obvious signature, and the one
/// anyone reaches for — would open a second route to the register file that the
/// type never sees. Nothing would fail: the codec would still refuse, the tests
/// would still pass, and the ban would quietly be a doc comment again.
///
/// So the driver does not get to name a register. `write` takes a
/// [`RegisterWrite`], which has private fields and no public constructor, so an
/// implementation of this trait **cannot express a forbidden write even inside
/// its own body**. The register byte does cross the boundary, but sealed inside
/// a value only this module can build.
///
/// `read` does take a register, and that asymmetry is the point rather than an
/// oversight: a read cannot store an identifier, so reads are not what D13's
/// rule is about. Constraining them would defend nothing and cost a trait
/// method per register.
///
/// # What it still does not close
///
/// Firmware owns the I2C peripheral and can always bypass this trait by driving
/// the bus directly. No type in a platform-independent crate can prevent that.
/// The mitigation is ownership, not typing: the implementor should *consume*
/// the peripheral, so no raw handle survives elsewhere and the only code that
/// can reach the bus is the handful of lines implementing these two methods.
pub trait RegisterBus {
    /// However the bus driver fails. `esp_hal::i2c::master::Error` on hardware.
    type Error;

    /// Push a sanctioned write: send [`RegisterWrite::bytes`] to
    /// [`I2C_ADDRESS`]. Implementations forward bytes and decide nothing.
    fn write(&mut self, write: &RegisterWrite) -> Result<(), Self::Error>;

    /// Set the register pointer to `register`, then read `out.len()` bytes.
    fn read(&mut self, register: u8, out: &mut [u8]) -> Result<(), Self::Error>;
}

/// Reading the clock failed on the bus, or in the bytes the bus returned.
///
/// Kept as two variants because they call for different responses and are
/// genuinely different events. A [`ReadError::Bus`] means the transaction did
/// not happen — the part did not acknowledge, the bus timed out — and retrying
/// is reasonable. A [`ReadError::Clock`] means the transaction succeeded
/// perfectly and the bytes must not be believed; retrying returns the same
/// answer, because a dead coin cell does not heal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError<E> {
    /// The I2C transaction itself failed.
    Bus(E),
    /// The bytes came back and could not be trusted. See [`ClockError`].
    Clock(ClockError),
}

/// The whole read: status, then the time registers, then Unix milliseconds.
///
/// The order is the reason this lives here rather than in the driver. The stop
/// flag is what decides whether the time registers mean anything, so it must be
/// read first — and "must be read first" in a driver is a comment somebody
/// follows, while here it is simply not the caller's to get wrong. Firmware
/// cannot skip the check, because firmware does not own the sequence.
///
/// Two transactions rather than one nine-byte read: the status register is at
/// `0x0F`, past `0x07`–`0x0D`, and a single sweep across the range would pull
/// the alarm registers into a buffer for no reason. Reading them is harmless —
/// reads are not what the ban is about — but not reading them at all is one
/// less place a future refactor can find a use for the bytes.
pub fn read_clock<B: RegisterBus>(bus: &mut B) -> Result<u64, ReadError<B::Error>> {
    let mut status = [0u8; 1];
    bus.read(REG_STATUS, &mut status).map_err(ReadError::Bus)?;

    let mut registers = [0u8; TIME_REGISTER_COUNT];
    bus.read(REG_SECONDS, &mut registers)
        .map_err(ReadError::Bus)?;

    read_unix_ms(status[0], &registers).map_err(ReadError::Clock)
}

/// Set the clock and then acknowledge the stop flag, in that order.
///
/// The order is load-bearing and is not the caller's to choose. The stop flag
/// is the only durable record that the time registers are stale; clearing it
/// before a real time is written converts a detectable fault into a
/// confidently wrong date, with nothing left to say otherwise.
///
/// The status byte is read here rather than passed in, for the same reason.
/// A caller supplying it could supply a stale one, and the acknowledgement is a
/// read-modify-write — the low bits carry the 32 kHz enable and the alarm
/// flags, so a blind write would silently reconfigure the part.
pub fn set_clock<B: RegisterBus>(bus: &mut B, time: &CivilTime) -> Result<(), B::Error> {
    let mut status = [0u8; 1];
    bus.read(REG_STATUS, &mut status)?;

    bus.write(&RegisterWrite::set_time(time))?;
    bus.write(&RegisterWrite::acknowledge_oscillator_stop(status[0]))
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Registers for 2026-08-27 14:05:09, a Thursday. Written out by hand from
    /// the datasheet's register map rather than produced by `to_registers`, so
    /// the two directions are checked against something other than each other.
    const KNOWN_REGS: [u8; TIME_REGISTER_COUNT] = [
        0x09, // seconds
        0x05, // minutes
        0x14, // hours, 24-hour mode
        0x05, // day of week: Thursday, with Sunday = 1
        0x27, // date
        0x08, // month, century clear
        0x26, // year within century
    ];

    /// 2026-08-27T14:05:09Z. Independently computed, not derived from this
    /// module.
    const KNOWN_UNIX_MS: u64 = 1_787_839_509_000;

    fn civil(year: u16, month: u8, day: u8) -> CivilTime {
        CivilTime::new(year, month, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn a_known_register_dump_decodes_to_a_known_instant() {
        let time = decode_time(&KNOWN_REGS).unwrap();
        assert_eq!(
            (time.year(), time.month(), time.day()),
            (2026, 8, 27),
            "date fields"
        );
        assert_eq!(
            (time.hour(), time.minute(), time.second()),
            (14, 5, 9),
            "time fields"
        );
        assert_eq!(time.unix_ms(), KNOWN_UNIX_MS);
        assert_eq!(read_unix_ms(0x00, &KNOWN_REGS), Ok(KNOWN_UNIX_MS));
    }

    #[test]
    fn encoding_the_known_instant_reproduces_the_register_dump() {
        let time = CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap();
        assert_eq!(time.to_registers(), KNOWN_REGS);
    }

    #[test]
    fn every_second_of_a_day_survives_a_round_trip() {
        // Cheap exhaustive pass over the field ranges that BCD packing is most
        // likely to get wrong: the tens boundaries in all three time fields.
        for hour in 0..24u8 {
            for minute in 0..60u8 {
                for second in 0..60u8 {
                    let time = CivilTime::new(2026, 8, 27, hour, minute, second).unwrap();
                    assert_eq!(
                        decode_time(&time.to_registers()),
                        Ok(time),
                        "{hour:02}:{minute:02}:{second:02}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_epoch_anchors_are_right() {
        assert_eq!(civil(2000, 1, 1).unix_ms(), 946_684_800_000);
        assert_eq!(civil(2024, 2, 29).unix_ms(), 1_709_164_800_000);
        assert_eq!(civil(2100, 1, 1).unix_ms(), 4_102_444_800_000);
        assert_eq!(civil(2199, 12, 31).unix_ms(), 7_258_032_000_000);
    }

    #[test]
    fn a_day_is_a_day_across_every_month_boundary_in_the_range() {
        // days_from_civil's month shuffle is the part most likely to be wrong
        // at a boundary, and a wrong day is a whole 86 400 000 ms of error.
        let mut previous = civil(2000, 1, 1).unix_ms();
        for year in MIN_YEAR..=MAX_YEAR {
            for month in 1..=12u8 {
                for day in 1..=days_in_month(year, month) {
                    if (year, month, day) == (2000, 1, 1) {
                        continue;
                    }
                    let now = civil(year, month, day).unix_ms();
                    assert_eq!(
                        now - previous,
                        86_400_000,
                        "{year}-{month:02}-{day:02} is not one day after its predecessor"
                    );
                    previous = now;
                }
            }
        }
    }

    #[test]
    fn the_century_bit_moves_the_year_by_a_hundred() {
        let mut regs = KNOWN_REGS;
        regs[5] |= MONTH_CENTURY;
        assert_eq!(decode_time(&regs).unwrap().year(), 2126);
        assert_eq!(
            CivilTime::new(2126, 8, 27, 14, 5, 9)
                .unwrap()
                .to_registers()[5]
                & MONTH_CENTURY,
            MONTH_CENTURY,
            "the encoder must set the bit it expects to read back"
        );
    }

    /// The whole reason the status byte is a parameter: these registers are
    /// perfectly well-formed, and stale.
    #[test]
    fn a_stopped_oscillator_rejects_an_otherwise_valid_reading() {
        assert!(decode_time(&KNOWN_REGS).is_ok(), "the registers are fine");
        assert_eq!(
            read_unix_ms(OSCILLATOR_STOP_FLAG, &KNOWN_REGS),
            Err(ClockError::OscillatorStopped),
        );
        // Any other bits set alongside it change nothing.
        assert_eq!(
            read_unix_ms(0xFF, &KNOWN_REGS),
            Err(ClockError::OscillatorStopped),
        );
        assert!(oscillator_stopped(0x88));
        assert!(!oscillator_stopped(0x08));
    }

    #[test]
    fn clearing_the_stop_flag_leaves_every_other_bit_alone() {
        // Bit 3 is the 32 kHz enable, bits 1 and 0 the alarm flags. A blind
        // write of 0x00 would silently reconfigure the part.
        assert_eq!(clear_oscillator_stop_flag(0x8B), 0x0B);
        assert_eq!(clear_oscillator_stop_flag(0x0B), 0x0B);
        assert!(!oscillator_stopped(clear_oscillator_stop_flag(0xFF)));
    }

    /// An absent or unpowered part reads as all ones. It must not decode to
    /// anything at all.
    #[test]
    fn a_floating_bus_does_not_decode() {
        assert!(decode_time(&[0xFF; TIME_REGISTER_COUNT]).is_err());
        assert!(read_unix_ms(0x00, &[0xFF; TIME_REGISTER_COUNT]).is_err());

        // All zeroes is the other degenerate read, and it is a month of 0 and a
        // date of 0 — impossible, not merely unlikely.
        assert!(decode_time(&[0x00; TIME_REGISTER_COUNT]).is_err());
    }

    #[test]
    fn a_reserved_bit_set_anywhere_in_the_dump_is_caught() {
        // Each entry: register index, the mask of bits the datasheet fixes at
        // zero. The hours register is absent because bit 6 is the 12/24 flag
        // and bit 7 is covered by its own case below.
        for (index, reserved) in [(0usize, 0x80u8), (1, 0x80), (3, 0xF8), (4, 0xC0), (5, 0x60)] {
            let mut regs = KNOWN_REGS;
            regs[index] |= reserved;
            assert_eq!(
                decode_time(&regs),
                Err(ClockError::ReservedBitSet {
                    register: index as u8
                }),
                "register {index:#04x} accepted a reserved bit",
            );
        }
    }

    #[test]
    fn a_nibble_above_nine_is_not_bcd() {
        let mut regs = KNOWN_REGS;
        regs[0] = 0x0A; // ten units, which BCD cannot express
        assert_eq!(
            decode_time(&regs),
            Err(ClockError::NotBcd { register: 0x00 })
        );

        let mut regs = KNOWN_REGS;
        regs[6] = 0xAA;
        assert_eq!(
            decode_time(&regs),
            Err(ClockError::NotBcd { register: 0x06 })
        );
    }

    /// Wrong by up to twelve hours, and undetectable downstream.
    #[test]
    fn twelve_hour_mode_is_refused_rather_than_misread() {
        let mut regs = KNOWN_REGS;
        regs[2] = HOURS_12_HOUR_MODE | 0x02; // 2 AM in 12-hour mode
        assert_eq!(decode_time(&regs), Err(ClockError::TwelveHourMode));
    }

    #[test]
    fn the_encoder_never_writes_twelve_hour_mode() {
        for hour in 0..24u8 {
            let regs = CivilTime::new(2026, 8, 27, hour, 0, 0)
                .unwrap()
                .to_registers();
            assert_eq!(regs[2] & HOURS_12_HOUR_MODE, 0, "hour {hour}");
        }
    }

    #[test]
    fn impossible_dates_are_rejected() {
        assert_eq!(
            CivilTime::new(2026, 2, 29, 0, 0, 0),
            Err(ClockError::OutOfRange { register: 0x04 }),
            "2026 is not a leap year"
        );
        assert!(CivilTime::new(2024, 2, 29, 0, 0, 0).is_ok(), "2024 is");
        assert_eq!(
            CivilTime::new(2026, 13, 1, 0, 0, 0),
            Err(ClockError::OutOfRange { register: 0x05 })
        );
        assert_eq!(
            CivilTime::new(2026, 4, 31, 0, 0, 0),
            Err(ClockError::OutOfRange { register: 0x04 }),
            "April has thirty days"
        );
        assert_eq!(
            CivilTime::new(2026, 8, 27, 24, 0, 0),
            Err(ClockError::OutOfRange { register: 0x02 })
        );
        assert_eq!(
            CivilTime::new(2026, 8, 27, 0, 0, 60),
            Err(ClockError::OutOfRange { register: 0x00 }),
            "no leap seconds"
        );
        assert_eq!(
            CivilTime::new(1999, 12, 31, 0, 0, 0),
            Err(ClockError::OutOfRange { register: 0x06 })
        );
    }

    /// The DS3231's leap-year logic is "divisible by four", so a part left
    /// running will produce this date. The Gregorian rule says it does not
    /// exist, and a decoder that accepted it would be a day out from then on.
    #[test]
    fn the_chips_own_2100_leap_year_bug_surfaces_as_a_rejection() {
        assert!(!is_leap_year(2100));
        let regs = [0x00, 0x00, 0x00, 0x02, 0x29, 0x82, 0x00]; // 2100-02-29
        assert_eq!(
            decode_time(&regs),
            Err(ClockError::OutOfRange { register: 0x04 })
        );
        // The day either side of it is fine, so this is the rule and not a
        // broken century bit.
        assert!(decode_time(&[0x00, 0x00, 0x00, 0x01, 0x28, 0x82, 0x00]).is_ok());
        assert!(decode_time(&[0x00, 0x00, 0x00, 0x02, 0x01, 0x83, 0x00]).is_ok());
    }

    #[test]
    fn the_day_of_week_register_is_range_checked_but_not_believed() {
        // Out of range: zero is not a valid 1-of-7 count.
        let mut regs = KNOWN_REGS;
        regs[3] = 0x00;
        assert_eq!(
            decode_time(&regs),
            Err(ClockError::OutOfRange { register: 0x03 })
        );

        // In range but disagreeing with the date: accepted, because the
        // mapping belongs to whoever set the clock. Documented on decode_time.
        let mut regs = KNOWN_REGS;
        regs[3] = 0x01;
        assert_eq!(decode_time(&regs).unwrap().unix_ms(), KNOWN_UNIX_MS);
    }

    #[test]
    fn the_computed_weekday_matches_known_days() {
        // 1=Sunday. Checked against dates whose weekday is not in dispute.
        assert_eq!(civil(2000, 1, 1).to_registers()[3], 7, "a Saturday");
        assert_eq!(civil(2026, 8, 27).to_registers()[3], 5, "a Thursday");
        assert_eq!(civil(2026, 8, 30).to_registers()[3], 1, "a Sunday");
    }

    /// Second resolution, stated as a test so it cannot drift into an
    /// assumption somewhere downstream.
    #[test]
    fn every_timestamp_is_a_whole_number_of_seconds() {
        assert_eq!(decode_time(&KNOWN_REGS).unwrap().unix_ms() % 1000, 0);
        assert_eq!(civil(2199, 12, 31).unix_ms() % 1000, 0);
    }

    // -----------------------------------------------------------------------
    // D13's scratchpad ban, enforced rather than documented
    // -----------------------------------------------------------------------

    /// Every register on the part is classified exactly once.
    ///
    /// This is the test that gives the ban its teeth. `SCRATCHPAD_REGISTERS` on
    /// its own is a list someone can quietly fail to extend; a partition cannot
    /// be quietly failed to extend, because an address in none of the three sets
    /// fails here and an address in two of them fails here as well.
    ///
    /// So the only way to start using a battery-backed register is to move it
    /// out of the scratchpad set explicitly, in a diff, with this test's name in
    /// the blame — which is the whole difference between a rule and a comment.
    #[test]
    fn every_register_is_classified() {
        let mut classifications = [0u8; MAX_REGISTER as usize + 1];
        for register in PERMITTED_REGISTERS {
            classifications[register as usize] += 1;
        }
        for register in SCRATCHPAD_REGISTERS {
            classifications[register as usize] += 1;
        }
        for register in UNUSED_REGISTERS {
            classifications[register as usize] += 1;
        }

        for (register, count) in classifications.iter().enumerate() {
            assert_eq!(
                *count, 1,
                "register {register:#04x} is classified {count} times, not exactly once",
            );
        }

        // ...and no set names a register the part does not have.
        assert_eq!(
            PERMITTED_REGISTERS.len() + SCRATCHPAD_REGISTERS.len() + UNUSED_REGISTERS.len(),
            MAX_REGISTER as usize + 1,
            "the three sets do not cover the register map exactly",
        );
    }

    /// Nothing this module can build writes to a battery-backed register.
    ///
    /// Exhaustive over both constructors: every hour of a day for the time
    /// write, every one of the 256 status bytes for the acknowledgement. There
    /// are only two producers of a `RegisterWrite`, so this covers the entire
    /// space of writes the type permits to exist.
    #[test]
    fn nothing_this_module_can_write_touches_the_scratchpad() {
        for hour in 0..24u8 {
            for day in [1u8, 28, 31] {
                let time = CivilTime::new(2026, 12, day.min(31), hour, 59, 59).unwrap();
                let write = RegisterWrite::set_time(&time);
                assert!(
                    !is_scratchpad_register(write.register()),
                    "set_time targeted {:#04x}",
                    write.register(),
                );
                assert_eq!(write.register(), REG_SECONDS);
            }
        }

        for status in 0..=u8::MAX {
            let write = RegisterWrite::acknowledge_oscillator_stop(status);
            assert!(
                !is_scratchpad_register(write.register()),
                "acknowledge_oscillator_stop targeted {:#04x}",
                write.register(),
            );
            assert_eq!(write.register(), REG_STATUS);
        }
    }

    /// The ban is not vacuous.
    ///
    /// Without this, `nothing_this_module_can_write_touches_the_scratchpad`
    /// would pass just as happily against a predicate that returns `false` for
    /// everything, and the invariant above would be decoration. The same reason
    /// `emission.rs` keeps `the_identifier_scan_catches_key_reuse`.
    #[test]
    fn the_scratchpad_ban_actually_fires() {
        // Both alarm blocks and the aging offset: the eight bytes a serial
        // number would fit in.
        for register in [0x07u8, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10] {
            assert!(
                is_scratchpad_register(register),
                "{register:#04x} is battery-backed writable storage and must be banned",
            );
        }

        // Everything this design does touch must not be caught by it, or the
        // ban would block the module's own work.
        for register in PERMITTED_REGISTERS {
            assert!(!is_scratchpad_register(register), "{register:#04x}");
        }

        // Control is configuration, not storage. Called out because it is the
        // one address whose classification is a judgement rather than a fact.
        assert!(!is_scratchpad_register(0x0E));
    }

    #[test]
    fn a_time_write_is_the_register_pointer_then_the_encoded_registers() {
        let time = CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap();
        let write = RegisterWrite::set_time(&time);

        assert_eq!(write.bytes()[0], REG_SECONDS, "register pointer leads");
        assert_eq!(write.payload(), &KNOWN_REGS, "payload is the encoding");
        assert_eq!(write.bytes().len(), 1 + TIME_REGISTER_COUNT);

        // The round trip closes: what this write would put in the part is what
        // decode_time reads back out of it.
        let mut regs = [0u8; TIME_REGISTER_COUNT];
        regs.copy_from_slice(write.payload());
        assert_eq!(decode_time(&regs), Ok(time));
    }

    #[test]
    fn acknowledging_a_stop_clears_that_bit_and_no_other() {
        for status in 0..=u8::MAX {
            let write = RegisterWrite::acknowledge_oscillator_stop(status);
            assert_eq!(write.bytes()[0], REG_STATUS);
            assert_eq!(write.payload(), &[status & 0x7F], "status {status:#04x}");
            assert!(!oscillator_stopped(write.payload()[0]));
        }
    }

    // -----------------------------------------------------------------------
    // The transport seam
    // -----------------------------------------------------------------------

    /// Stands in the firmware's position. Everything it does is what the real
    /// esp-hal wrapper does: forward bytes, record nothing, decide nothing.
    ///
    /// This mock is the entire reason the sequencing below is testable at all.
    /// `firmware/nostd` can host no tests — `--all-targets` needs the `test`
    /// crate and a `#[panic_handler]` a `no_std` binary cannot provide, which is
    /// why CI builds it `--lib --bins` — so any ordering rule that lived in the
    /// driver would be verified by nothing. Moving the sequence into this crate
    /// is what moves it into reach of a host test on stable.
    #[derive(Default)]
    struct MockBus {
        /// Every write, in order, as (register, payload).
        writes: heapless::Vec<(u8, heapless::Vec<u8, 8>), 4>,
        /// Registers the part will report.
        status: u8,
        registers: [u8; TIME_REGISTER_COUNT],
        /// Reads seen, in order, so ordering can be asserted.
        reads: heapless::Vec<u8, 4>,
        /// When set, every operation fails instead.
        fail: bool,
    }

    impl MockBus {
        fn holding(registers: [u8; TIME_REGISTER_COUNT], status: u8) -> Self {
            Self {
                registers,
                status,
                ..Default::default()
            }
        }
    }

    impl RegisterBus for MockBus {
        type Error = ();

        fn write(&mut self, write: &RegisterWrite) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            let mut payload = heapless::Vec::new();
            payload.extend_from_slice(write.payload()).unwrap();
            self.writes.push((write.register(), payload)).unwrap();
            Ok(())
        }

        fn read(&mut self, register: u8, out: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            let _ = self.reads.push(register);
            match register {
                REG_STATUS => out[0] = self.status,
                REG_SECONDS => out.copy_from_slice(&self.registers),
                other => panic!("read of unexpected register {other:#04x}"),
            }
            Ok(())
        }
    }

    #[test]
    fn a_firmware_shaped_implementation_drives_the_whole_read() {
        let mut bus = MockBus::holding(KNOWN_REGS, 0x00);
        assert_eq!(read_clock(&mut bus), Ok(KNOWN_UNIX_MS));
    }

    /// Status is read before the time registers, because it is what decides
    /// whether they mean anything.
    ///
    /// Asserted on the transaction order rather than only on the result, so the
    /// test still fails if someone reorders the reads in a way that happens to
    /// produce the right answer for a healthy part.
    #[test]
    fn the_stop_flag_is_read_before_the_time_registers() {
        let mut bus = MockBus::holding(KNOWN_REGS, 0x00);
        read_clock(&mut bus).unwrap();
        assert_eq!(
            bus.reads.as_slice(),
            &[REG_STATUS, REG_SECONDS],
            "the status check must come first, and must not be skipped",
        );
    }

    /// Firmware cannot skip the stop-flag check, because firmware does not own
    /// the sequence. Under a driver that exposed raw reads, this rule would be
    /// a comment.
    #[test]
    fn core_owns_the_stop_flag_check_so_a_driver_cannot_skip_it() {
        let mut bus = MockBus::holding(KNOWN_REGS, OSCILLATOR_STOP_FLAG);
        assert_eq!(
            read_clock(&mut bus),
            Err(ReadError::Clock(ClockError::OscillatorStopped)),
            "well-formed registers behind a raised stop flag must not be believed",
        );
    }

    /// A bus failure and an untrustworthy reading are different events and must
    /// not collapse into one.
    #[test]
    fn a_bus_failure_is_distinguishable_from_an_unbelievable_reading() {
        let mut bus = MockBus {
            fail: true,
            ..MockBus::holding(KNOWN_REGS, 0x00)
        };
        assert_eq!(read_clock(&mut bus), Err(ReadError::Bus(())));

        let mut junk = MockBus::holding([0xFF; TIME_REGISTER_COUNT], 0x00);
        assert!(matches!(read_clock(&mut junk), Err(ReadError::Clock(_))));
    }

    /// The time is written before the flag is acknowledged, and never after.
    ///
    /// Getting this backwards clears the only durable record that the registers
    /// were stale while they are still stale — a detectable fault becomes a
    /// confidently wrong date. It is the single most consequential ordering rule
    /// in the module, and it is now not a caller's to get wrong.
    #[test]
    fn the_clock_is_set_before_the_stop_flag_is_acknowledged() {
        let mut bus = MockBus::holding(KNOWN_REGS, 0x8B);
        let time = CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap();
        set_clock(&mut bus, &time).unwrap();

        assert_eq!(bus.writes.len(), 2, "exactly two writes");
        assert_eq!(bus.writes[0].0, REG_SECONDS, "the time is written first");
        assert_eq!(
            bus.writes[1].0, REG_STATUS,
            "the acknowledgement comes second",
        );
        assert_eq!(bus.writes[0].1, KNOWN_REGS, "the encoded time");
        assert_eq!(
            bus.writes[1].1.as_slice(),
            &[0x0B],
            "the stop bit cleared, the 32 kHz enable and alarm flags preserved",
        );
    }

    /// The status byte the acknowledgement preserves is read here, not supplied
    /// by a caller who might hand over a stale one.
    #[test]
    fn set_clock_reads_the_status_it_is_about_to_preserve() {
        let mut bus = MockBus::holding(KNOWN_REGS, 0x88);
        set_clock(&mut bus, &CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap()).unwrap();
        assert_eq!(bus.reads.as_slice(), &[REG_STATUS]);
        assert_eq!(bus.writes[1].1.as_slice(), &[0x08]);
    }

    /// The seam itself: nothing that reached the mock could have named a banned
    /// register, because nothing outside this module chose one.
    #[test]
    fn no_write_reaching_the_bus_targets_the_scratchpad() {
        let mut bus = MockBus::holding(KNOWN_REGS, 0xFF);
        set_clock(&mut bus, &CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap()).unwrap();

        assert!(!bus.writes.is_empty(), "the check must see traffic");
        for (register, _) in &bus.writes {
            assert!(
                !is_scratchpad_register(*register),
                "a write reached the bus at {register:#04x}",
            );
        }
    }

    /// A full turn of the crank: set a clock, read back what the part would now
    /// hold, and get the instant that went in.
    #[test]
    fn a_clock_that_was_set_reads_back_as_the_time_it_was_set_to() {
        let time = CivilTime::new(2026, 8, 27, 14, 5, 9).unwrap();

        let mut bus = MockBus::holding([0x00; TIME_REGISTER_COUNT], OSCILLATOR_STOP_FLAG);
        set_clock(&mut bus, &time).unwrap();

        // What the part would hold afterwards: the written time, and a status
        // whose stop flag the acknowledgement cleared.
        let mut written = [0u8; TIME_REGISTER_COUNT];
        written.copy_from_slice(&bus.writes[0].1);
        let mut settled = MockBus::holding(written, bus.writes[1].1[0]);

        assert_eq!(read_clock(&mut settled), Ok(time.unix_ms()));
    }
}
