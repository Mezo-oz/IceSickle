//! DS3231 transport: the bytes, and nothing else.
//!
//! This module is deliberately the least interesting file in the firmware. It
//! forwards bytes to an I2C address and forwards errors back. It parses
//! nothing, decides nothing, and sequences nothing.
//!
//! # Why it is this thin
//!
//! Everything that could be got wrong about the DS3231 lives in
//! [`icesickle_core::clock`], on purpose:
//!
//! - **What a reading means**, including the three ways a reading can be
//!   well-formed and false — a dead coin cell behind a raised oscillator-stop
//!   flag, a floating bus reading `0xFF`, a part left in 12-hour mode.
//! - **What order to do things in.** The stop flag must be read before the time
//!   registers mean anything, and the clock must be set before that flag is
//!   acknowledged. Both rules are enforced by
//!   [`read_clock`](icesickle_core::clock::read_clock) and
//!   [`set_clock`](icesickle_core::clock::set_clock) owning the sequence.
//! - **Which registers may be written at all**, via
//!   [`RegisterWrite`](icesickle_core::clock::RegisterWrite).
//!
//! That split is not tidiness. `firmware/nostd` can host no tests — a test
//! target needs the `test` crate and a `#[panic_handler]` a `no_std` binary
//! cannot provide, which is why CI builds this crate `--lib --bins`. Any logic
//! that lived here would be verified by nothing at all; the emulator proves the
//! firmware boots, not that it is right. Every rule above is covered by host
//! tests on stable *because* it is not in this file.
//!
//! So the measure of this module is how little it contains. If it starts
//! growing branches, the logic has drifted to the side of the boundary that
//! cannot test it.
//!
//! # The ban, and why ownership is part of it
//!
//! `icesickle_core::clock::RegisterWrite` makes a write to the DS3231's
//! battery-backed scratchpad registers unrepresentable, and [`Ds3231`]'s
//! [`RegisterBus`] implementation cannot express one either — it never receives
//! a register number for a write, only a sealed value it forwards.
//!
//! A type cannot stop firmware from driving the bus directly, though, so
//! [`Ds3231::new`] **consumes** the `I2c` peripheral rather than borrowing it.
//! After construction no raw handle survives anywhere else, and the only code in
//! this crate that can reach the DS3231 is the two method bodies below. That is
//! not a proof, it is a small enough surface to read in one sitting — which,
//! absent a mechanism the silicon does not offer, is the ceiling.

use esp_hal::Blocking;
use esp_hal::i2c::master::{Error, I2c};

use icesickle_core::clock::{I2C_ADDRESS, RegisterBus, RegisterWrite};

/// The DS3231, holding the I2C peripheral it speaks over.
///
/// Owning rather than borrowing is the point — see the module docs.
pub struct Ds3231<'d> {
    i2c: I2c<'d, Blocking>,
}

impl<'d> Ds3231<'d> {
    /// Take the bus.
    ///
    /// The caller configures pins and speed, because the pinout is a board fact
    /// and belongs next to the other board facts in `main.rs`, not buried here.
    /// What this type guarantees is that once it holds the peripheral, nothing
    /// else does.
    pub fn new(i2c: I2c<'d, Blocking>) -> Self {
        Self { i2c }
    }
}

impl RegisterBus for Ds3231<'_> {
    type Error = Error;

    fn write(&mut self, write: &RegisterWrite) -> Result<(), Self::Error> {
        // The register byte is already the first byte of `bytes()`, chosen in
        // core. There is no argument here to get wrong.
        self.i2c.write(I2C_ADDRESS, write.bytes())
    }

    fn read(&mut self, register: u8, out: &mut [u8]) -> Result<(), Self::Error> {
        // Set the register pointer, then read: one transaction with a repeated
        // start, which is what the DS3231 expects and what keeps another master
        // from moving the pointer in between.
        self.i2c.write_read(I2C_ADDRESS, &[register], out)
    }
}
