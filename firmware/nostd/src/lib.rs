#![no_std]

pub mod button;
pub mod clock;
pub mod entropy;

// Attestation logic, the debounce state machine and the cooldown all live in
// `icesickle-core`, which is platform-independent and host-testable. This crate
// supplies only what is genuinely hardware: entropy from the SAR-ADC-backed
// TRNG, the clock, and the GPIO the trigger is wired to.
pub use icesickle_core as attestation;
