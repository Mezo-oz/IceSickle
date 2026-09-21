//! Platform-independent IceSickle device logic.
//!
//! The attestation itself lives at the crate root; the debounced button state
//! machine is in [`button`], the rate limit in [`cooldown`], the DS3231 register
//! codec in [`clock`], and the models for emission and power in [`emission`] and
//! [`power`]. They share one rule — **no hardware, and no clock of their own**.
//! Every reading a decision depends on arrives as a parameter.
//!
//! [`clock`] is not the exception it looks like. It decodes the bytes of a
//! real-time clock and owns the order it is read in, but never touches a bus:
//! the firmware supplies a [`clock::RegisterBus`] that forwards bytes, the same
//! way it passes `now_ms` to [`cooldown`]. Keeping the seam there is what makes
//! a part nobody here owns testable on a host that does not have one — a mock
//! bus stands in for the chip.
//!
//! [`auth`] is the exception: no code at all, only the constraint that keeps
//! device identity out of this project. Read it before adding anything that
//! could link two attestations to one device.
//!
//! Everything here is deterministic. Ed25519 signing is deterministic by
//! construction, and postcard encoding is deterministic by requirement, so the
//! only non-deterministic inputs an attestation has are the entropy seed and the
//! clock — and both are **parameters**, supplied by the caller.
//!
//! That is the whole point of this crate. The firmware fills the seed from a
//! [`Trng`]-backed source and the timestamp from the DS3231 (D13); a host test
//! passes fixed bytes and asserts exact signature output. The signing path is
//! therefore fully covered on any machine, with no ESP32 and no emulator —
//! which matters because Espressif's QEMU cannot reach this code at all
//! (`esp_hal::init()` does not return under it; see
//! `docs/NOSTD_ENTROPY_SPIKE.md`).
//!
//! [`button`] and [`cooldown`] are here for the same reason. Their esp-idf
//! ancestors read `esp_timer_get_time()` internally and, in the cooldown's
//! case, kept state in a `static`, so neither could be exercised without an
//! ESP32 and neither had a test worth the name. Taking `now_ms` as an argument
//! is the entire difference between that and the suites in those modules.
//!
//! `no_std` and allocator-free: postcard is built without its `alloc` feature,
//! so `to_allocvec` is unreachable and a signed payload cannot end up on a heap.
//!
//! [`Trng`]: https://docs.rs/esp-hal/latest/esp_hal/rng/struct.Trng.html

#![no_std]

pub mod auth;
pub mod button;
pub mod clock;
pub mod cooldown;
pub mod emission;
pub mod power;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Length of the signed payload, identical for every attestation.
///
/// Traffic-analysis hygiene. A postcard encoding of [`AttestationPayload`] is
/// variable-length — varints shrink for small timestamps and counters, and event
/// variants carry different field counts. Signing the natural encoding would
/// leak which event produced an attestation, and roughly how long the device had
/// been powered, before any transport tier got a chance to hide anything.
///
/// So the encoder writes into a zero-filled buffer of this size and the whole
/// buffer is signed. The padding is *inside* the signed region and cannot be
/// stripped or rewritten without invalidating the signature.
///
/// Two limits, stated plainly:
///
/// - This fixes the *emitted* length only. A transport carrying the payload in
///   cleartext still shows the trailing zero run, and therefore the true encoded
///   length, to anyone reading the bytes. That is the transport's problem.
/// - 32 is headroom, not a measurement: the current worst case is 18 bytes.
///   [`Attestation::create`] fails closed if a future variant overflows it.
///   `docs/TOKEN_PROTOCOL.md` settles v2 at 64, inside a 224-byte frame.
pub const ATTESTATION_PAYLOAD_LEN: usize = 32;

/// Current payload format version.
pub const PAYLOAD_VERSION: u8 = 1;

/// Events that can trigger an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationEvent {
    /// Physical button press.
    ButtonPress { gpio: u8 },
    /// Future: other physical events (switch, sensor threshold, etc.)
    Unknown,
}

/// The payload that gets signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub version: u8,
    pub event: AttestationEvent,
    /// Milliseconds since device boot.
    ///
    /// **v2 changes this to Unix milliseconds** (D13): the device has a
    /// battery-backed clock, and the arrival check in `TOKEN_PROTOCOL.md` §6
    /// step 8 needs a value comparable to a verifier's wall clock.
    ///
    /// Comparable is not the same as trusted. A seized device can be set to any
    /// time, so this is an input to be anchored, never an authority — the
    /// bounding in `docs/VERIFIER_MODEL.md` §3.2 and §3.3 is what carries the
    /// weight.
    pub timestamp_ms: u64,
    /// Monotonic counter. Resets on power cycle.
    pub counter: u32,
}

/// Failure modes of [`Attestation::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The encoded payload did not fit in [`ATTESTATION_PAYLOAD_LEN`] bytes.
    ///
    /// Fails closed on purpose: a payload we cannot pad to the fixed length
    /// would leak its event type by length, so we decline to sign it at all.
    PayloadTooLong,
}

/// A completed attestation. Public data only — the private key is already gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    event: AttestationEvent,
    timestamp_ms: u64,
    public_key: [u8; 32],
    signature: [u8; 64],
    signed_payload: [u8; ATTESTATION_PAYLOAD_LEN],
}

impl Attestation {
    /// Derive an ephemeral keypair from `seed`, sign the padded payload, and
    /// discard the key.
    ///
    /// **`seed` is zeroized before this returns**, whether it succeeds or fails.
    /// Taking `&mut` rather than a value is deliberate: it lets this function
    /// clear the caller's buffer rather than trusting the caller to remember.
    ///
    /// The ephemeral key itself is zeroized by `ed25519_dalek::SigningKey`'s own
    /// `Drop` (`signing.rs:659`, gated on the `zeroize` feature, enabled here).
    /// No wrapper re-states that guarantee, because we do not provide it.
    ///
    /// Deterministic: identical inputs produce byte-identical output.
    pub fn create(
        seed: &mut [u8; 32],
        event: AttestationEvent,
        timestamp_ms: u64,
        counter: u32,
    ) -> Result<Self, Error> {
        let payload = AttestationPayload {
            version: PAYLOAD_VERSION,
            event,
            timestamp_ms,
            counter,
        };

        // Zero-filled canvas; the encoder fills the front, the rest stays zero,
        // and the signature covers all of it.
        let mut signed_payload = [0u8; ATTESTATION_PAYLOAD_LEN];
        let encoded = postcard::to_slice(&payload, &mut signed_payload)
            .map_err(|_| Error::PayloadTooLong)
            .map(|used| used.len());

        let encoded = match encoded {
            Ok(n) => n,
            Err(e) => {
                seed.zeroize();
                return Err(e);
            }
        };
        debug_assert!(encoded <= ATTESTATION_PAYLOAD_LEN);

        let signing_key = SigningKey::from_bytes(seed);
        seed.zeroize();

        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&signed_payload).to_bytes();
        drop(signing_key);

        Ok(Self {
            event,
            timestamp_ms,
            public_key,
            signature,
            signed_payload,
        })
    }

    pub fn event(&self) -> AttestationEvent {
        self.event
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The exact bytes that were signed, padding included.
    ///
    /// A verifier needs these verbatim. Decode the event with
    /// `postcard::take_from_bytes`, which stops at the end of the struct and
    /// hands back the padding as the remainder.
    pub fn signed_payload_bytes(&self) -> &[u8; ATTESTATION_PAYLOAD_LEN] {
        &self.signed_payload
    }

    pub fn public_key_hex(&self) -> heapless::String<64> {
        hex_encode(&self.public_key)
    }

    pub fn signature_hex(&self) -> heapless::String<128> {
        hex_encode(&self.signature)
    }

    pub fn signed_payload_hex(&self) -> heapless::String<64> {
        hex_encode(&self.signed_payload)
    }
}

/// Hex encoding into a fixed-capacity string.
///
/// `N` must be `2 * bytes.len()`; every call site satisfies that, so the pushes
/// cannot fail. The debug assertion documents it rather than trusting it.
pub fn hex_encode<const N: usize>(bytes: &[u8]) -> heapless::String<N> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    debug_assert_eq!(N, bytes.len() * 2, "hex buffer must be exactly 2x input");

    let mut s = heapless::String::new();
    for &b in bytes {
        let _ = s.push(HEX_CHARS[(b >> 4) as usize] as char);
        let _ = s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    const SEED: [u8; 32] = [7u8; 32];

    fn attest(event: AttestationEvent, ts: u64, counter: u32) -> Attestation {
        let mut seed = SEED;
        Attestation::create(&mut seed, event, ts, counter).expect("should fit")
    }

    /// The signing path, pinned byte-for-byte.
    ///
    /// This is the coverage the emulator could not provide: identical inputs
    /// must produce identical signatures forever. If a dependency bump or a
    /// payload-layout change alters the output, this fails loudly rather than
    /// silently invalidating every attestation the field has already produced.
    #[test]
    fn signing_is_deterministic_and_pinned() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 12_345, 7);

        assert_eq!(
            a.signed_payload_hex().as_str(),
            "010000b960070000000000000000000000000000000000000000000000000000",
            "payload encoding changed"
        );
        assert_eq!(
            a.public_key_hex().as_str(),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "public key derivation changed"
        );
        assert_eq!(
            a.signature_hex().as_str(),
            "d55bcb74ebbf7afaeee329a355bbc9976f0f4bea1782f848cb43a78da20bfc2b9dc7ffc6f03ab6954ffd51347bc3e0a17fa991f618f2544d83df8f7960ddff09",
            "signature changed"
        );
    }

    #[test]
    fn identical_inputs_give_identical_output() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 3 }, 1, 1);
        let b = attest(AttestationEvent::ButtonPress { gpio: 3 }, 1, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn differing_inputs_give_differing_signatures() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 1, 1);
        let b = attest(AttestationEvent::ButtonPress { gpio: 0 }, 1, 2);
        assert_ne!(a.signature_bytes(), b.signature_bytes());
        // ... but the same length. That is the point of the padding.
        assert_eq!(
            a.signed_payload_bytes().len(),
            b.signed_payload_bytes().len()
        );
    }

    /// The traffic-analysis property, across every event variant and a range of
    /// field magnitudes that change the varint widths.
    #[test]
    fn payload_length_is_fixed_across_events_and_magnitudes() {
        let events = [
            AttestationEvent::ButtonPress { gpio: 0 },
            AttestationEvent::ButtonPress { gpio: 255 },
            AttestationEvent::Unknown,
        ];
        for event in events {
            for (ts, counter) in [(0u64, 0u32), (u64::MAX, u32::MAX), (12_345, 7)] {
                let a = attest(event, ts, counter);
                assert_eq!(
                    a.signed_payload_bytes().len(),
                    ATTESTATION_PAYLOAD_LEN,
                    "{event:?} ts={ts} counter={counter} changed the signed length"
                );
            }
        }
    }

    #[test]
    fn seed_is_zeroized_even_on_success() {
        let mut seed = SEED;
        let _ = Attestation::create(&mut seed, AttestationEvent::Unknown, 1, 1).unwrap();
        assert_eq!(seed, [0u8; 32], "seed survived signing");
    }

    #[test]
    fn signature_verifies_against_its_own_public_key() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 999, 3);
        let vk = VerifyingKey::from_bytes(a.public_key_bytes()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(a.signature_bytes());
        vk.verify(a.signed_payload_bytes(), &sig)
            .expect("attestation must verify against its own key");
    }

    #[test]
    fn tampering_with_padding_invalidates_the_signature() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 999, 3);
        let mut tampered = *a.signed_payload_bytes();
        // Flip a bit deep in the padding, which a naive verifier might ignore.
        tampered[ATTESTATION_PAYLOAD_LEN - 1] ^= 1;

        let vk = VerifyingKey::from_bytes(a.public_key_bytes()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(a.signature_bytes());
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "padding is inside the signed region and must not be malleable"
        );
    }

    /// A verifier recovers the event from the padded payload, and the remainder
    /// is padding rather than smuggled data.
    #[test]
    fn payload_round_trips_and_the_remainder_is_zero() {
        let a = attest(AttestationEvent::ButtonPress { gpio: 42 }, 12_345, 7);
        let (decoded, rest): (AttestationPayload, &[u8]) =
            postcard::take_from_bytes(a.signed_payload_bytes()).expect("should decode");

        assert_eq!(decoded.version, PAYLOAD_VERSION);
        assert_eq!(decoded.event, AttestationEvent::ButtonPress { gpio: 42 });
        assert_eq!(decoded.timestamp_ms, 12_345);
        assert_eq!(decoded.counter, 7);
        assert!(rest.iter().all(|b| *b == 0), "padding must be all zeros");
    }

    #[test]
    fn worst_case_payload_still_fits_with_room_to_spare() {
        let mut seed = SEED;
        let a = Attestation::create(
            &mut seed,
            AttestationEvent::ButtonPress { gpio: u8::MAX },
            u64::MAX,
            u32::MAX,
        )
        .expect("worst case must fit");

        let (_, rest): (AttestationPayload, &[u8]) =
            postcard::take_from_bytes(a.signed_payload_bytes()).unwrap();
        let encoded = ATTESTATION_PAYLOAD_LEN - rest.len();
        assert!(
            encoded <= 18,
            "worst-case encoding grew to {encoded} bytes; \
             docs/VERIFIER_MODEL.md sizing assumes 18"
        );
    }

    #[test]
    fn hex_encode_is_lowercase_and_padded() {
        let s: heapless::String<8> = hex_encode(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s.as_str(), "deadbeef");
        let s: heapless::String<4> = hex_encode(&[0x00, 0xff]);
        assert_eq!(s.as_str(), "00ff");
    }
}
