//! Host-side verification of IceSickle attestations captured from a serial log.
//!
//! The firmware prints an attestation over serial. This crate parses that text
//! and checks the things a verifier can actually check today:
//!
//! - the signature verifies against the public key over the exact signed bytes,
//! - the signed payload is exactly [`ATTESTATION_PAYLOAD_LEN`] bytes, i.e. the
//!   fixed-length padding held,
//! - the entropy gate was demonstrated in the right order at boot.
//!
//! It deliberately does **not** claim the attestation is evidence of an event.
//! See `docs/VERIFIER_MODEL.md` for why that is out of reach today.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Re-exported from the firmware's own crate, so the verifier and the device
/// cannot disagree about how long a signed payload is.
pub use icesickle_core::ATTESTATION_PAYLOAD_LEN;

/// An attestation recovered from a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub payload: Vec<u8>,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A labelled line was not present in the log.
    MissingField(&'static str),
    /// A field was present but was not valid hex.
    BadHex(&'static str),
    /// A field decoded to the wrong number of bytes.
    BadLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// The public key was not a valid Ed25519 point.
    BadPublicKey,
    /// The signature did not verify over the signed payload.
    SignatureInvalid,
    /// The boot-time entropy gate did not behave as expected.
    Gate(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingField(x) => write!(f, "log has no `{x}:` line"),
            Error::BadHex(x) => write!(f, "`{x}` is not valid hex"),
            Error::BadLength {
                field,
                expected,
                got,
            } => write!(f, "`{field}` is {got} bytes, expected {expected}"),
            Error::BadPublicKey => write!(f, "public key is not a valid Ed25519 point"),
            Error::SignatureInvalid => write!(f, "signature does not verify over the payload"),
            Error::Gate(x) => write!(f, "entropy gate: {x}"),
        }
    }
}

impl std::error::Error for Error {}

/// Pull the value following `label:` on the first line that contains it.
fn field<'a>(log: &'a str, label: &str) -> Option<&'a str> {
    log.lines()
        .find_map(|line| line.split_once(label).map(|(_, rest)| rest.trim()))
        .filter(|v| !v.is_empty())
}

fn unhex(s: &str, what: &'static str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::BadHex(what));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::BadHex(what)))
        .collect()
}

/// Recover an attestation from serial output.
pub fn parse_log(log: &str) -> Result<Attestation, Error> {
    let payload = unhex(
        field(log, "payload:").ok_or(Error::MissingField("payload"))?,
        "payload",
    )?;
    let pk = unhex(
        field(log, "pubkey:").ok_or(Error::MissingField("pubkey"))?,
        "pubkey",
    )?;
    let sig = unhex(
        field(log, "signature:").ok_or(Error::MissingField("signature"))?,
        "signature",
    )?;

    let public_key: [u8; 32] = pk.as_slice().try_into().map_err(|_| Error::BadLength {
        field: "pubkey",
        expected: 32,
        got: pk.len(),
    })?;
    let signature: [u8; 64] = sig.as_slice().try_into().map_err(|_| Error::BadLength {
        field: "signature",
        expected: 64,
        got: sig.len(),
    })?;

    Ok(Attestation {
        payload,
        public_key,
        signature,
    })
}

/// The signed payload must be exactly the fixed length, for every event type.
///
/// This is the traffic-analysis property from the spike: if it ever fails, an
/// attestation's length has started leaking something about its contents.
pub fn check_payload_len(a: &Attestation) -> Result<(), Error> {
    if a.payload.len() == ATTESTATION_PAYLOAD_LEN {
        Ok(())
    } else {
        Err(Error::BadLength {
            field: "payload",
            expected: ATTESTATION_PAYLOAD_LEN,
            got: a.payload.len(),
        })
    }
}

/// Check the signature over the exact bytes that were signed.
pub fn verify(a: &Attestation) -> Result<(), Error> {
    let vk = VerifyingKey::from_bytes(&a.public_key).map_err(|_| Error::BadPublicKey)?;
    let sig = Signature::from_bytes(&a.signature);
    vk.verify(&a.payload, &sig)
        .map_err(|_| Error::SignatureInvalid)
}

/// Confirm the boot-time entropy gate behaved as the spike claims.
///
/// The firmware logs "gate holds" before creating a `TrngSource` and "gate open"
/// after. Either of the "UNEXPECTED" branches firing means the gate did not do
/// what `docs/NOSTD_ENTROPY_SPIKE.md` says it does, which matters more than any
/// other assertion here.
pub fn check_gate(log: &str) -> Result<(), Error> {
    if log.contains("UNEXPECTED") {
        return Err(Error::Gate("firmware reported an UNEXPECTED gate state"));
    }
    let closed = log
        .find("gate holds")
        .ok_or(Error::Gate("no 'gate holds' line before TrngSource"))?;
    let open = log
        .find("gate open")
        .ok_or(Error::Gate("no 'gate open' line after TrngSource"))?;
    if closed >= open {
        return Err(Error::Gate("'gate open' appeared before 'gate holds'"));
    }
    Ok(())
}

/// Run every check against a captured log.
pub fn check_all(log: &str) -> Result<Attestation, Error> {
    check_gate(log)?;
    let a = parse_log(log)?;
    check_payload_len(&a)?;
    verify(&a)?;
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Build a log that looks like real firmware output, signed for real.
    /// Fixed seed, so this is deterministic.
    ///
    /// `parse_log` never reads the timestamp line — only `payload:`, `pubkey:`
    /// and `signature:` — so the clock line here is decoration and no test
    /// depends on its shape. It is kept matching the firmware anyway: a fixture
    /// that has quietly stopped resembling the thing it imitates is worth less
    /// with every release, and this one said "ms since boot" for three decisions
    /// after that stopped being true.
    fn good_log() -> String {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut payload = [0u8; ATTESTATION_PAYLOAD_LEN];
        payload[..4].copy_from_slice(&[1, 0, 0, 42]); // encoded head, rest is padding
        let sig = sk.sign(&payload);
        format!(
            "INFO - IceSickle no_std firmware\n\
             INFO - gate holds: no true entropy available before TrngSource exists\n\
             INFO - TrngSource live: SAR-ADC entropy enabled, radio off\n\
             INFO - gate open: true entropy available\n\
             INFO - === ATTESTATION ===\n\
             INFO - event:     ButtonPress {{ gpio: 0 }}\n\
             INFO - clock: OK   2026-08-27T14:05:09Z (1787839509000 ms)\n\
             INFO - timestamp: 1787839509000 (Unix ms)\n\
             INFO - payload:   {}\n\
             INFO - pubkey:    {}\n\
             INFO - signature: {}\n",
            hex(&payload),
            hex(sk.verifying_key().as_bytes()),
            hex(&sig.to_bytes()),
        )
    }

    #[test]
    fn accepts_a_genuine_attestation() {
        let a = check_all(&good_log()).expect("genuine attestation should verify");
        assert_eq!(a.payload.len(), ATTESTATION_PAYLOAD_LEN);
    }

    #[test]
    fn rejects_a_tampered_payload() {
        // Flip a bit inside the padding: still the right length, still parses.
        let log = good_log().replace("payload:   0100002a", "payload:   0100002b");
        assert_eq!(check_all(&log), Err(Error::SignatureInvalid));
    }

    #[test]
    fn rejects_a_short_payload() {
        let good = good_log();
        let full = field(&good, "payload:").unwrap().to_string();
        let log = good.replace(&full, &full[..full.len() - 2]);
        assert!(matches!(
            check_all(&log),
            Err(Error::BadLength {
                field: "payload",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_missing_field() {
        let log = good_log()
            .lines()
            .filter(|l| !l.contains("signature:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(check_all(&log), Err(Error::MissingField("signature")));
    }

    #[test]
    fn rejects_an_unexpected_gate_state() {
        let log = good_log().replace(
            "gate holds: no true entropy available before TrngSource exists",
            "UNEXPECTED: true entropy reported available before TrngSource exists",
        );
        assert!(matches!(check_all(&log), Err(Error::Gate(_))));
    }

    #[test]
    fn rejects_a_gate_opening_out_of_order() {
        let mut log = String::from("INFO - gate open: true entropy available\n");
        log.push_str("INFO - gate holds: no true entropy available\n");
        assert!(matches!(check_gate(&log), Err(Error::Gate(_))));
    }

    #[test]
    fn rejects_a_log_with_no_attestation() {
        assert!(check_all("INFO - gate holds\nINFO - gate open\n").is_err());
    }
}
