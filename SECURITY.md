# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in IceSickle, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email details to: mezoozpress@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix timeline within 7 days.

## Security Model

Before reporting, please review [THREAT_MODEL.md](THREAT_MODEL.md) to understand what is and isn't in scope.

**In scope:**
- Vulnerabilities in the signing/key generation logic
- Memory safety issues (buffer overflows, use-after-free, etc.)
- Failures to zeroize key material
- Entropy source weaknesses
- Serialization bugs that could lead to signature bypass

**Out of scope (by design):**
- Physical attacks requiring device access
- Device cloning (no device identity by design)
- Firmware replacement (no secure boot by design)
- Clock manipulation (no secure time source by design)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅ (pre-release, best-effort) |

## Cryptographic Dependencies

IceSickle uses:
- `ed25519-dalek` v2.x - Ed25519 signatures
- `zeroize` v1.x - Secure memory clearing
- ESP-IDF hardware RNG - Entropy source

We track security advisories for these dependencies via `cargo audit`.
