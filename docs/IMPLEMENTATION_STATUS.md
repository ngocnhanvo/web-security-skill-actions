# Implementation status

V1 is a narrow, intentionally non-invasive website posture auditor, not a comprehensive vulnerability scanner.

- Implemented public HTTPS/TLS expiration, response security-header/cookie observations, and unverified server technology version hints.
- Authorized mode is gated by user-selected same-host HTTPS JSON and explicit host, challenge, date and test-path checks.
- Active tests are fixed GET-only heuristics; no exploitation, brute force or credential attempts.
- Local offline tests exist in `tests/`; GitHub Actions CI runs them on push.
- Public Actions artifact contains a redacted summary and intentionally excludes private active findings.
- Not implemented: full CVE correlation, full HTTP-site crawling, authenticated application testing, complete OWASP ASVS coverage.
- GitHub Actions execution and real-domain test still require separate verified CI/run evidence.
