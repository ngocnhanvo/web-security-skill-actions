# Website Security Auditor V1 — specification

## Goal

With only an HTTPS domain, deliver a conservative public assessment of directly observable HTTPS/TLS and browser response security settings. With separate verified owner permission, add a tiny fixed set of GET-only SQL error, HTML-reflection and unauthenticated-access heuristics. No claim of comprehensive penetration testing.

## Inputs

- `domain`: exact apex/hostname, HTTPS port 443 only.
- `authorization_url`: optional arbitrary same-host HTTPS path to permission JSON; never force `.well-known`.
- `challenge`: independent unpredictable token issued by operator; must match owner-hosted permission JSON.
- Allowlisted `test_paths` and test types are supplied by website controller, not discovered by crawler.

## Safety requirements

- DNS must resolve exclusively to globally routable addresses; pin TLS connections to validated IP and verify certificate/SNI.
- No redirects followed; request timeout and response limit; abort at 429/5xx; at most 30 GET requests and 1 per second, concurrency 1.
- No POST, login attempt, guessing, password spraying, code execution, data modification, data extraction or cookie replay.
- Owner authorization must match exact hostname, challenge, dates and explicitly scoped paths, and be fetched again every scan.
- Public outputs must not include secrets, payloads, vulnerable endpoints or detailed active findings.

## Evidence and uncertainty

- Configuration findings are observed only for tested page/response.
- SQL error, HTML reflection and owner-marker exposure are suspected observations, not confirmed exploitation.
- Version banners are hints only; CVE claims require vendor/NVD verification of affected versions/config/backports.
- Not checking a category means NOT TESTED, never PASS or OWASP certification.

## Acceptance

- Offline tests prove bad DNS, redirects, host/port mismatch, invalid/revoked consent and request budgets fail closed.
- An unconsented scan never issues active GET probes.
- The public artifact omits active URLs and findings.
- The CI workflow passes on GitHub-hosted runner, independently from offline test results.
