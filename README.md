# Web Security Auditor Actions — low-impact domain checks

This is the **public runner** for `ngocnhanvo/web-security-skill` (private). The scanner implements a conservative **V1**, not full penetration testing or an OWASP ASVS certification.

## Safety contract

- **Without consent**: one HTTPS homepage GET, TLS certificate observation, response header/cookie observations, conservative technology version hints. DNS is resolved and checked for non-global addresses. HTTPS connections pin the validated global IP and validate the original hostname through TLS/SNI. No redirect is followed; no port scan, brute force, discovery crawler or injection.
- **With valid current consent**: only owner-listed GET paths and test types, at most 30 HTTP requests including the homepage and authorization file, serial requests spaced at least one second apart. Stop on 429, 5xx, network error, redirect or budget exhaustion. SQLi = one `'` heuristic; XSS = inert markup reflection (NO script execution); basic guest access = one owner-listed path with an expected protected marker. Findings are **suspected**, never proven exploitable.
- Permission JSON can be at **any public HTTPS path** on the exact target hostname. Supplied URL is validated and never redirected. Consent requires a fresh challenge, expiry <= 7 days and a precise allowlist. It is evidence of site-file control and expressed consent, not definitive legal authorization: obtain written permission from the party with authority.
- Public GitHub Actions inputs, logs and artifacts may be visible to others. The workflow uploads **only a reduced summary**, deliberately excluding detailed active findings, paths and request/response content. Full detail exists only in the ephemeral runner directory and is deleted with the runner. If you need private detailed evidence, execute the same CLI in your own controlled environment and keep the full report private.

## Development / tests

Requires Python 3.12+; uses only Python standard library.

```bash
python3 -m unittest discover -s tests -v
```

Create an authorization document (site owner must review, select explicit paths, and change `consent_confirmed` to `true`):

```bash
python3 -m auditor challenge --domain example.com --out site-permission.json
```

Upload the edited file to an arbitrary public HTTPS location on the target host. Then use its exact URL, and the `authorization_id` from your generated file, as inputs:

```bash
python3 -m auditor scan --domain example.com \
  --authorization-url https://example.com/my-test/permission.json \
  --challenge REPLACE_WITH_GENERATED_AUTHORIZATION_ID \
  --out private-report.json --public-out public-summary.json
```

Without any permission file:

```bash
python3 -m auditor scan --domain example.com --public-out public-summary.json
```

For **GitHub Actions**: open `Actions → Low-impact website security audit → Run workflow` and enter `domain`; leave permission URL and challenge blank for public-only mode. To run authorized mode, provide both values. Do not send arbitrary inputs to a scanner outside your permission scope.

## Output and interpretation

- `public.findings`: direct configuration observations (e.g. absent security headers). Severity is a prioritization suggestion, not proof of compromise.
- `public.admin_interface_exposure`: Low-severity `ADMIN_INTERFACE_EXPOSURE` when an explicit administration link label (visible text, aria-label or title) advertises the same hostname or a descendant hostname in the already-fetched homepage HTML. Status is `warning`, `not_found` (not observed within that HTML only) or `not_tested` (unusable response). Evidence types are redacted categories, not URLs. No guessing admin URLs or hostnames, DNS enumeration, following links, login attempts or disclosure of link targets. The destination is not verified, and this is not authentication bypass. Prefer MFA and effective authorization over relying on hidden URLs.
- `public.technology_hints`: unverified product/version signals extracted from headers, **not automatic CVE matches**. CVE correlation requires validated component identity, affected version range, applicability and backport checks.
- `active.findings`: locally stored *suspected* SQLi / XSS reflection / guest access observations; no exploit payload, no script execution, no database extraction.
- `authorization`: `public_only` / `authorized` / `invalid`.
- `scan_status`: `completed` / `halted`, where `halted` is not a clean pass.

OWASP references: [WSTG 4.2](https://wstg.owasp.org/v4.2/), [ASVS 5.0.0](https://asvs.owasp.org/), [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html) (`security.txt` does **not** grant permission to test).

## V1 intentionally not included

Deep CVE verification, ZAP active scans, Nuclei templates, XSS browser execution, SQLi exploitation, full authentication bypass testing, WAF testing, source audit and production performance testing. Add these only after separate scope reviews, opt-in and dedicated safety tests.
