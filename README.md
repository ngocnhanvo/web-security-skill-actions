# Web Security Auditor Actions — low-impact domain checks

This is the **public runner** for `ngocnhanvo/web-security-skill` (private). The scanner implements a conservative **V1**, not full penetration testing or an OWASP ASVS certification.

## Safety contract

- **Without consent**: one HTTPS homepage GET by default, TLS certificate observation, response header/cookie observations, conservative technology version hints. An explicit `--admin-subdomains` flag (enabled in the public workflow) adds up to ten direct-child hostname candidates with at most two HTTPS GETs per publicly resolvable candidate, including one safe same-host redirect; each result is listed. DNS and TLS are checked before a GET, and Playwright renders received HTML offline without JavaScript or network. This is limited recognition, not vulnerability exploitation. DNS is resolved and checked for non-global addresses. HTTPS connections pin the validated global IP and validate the original hostname through TLS/SNI. Only one same-host HTTPS path-only redirect may be followed in admin subdomain mode; no port scan, brute force, discovery crawler or injection.
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

## Offline owner administration inventory

For deeper configuration review use an owner-completed private copy of `templates/admin-inventory.example.json`. Use a non-sensitive alias for each actual interface and enter the owner's observed controls. This local mode does not contact any server or discover hostnames.

```bash
python3 -m auditor review-admin-inventory --input owner-inventory.json --out private-inventory-review.json
```

Do not commit real inventories or reports to the public repository. The command labels all answers as owner-reported, not independently verified; unknown controls remain not verified. No network probing or authentication test is performed. See [admin interface review](docs/admin-interface-review.md).

## Top 10 administration review

Public HTML observations count at most ten distinct explicitly advertised descendant hostnames, with an overflow flag; no names are disclosed or contacted. The count is not a prevalence ranking. The local owner inventory optionally accepts `publicly_advertised` (yes/no/unknown) and `name_prevalence` (high/medium/low/unknown). Prioritize advertised records first, then high and medium declared name prevalence, with a deterministic alias tie-break. Select at most ten eligible existing records in `priority_review`; full control review remains unchanged. Prevalence is the owner's assessment, not measured statistics. No guessed hostnames, wordlists or additional requests.

## Optional offline Playwright interface review

For an owner-provided UTF-8 HTML snapshot, install Playwright and its Chromium browser in a controlled local environment, then run:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 -m auditor review-admin-snapshot --input owner-page.html --out private-interface-review.json
```

The browser renders supplied HTML offline, with JavaScript disabled and requests aborted. It does not navigate to websites, generate hostnames, submit forms, or enter credentials. A candidate admin login requires explicit administration labels plus a visible form/password input. Error or ambiguous pages do not receive a Low candidate warning. Results never establish live reachability or authentication bypass. Keep snapshots and reports private. Browser integration tests are enabled in CI via RUN_OFFLINE_BROWSER_TESTS=1. The audit workflow also uses --offline-browser to classify only the existing homepage HTML response, without following links or requesting additional destinations; the redacted field is public.homepage_browser_review. Browser failure is reported as not_tested.

## Public Top 10 hostname checks (implemented)

The Public Audit workflow enables `--admin-subdomains` automatically. The exact, fixed, **unranked** candidate prefixes are `admin`, `quantri`, `administrator`, `cms`, `backend`, `panel`, `manage`, `dashboard`, `portal`, `cpanel`. Each is prepended to the **exact supplied hostname**, not to its registrable parent; e.g. `admin.example.com`. These are common-name examples, **not statistically measured popularity**.

The `public.admin_subdomain_review.results` array lists **all ten hostnames**, including DNS failures, non-global IP rejection, TLS/HTTP errors, cross-host redirects not followed, same-host redirects limited to one, status codes, offline Chromium classification, and any Low admin-login candidate. Only explicit admin labels plus a visible login form and password input produce Low. Missing DNS, 403, redirects, browser errors and uncertain pages are **not** security passes. No login submission, brute force, JavaScript execution, browser network fetching, cross-host redirects or data extraction. The report includes exact per-host request counts, initial/final HTTP status and a safe redirect category. Global budget is at most 30 requests, at least 1 second between GETs; stop remaining candidates after 429 or 5xx.

Standalone local invocation:

```bash
python3 -m auditor scan --domain example.com --offline-browser --admin-subdomains --public-out public-summary.json
```

The authorization mode is separate; the CLI rejects using `--admin-subdomains` together with `--authorization-url`. Since predictable hostnames are included in publicly visible scan artifacts, do not use public Actions for private infrastructure inventories.

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
