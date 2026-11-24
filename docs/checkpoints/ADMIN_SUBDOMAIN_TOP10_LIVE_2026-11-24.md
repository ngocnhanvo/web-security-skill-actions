# Top 10 administration hostname review — 2026-11-24

## Scope and evidence
- Actions implementation: `cbc445edb6c1fedfb4ab48a215f631df3a1b9ff6`; skill guidance: `e13332a65c242b62c604d3881857591d43e6cfb4`.
- Exactly ten direct-child hostname candidates per supplied domain: admin, quantri, administrator, cms, backend, panel, manage, dashboard, portal, cpanel.
- Global DNS check, pinned validated TLS/HTTPS:443, GET only, at most one same-host path-only redirect, no cross-host redirect, no login submission. HTML (when retrievable) is rendered offline with Playwright; redirect and TLS failures are NOT proof of absence.
- Initial runner CI: 76/76 passed, https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45320708177.
- Updated runner's esc.vn audit tested 79/79 successfully; https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45321323857.

## esc.vn
- Initial ten-host run: https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45320813968, public-security-summary artifact 14888255107, decoded from its JSON in current session.
- Final redirect-aware run: https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45321323857, artifact 14887139013, decoded from its JSON in current session.
- DNS attempted 10/10. `admin.esc.vn`: global DNS, two HTTPS GETs: first 302, next 302; first safe same-host redirect followed, next redirect rejected as cross-host or unsafe. No HTML interface classified. The other nine names returned DNS unresolved/error. No confirmed admin login candidate. Not a site-wide security clearance.

## taphoatuoiduynh.duckdns.org
- Initial ten-host run: https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45320817368, public-security-summary artifact 14887895712, decoded from its JSON in current session.
- DNS attempted 10/10; all ten returned global IPs. One pinned HTTPS GET attempted for each: all ten reported TLS/HTTP/response errors; HTTP status unavailable, offline browser NOT TESTED. Could reflect wildcard DNS; no conclusion about ten individually configured sites. No confirmed admin login candidate.
- Redirect-aware recheck initiated: https://github.com/ngocnhanvo/web-security-skill-actions/actions/runs/45321327834; as of this checkpoint, in-progress at Install pinned offline browser. Do not claim its report was read.

## Interpretation
- The phrase 'scan completed' means all requested DNS/HTTPS attempts were recorded, NOT that an administration page was ruled out.
- In both domains, zero observed visual admin-login candidates; there are **unknowns** (ESC redirect and taphoa HTTPS/TLS errors).
- The public report lists every candidate and outcome. No passwords, SQLi, XSS, authentication bypass, hidden paths or screenshots were attempted.
