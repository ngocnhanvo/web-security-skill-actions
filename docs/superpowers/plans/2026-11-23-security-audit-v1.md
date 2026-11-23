# Domain-only Website Security Auditor V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task; tests precede implementation.

**Goal:** Deliver a least-impact domain-only public web configuration checker and a separately authorized, tightly scoped low-impact probe mode.

**Architecture:** Private ChatGPT skill describes scope and evidence. Public GitHub Actions runner uses only Python standard library, no unreviewed tool/payload updates, and never uploads sensitive raw scan results. Its default public mode is GET-only and single-origin; signed-in functionality is outside v1 scope.

**Tech Stack:** Python 3.12, unittest, GitHub Actions, YAML, JSON.

**Spec:** `docs/security-audit-v1-spec.md`.

## Global Constraints
- Only the explicit HTTPS hostname; no redirects; fail-closed on DNS private/non-global addresses; fixed port 443.
- Public mode does not inject SQLi or browser-executable XSS or access restricted routes.
- Authorized mode requires file URL supplied by user, exact hostname, fresh challenge, time window, precise allowed paths and tests, low request budget, rate cap.
- An authorization file is evidence of site control and expressed consent, not conclusive legal authority.
- Never label XSS/SQLi or auth bypass as confirmed based on heuristic response changes.
- Public repository artifacts may contain only sanitized summaries, not full requests/responses, credentials, cookies, precise vulnerable URLs or payloads.
- Fail safely on 429 and 5xx, DNS rebinding to private addresses, TLS errors and redirects.

## Review Focus
- URL with credential or port must be rejected and tested.
- DNS rebinding and all-private/mixed A/AAAA must fail before HTTP and tested.
- A public-only scan with any `authorization_url` failure must not emit probes and tested.
- Cookie HTTP response should never leak values into public report and tested.
- Read budget and 429 stop are hard gates and tested.

### Task 1 — Target parsing and pinned HTTPS transport
**Files:** `auditor/network.py`, `tests/test_network.py`.
**Interfaces:** `validate_target`, `resolve_global_ips`, `PinnedHTTP`, `AuditError`.
- [x] RED: add target and SSRF tests; run unittest and see module missing.
- [x] GREEN: validate HTTPS hostname and DNS; implement TLS pinned HTTP with size/time limits and no redirects.
- [x] VERIFY: run `python -m unittest discover -s tests -v`.

### Task 2 — Consent protocol and budget
**Files:** `auditor/authorization.py`, `auditor/budget.py`, `tests/test_authorization.py`.
**Interfaces:** `Authorization`, `validate_authorization`, `Budget`.
- [x] RED: missing/expired/challenge/path tests.
- [x] GREEN: strict low-impact consent parser and request cap.
- [x] VERIFY: run unittest suite.

### Task 3 — Public checks and contained active probes
**Files:** `auditor/checks.py`, `auditor/probes.py`, `tests/test_checks.py`, `tests/test_probes.py`.
**Interfaces:** `check_headers`, `fingerprints`, `probe_*`.
- [x] RED: findings, no literal sensitive values, strict scopes tests.
- [x] GREEN: header/cookie/TLS checks and non-destructive suspected SQLi/XSS/auth checks only with authorized test paths.
- [x] VERIFY: run unittest suite.

### Task 4 — CLI, report policy and GitHub Actions
**Files:** `auditor/__main__.py`, `auditor/runner.py`, `.github/workflows/security-audit.yml`, `README.md`, tests.
**Interfaces:** `challenge`, `scan`, `public_report`.
- [x] RED: test public-mode downgrade, sealed data, challenge generation.
- [x] GREEN: CLI orchestration and public-only summary artifact; manual workflow.
- [x] VERIFY: run local unittest suite.
- [ ] VERIFY: GitHub Actions CI and a manual real-domain scan.

### Task 5 — Private skill and authorization/report templates
**Files:** `../skill/SKILL.md`, `../skill/references/*.md`, `../skill/templates/*.json`, `../skill/README.md`.
- [x] GREEN: skill contract, authorization instructions, non-claims, OWASP mapping and reporting standards.
- [x] VERIFY: validate references, examples and frontmatter with local tests.
- [ ] VERIFY: agent behavior-pressure tests in a real connected ChatGPT environment.
