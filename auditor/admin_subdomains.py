"""Constrained direct-child public administration-hostname review.

Ten fixed naming candidates, one HTTPS GET per resolvable public hostname.
No login attempts, arbitrary wordlist, crawling, redirect following, or cross-host requests.
"""
from __future__ import annotations

from auditor.admin_snapshot import SnapshotError, review_html_bytes
from auditor.budget import Budget, BudgetError
from auditor.network import AuditError, PinnedHTTP, resolve_global_ips, validate_target

# Names are practical examples, NOT a measured popularity ranking.
PREFIXES = (
    'admin', 'quantri', 'administrator', 'cms', 'backend',
    'panel', 'manage', 'dashboard', 'portal', 'cpanel',
)
assert len(PREFIXES) == 10 and len(set(PREFIXES)) == 10


def review_common_admin_hosts(domain: str, *, resolve=resolve_global_ips,
                              client_factory=PinnedHTTP, render=review_html_bytes,
                              budget: Budget | None = None) -> dict:
    """Report every checked or skipped candidate, including exact attempted hostnames."""
    parent = validate_target(domain)
    budget = budget or Budget(30, 1.0)
    records = []
    stop = False
    for prefix in PREFIXES:
        hostname = validate_target(prefix + '.' + parent)
        row = {'hostname': hostname, 'dns_status': 'not_tested',
               'https_status': 'not_tested', 'http_status': None,
               'browser_status': 'not_tested', 'risk': None}
        records.append(row)
        if stop:
            row['dns_status'] = 'skipped_after_stop'
            row['https_status'] = 'skipped_after_stop'
            continue
        try:
            ips = resolve(hostname)
        except AuditError as exc:
            row['dns_status'] = ('blocked_non_global' if 'non-global' in str(exc)
                                 else 'unresolved_or_error')
            continue
        if not ips:
            row['dns_status'] = 'unresolved_or_error'
            continue
        row['dns_status'] = 'resolved_global'
        try:
            budget.before()
        except BudgetError:
            row['https_status'] = 'stopped_request_budget'
            stop = True
            continue
        try:
            # Explicitly do NOT follow Location headers. IP is pinned and TLS verified.
            response = client_factory(hostname, ips).get_unfollowed('https://' + hostname + '/')
        except AuditError:
            row['https_status'] = 'tls_http_or_response_error'
            continue
        row['http_status'] = response.status
        if response.status == 429 or response.status >= 500:
            row['https_status'] = 'rate_limited_or_server_error'
            stop = True
            try:
                budget.after(response.status)
            except BudgetError:
                pass
            continue
        budget.after(response.status)
        if 300 <= response.status < 400:
            row['https_status'] = 'redirect_not_followed'
            continue
        row['https_status'] = 'response_received'
        if not 200 <= response.status < 300:
            continue
        ctype = (response.header('Content-Type') or '').split(';', 1)[0].lower().strip()
        encoding = (response.header('Content-Encoding') or 'identity').strip().lower()
        if ctype != 'text/html' or encoding != 'identity':
            row['browser_status'] = 'not_tested_non_html'
            continue
        try:
            classification = render(response.body)
        except SnapshotError:
            row['browser_status'] = 'not_verified_browser_error'
            continue
        result = classification.get('status', 'unknown')
        if result not in {'admin_login_candidate', 'ordinary_login', 'unknown', 'not_verified'}:
            result = 'unknown'
        row['browser_status'] = result
        if result == 'admin_login_candidate':
            row['risk'] = 'low'
    return {
        'status': 'halted' if stop else 'completed',
        'scope': 'ten predefined direct-child HTTPS hostname candidates',
        'selection': 'common_name_examples_not_measured_prevalence',
        'http_method': 'GET', 'followed_redirects': False,
        'authentication_attempts': 0,
        'browser_mode': 'offline_render_of_fetched_html_no_scripts_or_network',
        'candidate_count': len(PREFIXES),
        'dns_attempted_count': sum(r['dns_status'] not in ('not_tested', 'skipped_after_stop') for r in records),
        'http_attempted_count': sum(r['https_status'] not in ('not_tested', 'skipped_after_stop', 'stopped_request_budget')
                                    for r in records),
        'admin_login_candidates': sum(r['browser_status'] == 'admin_login_candidate' for r in records),
        'results': records,
        'disclaimer': 'No admin login candidate is proof of authentication bypass. An unrecognized page or failed request is not a clean security pass.',
    }
