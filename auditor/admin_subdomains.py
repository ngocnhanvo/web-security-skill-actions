"""Constrained direct-child public administration-hostname review.

Ten fixed naming candidates, up to two HTTPS GETs per public hostname (one same-host redirect).
No login attempts, arbitrary wordlist, crawling, cross-host redirects or requests.
"""
from __future__ import annotations
from urllib.parse import urljoin

from auditor.admin_snapshot import SnapshotError, review_html_bytes
from auditor.budget import Budget, BudgetError
from auditor.network import AuditError, PinnedHTTP, resolve_global_ips, validate_target, validate_https_url

# Names are practical examples, NOT a measured popularity ranking.
PREFIXES = (
    'admin', 'quantri', 'administrator', 'cms', 'backend',
    'panel', 'manage', 'dashboard', 'portal', 'cpanel',
)
assert len(PREFIXES) == 10 and len(set(PREFIXES)) == 10


def _transport_status(error):
    return {'TLS certificate verification failed':'tls_certificate_error',
            'TLS handshake failed':'tls_handshake_error',
            'Connection timed out':'connection_timeout'}.get(str(error), 'transport_or_response_error')


def _same_host_target(url, location, hostname):
    if not isinstance(location, str) or not location or any(ord(c)<32 for c in location) or '\\' in location:
        return None
    target=urljoin(url,location)
    try:
        path=validate_https_url(target,hostname)
    except AuditError:
        return None
    if target == url or '?' in path or len(path)>250:
        return None
    return target


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
               'https_status': 'not_tested', 'http_status': None, 'first_http_status': None,
               'request_count': 0, 'redirect_scope': 'not_tested',
               'redirect_followed': False, 'browser_status': 'not_tested', 'risk': None}
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
        client = client_factory(hostname, ips)
        url = 'https://' + hostname + '/'
        for hop in range(2):
            try:
                budget.before()
            except BudgetError:
                row['https_status'] = 'stopped_request_budget'
                stop = True
                break
            row['request_count'] += 1
            try:
                response = client.get_unfollowed(url)
            except AuditError as exc:
                row['https_status'] = _transport_status(exc)
                break
            row['http_status'] = response.status
            if row['first_http_status'] is None:
                row['first_http_status'] = response.status
            if response.status == 429 or response.status >= 500:
                row['https_status'] = 'rate_limited_or_server_error'
                stop = True
                try:
                    budget.after(response.status)
                except BudgetError:
                    pass
                break
            budget.after(response.status)
            if 300 <= response.status < 400:
                safe = _same_host_target(url, response.header('Location'), hostname)
                if not safe:
                    row['https_status'] = 'redirect_not_followed'
                    row['redirect_scope'] = 'different_host_or_unsafe'
                    break
                row['redirect_scope'] = 'same_hostname'
                if hop == 1:
                    row['https_status'] = 'redirect_limit_reached'
                    break
                row['redirect_followed'] = True
                url = safe
                continue
            row['https_status'] = 'response_received'
            if not 200 <= response.status < 300:
                break
            ctype = (response.header('Content-Type') or '').split(';', 1)[0].lower().strip()
            encoding = (response.header('Content-Encoding') or 'identity').strip().lower()
            if ctype != 'text/html' or encoding != 'identity':
                row['browser_status'] = 'not_tested_non_html'
                break
            try:
                classification = render(response.body)
            except SnapshotError:
                row['browser_status'] = 'not_verified_browser_error'
                break
            result = classification.get('status', 'unknown')
            if result not in {'admin_login_candidate', 'ordinary_login', 'unknown', 'not_verified'}:
                result = 'unknown'
            row['browser_status'] = result
            if result == 'admin_login_candidate':
                row['risk'] = 'low'
            break
    return {
        'status': 'halted' if stop else 'completed',
        'scope': 'ten predefined direct-child HTTPS hostname candidates',
        'selection': 'common_name_examples_not_measured_prevalence',
        'http_method': 'GET', 'max_gets_per_candidate': 2,
        'followed_redirects': 'at_most_one_safe_same_hostname',
        'authentication_attempts': 0,
        'browser_mode': 'offline_render_of_fetched_html_no_scripts_or_network',
        'candidate_count': len(PREFIXES),
        'dns_attempted_count': sum(r['dns_status'] not in ('not_tested', 'skipped_after_stop') for r in records),
        'http_attempted_count': sum(r['request_count'] for r in records),
        'admin_login_candidates': sum(r['browser_status'] == 'admin_login_candidate' for r in records),
        'results': records,
        'disclaimer': 'No admin login candidate is proof of authentication bypass. An unrecognized page or failed request is not a clean security pass.',
    }
