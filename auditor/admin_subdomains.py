"""Bounded public check for ten common admin-subdomain naming examples.

GET only on exact, publicly resolvable child hosts. TLS is checked and IP pinned.
At most two safe same-host redirects, including WordPress wp-login redirect_to.
No cross-host hops, form submissions, login attempts or brute force.
"""
from __future__ import annotations
from urllib.parse import parse_qsl, urljoin, urlsplit

from auditor.admin_snapshot import SnapshotError, review_html_bytes
from auditor.budget import Budget, BudgetError
from auditor.network import AuditError, PinnedHTTP, resolve_global_ips, validate_target, validate_https_url

PREFIXES = ('admin', 'quantri', 'administrator', 'cms', 'backend',
            'panel', 'manage', 'dashboard', 'portal', 'cpanel')
MAX_REDIRECTS = 2
assert len(PREFIXES) == 10 and len(set(PREFIXES)) == 10


def _transport_status(error):
    return {
        'TLS certificate verification failed': 'tls_certificate_error',
        'TLS handshake failed': 'tls_handshake_error',
        'Connection timed out': 'connection_timeout',
    }.get(str(error), 'transport_or_response_error')


def _same_host_target(url, location, hostname):
    """Accept only a bounded, exact-host HTTPS path, plus a safe WP login query.

    The WordPress redirect_to parameter must itself be HTTPS on the same host,
    pointing back to /wp-admin. Never transmit an arbitrary redirect query.
    """
    if (not isinstance(location, str) or not location or len(location) > 512
            or any(ord(c) < 32 for c in location) or '\\' in location):
        return None
    target = urljoin(url, location)
    if len(target) > 512:
        return None
    try:
        path = validate_https_url(target, hostname)
    except AuditError:
        return None
    if target == url or len(path) > 400:
        return None
    parts = urlsplit(target)
    if parts.query:
        if parts.path != '/wp-login.php':
            return None
        try:
            query = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=4)
        except ValueError:
            return None
        if not query or len(query) != len(set(k for k, _ in query)):
            return None
        if any(k not in ('redirect_to', 'reauth') for k, _ in query):
            return None
        for key, value in query:
            if key == 'reauth' and value not in ('0', '1'):
                return None
            if key == 'redirect_to':
                try:
                    nested_path = validate_https_url(value, hostname)
                except AuditError:
                    return None
                if nested_path.split('?', 1)[0] not in ('/wp-admin', '/wp-admin/') and not nested_path.startswith('/wp-admin/'):
                    return None
                if '?' in nested_path:
                    return None
    return target


def review_common_admin_hosts(domain: str, *, resolve=resolve_global_ips,
                              client_factory=PinnedHTTP, render=review_html_bytes,
                              budget: Budget | None = None) -> dict:
    """Report ten actual attempted/skipped hostnames, never disclose redirect URLs."""
    parent = validate_target(domain)
    budget = budget or Budget(30, 1.0)
    records = []
    stopped = False
    for prefix in PREFIXES:
        hostname = validate_target(prefix + '.' + parent)
        row = {'hostname': hostname, 'dns_status': 'not_tested',
               'https_status': 'not_tested', 'http_status': None, 'first_http_status': None,
               'request_count': 0, 'redirect_count': 0, 'redirect_scope': 'not_tested',
               'redirect_followed': False, 'browser_status': 'not_tested', 'risk': None}
        records.append(row)
        if stopped:
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
        for hop in range(MAX_REDIRECTS + 1):
            try:
                budget.before()
            except BudgetError:
                row['https_status'] = 'stopped_request_budget'
                stopped = True
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
                stopped = True
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
                if hop == MAX_REDIRECTS:
                    row['https_status'] = 'redirect_limit_reached'
                    break
                row['redirect_followed'] = True
                row['redirect_count'] += 1
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
            status = classification.get('status', 'unknown')
            if status not in {'admin_login_candidate', 'ordinary_login', 'unknown', 'not_verified'}:
                status = 'unknown'
            row['browser_status'] = status
            if status == 'admin_login_candidate':
                row['risk'] = 'low'
            break

    return {
        'status': 'halted' if stopped else 'completed',
        'scope': 'ten predefined direct-child HTTPS hostname candidates',
        'selection': 'common_name_examples_not_measured_prevalence',
        'http_method': 'GET', 'max_gets_per_candidate': MAX_REDIRECTS + 1,
        'followed_redirects': 'up_to_two_safe_same_hostname_including_wp_login',
        'authentication_attempts': 0,
        'browser_mode': 'offline_render_of_fetched_html_no_scripts_or_network',
        'candidate_count': len(PREFIXES),
        'dns_attempted_count': sum(r['dns_status'] not in ('not_tested', 'skipped_after_stop') for r in records),
        'http_attempted_count': sum(r['request_count'] for r in records),
        'admin_login_candidates': sum(r['browser_status'] == 'admin_login_candidate' for r in records),
        'results': records,
        'disclaimer': 'An admin login form is a Low exposure observation, NOT proof of authentication bypass. Unverified pages and request errors do not establish safety.',
    }
