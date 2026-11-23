"""Minimal authorized GET-only heuristics. Never assert exploitation success."""
from __future__ import annotations
import secrets
from urllib.parse import urlsplit, parse_qsl, urlencode
from auditor.authorization import AllowedPath
from auditor.budget import Budget
from auditor.checks import issue

_SQL_ERRORS=(b'you have an error in your sql syntax',b'sqlstate[',b'unclosed quotation mark',
             b'postgresql.query',b'sqlite3.operationalerror',b'ora-009',b'odbc sql server driver')


def _get(client, url: str, budget: Budget):
    budget.before()
    response=client.get(url)
    budget.after(response.status)
    return response


def _inject_param(base: str, path: str, value: str) -> str:
    parts=urlsplit('https://' + base + path)
    params=parse_qsl(parts.query,keep_blank_values=True)
    if not params:
        raise ValueError('No query parameters in consented GET endpoint')
    key, old=params[0]
    params[0]=(key, old + value)
    # All query strings are percent-encoded; do not allow path or host changes.
    return 'https://' + base + parts.path + '?' + urlencode(params)


def probe_sql(client, origin: str, approved: AllowedPath, budget: Budget) -> dict[str,str] | None:
    if 'sql_injection_low_impact' not in approved.tests:
        raise ValueError('Unapproved SQLi probe')
    host = urlsplit(origin).hostname
    baseline=_get(client, origin+approved.path, budget).body.lower()
    suspect=_get(client, _inject_param(host,approved.path,"'"),budget).body.lower()
    if any(marker in suspect and marker not in baseline for marker in _SQL_ERRORS):
        return issue('SQL_ERROR_AFTER_QUOTE','SQL error following a quote input','medium','suspected',
                     'One authorized GET input caused a recognizable database error absent from baseline; exploitation not verified')
    return None


def probe_xss(client, origin: str, approved: AllowedPath, budget: Budget) -> dict[str,str] | None:
    if 'xss_low_impact' not in approved.tests:
        raise ValueError('Unapproved XSS probe')
    host=urlsplit(origin).hostname
    marker='audit-marker-'+secrets.token_hex(5)
    canary='<'+marker+'>'  # inert custom element, NO JavaScript or event handlers
    response=_get(client,_inject_param(host,approved.path,canary),budget)
    if canary.encode() in response.body:
        return issue('UNESCAPED_HTML_REFLECTION','HTML reflection not escaped','low','suspected',
                     'Inert markup was reflected unescaped; JavaScript execution and exploitability were not tested')
    return None


def probe_guest_auth(client, origin: str, approved: AllowedPath, budget: Budget) -> dict[str,str] | None:
    if 'authentication_basic' not in approved.tests or not approved.expected_protected_marker:
        raise ValueError('Unapproved guest access probe')
    response=_get(client,origin+approved.path,budget)
    if response.status == 200 and approved.expected_protected_marker.encode() in response.body:
        return issue('GUEST_PROTECTED_MARKER_VISIBLE','Protected content marker visible to guest','medium','suspected',
                     'Owner-supplied protected marker appeared in anonymous GET response; access control requires manual review')
    return None
