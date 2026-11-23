"""Strict validation of operator-generated challenge and site-hosted consent."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import json
import re
from urllib.parse import urlsplit

from auditor.network import AuditError, validate_https_url


class AuthorizationError(Exception):
    pass


TESTS = frozenset({'sql_injection_low_impact', 'xss_low_impact', 'authentication_basic'})


@dataclass(frozen=True)
class AllowedPath:
    path: str
    tests: frozenset[str]
    expected_protected_marker: str | None = None


@dataclass(frozen=True)
class Authorization:
    domain: str
    authorization_id: str
    allowed_tests: frozenset[str]
    test_paths: tuple[AllowedPath, ...]
    max_requests: int
    expires_at: datetime


def _when(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorizationError('Consent date must be an ISO 8601 string')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise AuthorizationError('Invalid consent date') from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise AuthorizationError('Consent date must have a timezone')
    return result.astimezone(timezone.utc)


def validate_authorization(value: dict, hostname: str, issued_challenge: str,
                           now: datetime | None = None) -> Authorization:
    if now is None:
        now = datetime.now(timezone.utc)
    if not isinstance(value, dict) or value.get('version') != 1:
        raise AuthorizationError('Unsupported authorization file')
    expected_keys = {'version', 'domain', 'authorization_id', 'authorized_auditor', 'authorized_by',
                     'consent_confirmed', 'not_before', 'expires_at', 'allowed_tests', 'test_paths', 'max_requests'}
    if set(value) != expected_keys:
        raise AuthorizationError('Consent fields must exactly match the supported schema')
    if value.get('domain') != hostname:
        raise AuthorizationError('Consent hostname does not match exact target')
    if not isinstance(issued_challenge, str) or len(issued_challenge) < 24 or not re.fullmatch(r'[A-Za-z0-9_-]{24,128}',issued_challenge):
        raise AuthorizationError('Auditor challenge is missing or weak')
    if value.get('authorization_id') != issued_challenge:
        raise AuthorizationError('Authorization challenge mismatch')
    if value.get('consent_confirmed') is not True:
        raise AuthorizationError('Explicit consent absent')
    if value.get('authorized_auditor') != 'Web Security Auditor NVN':
        raise AuthorizationError('Authorization does not designate this auditor')
    for label in ('authorized_auditor', 'authorized_by'):
        if not isinstance(value.get(label), str) or not 3 <= len(value[label].strip()) <= 160:
            raise AuthorizationError(f'Missing {label}')
    start, end = _when(value.get('not_before')), _when(value.get('expires_at'))
    if not start <= now <= end or end - start > timedelta(days=7):
        raise AuthorizationError('Consent not current or too broad')
    allowed = value.get('allowed_tests')
    if (not isinstance(allowed, list) or not allowed or
        not all(isinstance(x, str) for x in allowed) or
        len(allowed) != len(set(allowed)) or not set(allowed).issubset(TESTS)):
        raise AuthorizationError('Unrecognized or duplicated tests')
    count = value.get('max_requests')
    if type(count) is not int or not 1 <= count <= 30:
        raise AuthorizationError('Request budget must be within 1..30')
    paths = value.get('test_paths')
    if not isinstance(paths, list) or not 1 <= len(paths) <= 15:
        raise AuthorizationError('1..15 explicit test paths required')
    approved = []
    for path_spec in paths:
        if (not isinstance(path_spec, dict) or not set(path_spec).issubset({'path','tests','expected_protected_marker'}) or
            not isinstance(path_spec.get('path'), str)):
            raise AuthorizationError('Invalid test path')
        path = path_spec['path']
        if len(path) > 500 or not path.startswith('/') or path.startswith('//') or '%' in path or '\\' in path or '#' in path or any(ord(c)<32 for c in path):
            raise AuthorizationError('Unsafe relative URL in test scope')
        try:
            validate_https_url('https://' + hostname + path, hostname)
        except AuditError as exc:
            raise AuthorizationError('Out-of-scope test URL') from exc
        subset = path_spec.get('tests')
        if (not isinstance(subset, list) or not subset or
            not all(isinstance(x, str) for x in subset) or
            not set(subset).issubset(allowed) or len(subset) != len(set(subset))):
            raise AuthorizationError('Test path enables unapproved test')
        marker = path_spec.get('expected_protected_marker')
        if 'authentication_basic' in subset and (not isinstance(marker, str) or not 8 <= len(marker) <= 100):
            raise AuthorizationError('Guest access check requires a site-owner supplied protected marker')
        if marker is not None and (not isinstance(marker,str) or len(marker)>100):
            raise AuthorizationError('Unsafe protected marker')
        if ('sql_injection_low_impact' in subset or 'xss_low_impact' in subset) and not urlsplit('https://' + hostname + path).query:
            raise AuthorizationError('Injection probes require an explicitly scoped example GET query')
        approved.append(AllowedPath(path, frozenset(subset), marker))
    return Authorization(hostname, issued_challenge, frozenset(allowed), tuple(approved), count, end)


def decode_authorization(body: bytes) -> dict:
    if len(body) > 16 * 1024:
        raise AuthorizationError('Authorization file too large')
    try:
        result = json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthorizationError('Invalid UTF-8 JSON authorization') from exc
    if not isinstance(result,dict):
        raise AuthorizationError('Authorization must be a JSON object')
    return result
