"""Single-host HTTPS transport: validated DNS, pinned TCP IP, SNI and no redirects."""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 256 * 1024
TIMEOUT_SECONDS = 7


class AuditError(Exception):
    """Abort safely when the target or its response violates scan boundaries."""


def _ascii_host(name: str) -> str:
    try:
        ascii_name = name.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError) as exc:
        raise AuditError('Invalid domain encoding') from exc
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        pass
    else:
        raise AuditError('IP literals are not allowed as domains')
    if len(ascii_name) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', ascii_name):
        raise AuditError('Only public DNS domain names are accepted')
    return ascii_name


def validate_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise AuditError('Domain required')
    raw = target.strip()
    if '://' not in raw:
        raw = 'https://' + raw
    parts = urlsplit(raw)
    if parts.scheme != 'https' or parts.username is not None or parts.password is not None:
        raise AuditError('Target must be an HTTPS hostname without userinfo')
    try:
        port = parts.port
    except ValueError as exc:
        raise AuditError('Invalid port') from exc
    if port not in (None, 443) or parts.path not in ('', '/') or parts.query or parts.fragment:
        raise AuditError('Target must not include port, path, query or fragment')
    if not parts.hostname:
        raise AuditError('Host missing')
    return _ascii_host(parts.hostname)


def validate_https_url(url: str, expected_host: str) -> str:
    """Return safe request path (including query) for a URL on the exact host."""
    if not isinstance(url, str) or any(c in url for c in '\r\n\t'):
        raise AuditError('Malformed URL')
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise AuditError('Invalid port') from exc
    if parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None or port not in (None, 443):
        raise AuditError('Only HTTPS on port 443 without userinfo is allowed')
    if _ascii_host(parts.hostname) != expected_host or parts.fragment:
        raise AuditError('URL outside authorized exact host')
    path = parts.path or '/'
    if not path.startswith('//') and path.startswith('/') and '\\' not in path and any(ord(x)<32 for x in path) is False:
        return path + ('?' + parts.query if parts.query else '')
    raise AuditError('Unsafe request path')


def resolve_global_ips(hostname: str) -> list[str]:
    try:
        info = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise AuditError('DNS lookup failed') from exc
    addresses = sorted({x[4][0] for x in info})
    if not addresses:
        raise AuditError('DNS returned no addresses')
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise AuditError('Invalid DNS response') from exc
        if not ip.is_global:
            raise AuditError('DNS includes a private, reserved or otherwise non-global address')
    return addresses


@dataclass(frozen=True)
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, key: str) -> str | None:
        for name, val in self.headers:
            if name.lower() == key.lower():
                return val
        return None


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str):
        super().__init__(hostname, port=443, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class PinnedHTTP:
    def __init__(self, host: str, ips: list[str]):
        self.host = _ascii_host(host)
        if not ips or not all(ipaddress.ip_address(x).is_global for x in ips):
            raise AuditError('No verified public IP address')
        self.ips = ips

    def _get_path(self, path: str) -> Response:
        conn = _PinnedHTTPS(self.host, self.ips[0])
        try:
            conn.request('GET', path, headers={
                'Host': self.host, 'User-Agent': 'NVN-Security-Auditor/1.0 (+low-impact)',
                'Accept': 'text/html,application/json;q=0.8,*/*;q=0.5',
                'Connection': 'close',
            })
            response = conn.getresponse()
            # Read 1 byte over the limit to reliably reject oversize bodies.
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise AuditError('Response size exceeded limit')
            return Response(response.status, response.getheaders(), body)
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            raise AuditError('TLS or HTTP request failed') from exc
        finally:
            conn.close()

    def get_unfollowed(self, url: str) -> Response:
        """Return any HTTP status without following redirects, using pinned TLS and DNS guard."""
        path = validate_https_url(url, self.host)
        # DNS rebinding guard: re-check on every call, pin TCP to approved address.
        fresh = resolve_global_ips(self.host)
        if not set(fresh).intersection(self.ips):
            raise AuditError('DNS changed since target verification')
        return self._get_path(path)

    def get(self, url: str) -> Response:
        answer = self.get_unfollowed(url)
        if 300 <= answer.status < 400:
            raise AuditError('Redirect is not followed; target boundary preserved')
        return answer


def tls_days_until_expiry(host: str, ips: list[str], now_ts: float) -> float:
    """Check leaf certificate validity via pinned TLS, never bypassing verification."""
    if not ips or not all(ipaddress.ip_address(x).is_global for x in ips):
        raise AuditError('Untrusted destination address')
    conn=_PinnedHTTPS(_ascii_host(host),ips[0])
    try:
        conn.connect()
        cert=conn.sock.getpeercert() if conn.sock else None
        if not cert or 'notAfter' not in cert:
            raise AuditError('TLS peer did not return certificate expiry')
        return (ssl.cert_time_to_seconds(cert['notAfter'])-now_ts)/86400.0
    except (OSError,ssl.SSLError,ValueError) as exc:
        raise AuditError('Unable to validate TLS certificate') from exc
    finally:
        conn.close()
