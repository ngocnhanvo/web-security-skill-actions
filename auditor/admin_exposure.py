"""Inspect already-fetched HTML for explicitly advertised administration links.

No network calls, route guessing, crawling, script execution, or link disclosure.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import re
import unicodedata

from auditor.checks import issue
from auditor.network import Response

CODE = 'ADMIN_INTERFACE_EXPOSURE'
LABELS = frozenset({
    'admin login', 'administrator login', 'administration',
    'admin portal', 'admin dashboard', 'admin panel',
    'đăng nhập quản trị', 'đăng nhập quản trị viên',
    'trang quản trị', 'cổng quản trị', 'quản trị hệ thống',
})


def _label(value: str) -> str:
    return ' '.join(unicodedata.normalize('NFC', value).casefold().split())


class _PublicLinks(HTMLParser):
    def __init__(self, hostname: str):
        super().__init__(convert_charrefs=True)
        self.origin = 'https://' + hostname + '/'
        self.hostname = hostname
        self.anchor = None
        self.parts = []
        self.suppressed = []
        self.found = False
        self.base_uncertain = False

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'template', 'noscript'}:
            self.suppressed.append(tag)
            return
        if self.suppressed:
            return
        values = dict(attrs)
        if tag == 'base' and 'href' in values:
            # Conservative: do not interpret links with a modified base URL.
            self.base_uncertain = True
        if tag == 'a':
            self.anchor = values.get('href')
            self.parts = []

    def handle_data(self, data):
        if self.anchor is not None and not self.suppressed:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag == self.suppressed[-1]:
                self.suppressed.pop()
            return
        if tag != 'a':
            return
        href, label = self.anchor, _label(' '.join(self.parts))
        self.anchor = None
        self.parts = []
        if not href or label not in LABELS:
            return
        if href.startswith('#') or any(ord(c) < 32 for c in href) or '\\' in href:
            return
        try:
            target = urlsplit(urljoin(self.origin, href))
            if (target.scheme == 'https' and target.hostname == self.hostname
                    and target.port in (None, 443) and target.username is None
                    and target.password is None):
                self.found = True
        except ValueError:
            return


def inspect_admin_exposure(response: Response, hostname: str) -> tuple[dict, list[dict]]:
    """Return scoped status and at most one low-severity finding without URLs."""
    status = {'status': 'not_tested', 'scope': 'homepage HTML only',
              'note': 'No suitable HTML response was inspected'}
    ctype = (response.header('Content-Type') or '').split(';', 1)[0].strip().lower()
    encoding = (response.header('Content-Encoding') or 'identity').strip().lower()
    if not 200 <= response.status < 300 or ctype != 'text/html' or encoding != 'identity' or not response.body.strip():
        return status, []
    try:
        # V1 supports UTF-8 HTML only; never imply coverage when decoding fails.
        html = response.body.decode('utf-8-sig')
        parser = _PublicLinks(hostname)
        parser.feed(html)
        parser.close()
    except (UnicodeError, ValueError, AssertionError):
        return status, []
    if parser.base_uncertain:
        status['note'] = 'Modified HTML base URL; link interpretation skipped'
        return status, []
    if not parser.found:
        status.update(status='pass', note='No explicit administration link label observed in the inspected HTML; undisclosed interfaces and access controls were not tested')
        return status, []
    status.update(status='warning', note='An explicit same-origin administration link label is advertised; destination was not visited or verified')
    return status, [issue(CODE, 'Publicly advertised administration link', 'low',
                          'confirmed-configuration',
                          'Explicit administration link label in public homepage HTML; destination and access controls not tested; URL omitted')]
