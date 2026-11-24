"""Offline browser review of an operator-supplied HTML snapshot.

No navigation to a website, hostname generation, authentication, or network access.
Only categorical evidence is returned. A snapshot cannot establish live reachability.
"""
from pathlib import Path
import re
import unicodedata

MAX_BYTES = 256 * 1024


class SnapshotError(Exception):
    pass


def normalize(value):
    return ' '.join(unicodedata.normalize('NFC', value).casefold().split())


def classify_interface(title, headings, password_visible, form_visible):
    labels = [normalize(x) for x in [title, *headings]]
    error = any(re.search(r'\b(404|403|not found|access denied|domain for sale|default web site|bad gateway)\b', x) for x in labels)
    admin = any(re.search(r'\b(admin login|admin sign in|administrator login|administration portal|admin panel|admin dashboard|management console|đăng nhập quản trị|trang quản trị|cổng quản trị)\b', x) for x in labels)
    customer = any(re.search(r'\b(customer login|customer account|member login|đăng nhập khách hàng|tài khoản khách hàng)\b', x) for x in labels)
    if error:
        status = 'not_verified'
    elif admin and password_visible and form_visible and not customer:
        status = 'admin_login_candidate'
    elif customer and not admin:
        status = 'ordinary_login'
    else:
        status = 'unknown'
    return {'status': status, 'severity': 'low' if status == 'admin_login_candidate' else None,
            'evidence': {'admin_label': admin, 'visible_password_input': bool(password_visible),
                         'visible_form': bool(form_visible), 'customer_label': customer,
                         'error_page_label': error},
            'scope': 'operator_supplied_offline_snapshot', 'live_reachability': 'not_tested',
            'authentication': 'not_tested',
            'note': 'Visual indicators only; no live exposure or authentication bypass established'}


def review_snapshot(path):
    try:
        with Path(path).open('rb') as f:
            raw = f.read(MAX_BYTES + 1)
        if not raw or len(raw) > MAX_BYTES:
            raise SnapshotError('Invalid snapshot size')
        html = raw.decode('utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise SnapshotError('Unable to read UTF-8 HTML snapshot') from exc
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SnapshotError('Optional Playwright dependency is not installed') from exc
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--disable-background-networking', '--disable-sync', '--no-first-run'])
            try:
                context = browser.new_context(offline=True, java_script_enabled=False,
                                              service_workers='block', accept_downloads=False)
                context.route('**/*', lambda route: route.abort())
                page = context.new_page()
                # Set content in about:blank. Never navigate to a supplied URL.
                page.set_content(html, wait_until='domcontentloaded', timeout=5000)
                title = page.title()
                headings = page.locator('h1:visible, h2:visible').all_text_contents()[:30]
                password = page.locator('input[type=password]:visible').count() > 0
                form = page.locator('form:visible').count() > 0
                return classify_interface(title, headings, password, form)
            finally:
                browser.close()
    except Exception as exc:
        # Do not echo HTML, URLs, form values or browser errors.
        raise SnapshotError('Offline browser review could not be completed') from exc
