"""Explicit opt-in integration tests, local fixtures only."""
import os
import tempfile
import unittest
from pathlib import Path
from auditor.admin_snapshot import review_snapshot


@unittest.skipUnless(os.environ.get('RUN_OFFLINE_BROWSER_TESTS') == '1', 'Optional offline Chromium integration')
class TestOfflineBrowser(unittest.TestCase):
    def inspect(self, html):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.html'
            p.write_text(html,encoding='utf-8')
            return review_snapshot(p)

    def test_visible_admin_login(self):
        r=self.inspect('<title>Admin Login</title><h1>Admin Login</h1><form><input type=password></form>')
        self.assertEqual(r['status'],'admin_login_candidate')

    def test_hidden_password_not_counted(self):
        r=self.inspect('<title>Admin Login</title><form><input type=password hidden></form>')
        self.assertEqual(r['status'],'unknown')

    def test_javascript_cannot_modify_page(self):
        r=self.inspect('<title>Customer Login</title><form><input type=password></form><script>document.title="Admin Login"</script>')
        self.assertEqual(r['status'],'ordinary_login')


if __name__=='__main__':
    unittest.main()
