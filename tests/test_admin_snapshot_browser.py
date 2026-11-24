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

    def test_translated_wordpress_login_fixture(self):
        html = ('<title>Đăng nhập ‹ ESC.VN — WordPress</title>'
                '<h1 class="wp-login-logo">Powered by WordPress</h1>'
                '<form id="loginform" name="loginform" method="post">'
                '<label>Tên người dùng hoặc địa chỉ email</label>'
                '<input id="user_login" name="log" type="text">'
                '<label>Mật khẩu</label>'
                '<input id="user_pass" name="pwd" type="password">'
                '<input id="wp-submit" type="submit" value="Đăng nhập"></form>')
        r=self.inspect(html)
        self.assertEqual(r['status'],'admin_login_candidate')
        self.assertTrue(r['evidence']['wordpress_login_form'])

    def test_generic_customer_login_is_not_admin(self):
        html = ('<title>Customer Login</title><form id="loginform">'
                '<input name="email" type="email"><input name="pwd" type="password"></form>')
        r=self.inspect(html)
        self.assertEqual(r['status'],'ordinary_login')

    def test_hidden_password_not_counted(self):
        r=self.inspect('<title>Admin Login</title><form><input type=password hidden></form>')
        self.assertEqual(r['status'],'unknown')

    def test_javascript_cannot_modify_page(self):
        r=self.inspect('<title>Customer Login</title><form><input type=password></form><script>document.title="Admin Login"</script>')
        self.assertEqual(r['status'],'ordinary_login')


if __name__=='__main__':
    unittest.main()
