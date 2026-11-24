import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from auditor.admin_snapshot import classify_interface, review_snapshot, SnapshotError
from auditor.__main__ import main


class TestAdminSnapshot(unittest.TestCase):
    def test_admin_candidate_never_claims_live_reachability(self):
        r=classify_interface('Admin Login', [], True, True)
        self.assertEqual(r['status'], 'admin_login_candidate')
        self.assertEqual(r['severity'], 'low')
        self.assertEqual(r['live_reachability'], 'not_tested')
        self.assertEqual(r['authentication'], 'not_tested')

    def test_customer_login(self):
        r=classify_interface('Customer Login', [], True, True)
        self.assertEqual(r['status'], 'ordinary_login')
        self.assertIsNone(r['severity'])

    def test_error_takes_precedence(self):
        r=classify_interface('404 Not Found', ['Admin Login'], True, True)
        self.assertEqual(r['status'], 'not_verified')

    def test_label_without_form_not_enough(self):
        self.assertEqual(classify_interface('Admin Login', [], False, False)['status'], 'unknown')

    def test_ambiguous_label(self):
        self.assertEqual(classify_interface('Admin Login', ['Customer Login'], True, True)['status'], 'unknown')

    def test_vietnamese_heading(self):
        self.assertEqual(classify_interface('Site', ['Đăng nhập quản trị'], True, True)['status'], 'admin_login_candidate')

    def test_translated_wordpress_login_with_distinct_form(self):
        r=classify_interface('Đăng nhập ‹ ESC.VN — WordPress', ['Powered by WordPress'],
                             True, True, wordpress_login_form=True)
        self.assertEqual(r['status'],'admin_login_candidate')
        self.assertEqual(r['severity'],'low')
        self.assertTrue(r['evidence']['wordpress_login_form'])

    def test_wordpress_title_without_form_is_not_admin(self):
        r=classify_interface('My WordPress Website', [], False, False)
        self.assertEqual(r['status'],'unknown')

    def test_reject_large_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x.html'
            path.write_bytes(b'a' * (256*1024+1))
            with self.assertRaises(SnapshotError):
                review_snapshot(path)

    def test_cli_writes_only_private_classification(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'x.html'
            out=Path(d)/'out.json'
            src.write_text('<html></html>')
            with patch('auditor.__main__.review_snapshot',return_value={'status':'unknown'}) as review:
                self.assertEqual(main(['review-admin-snapshot','--input',str(src),'--out',str(out)]),0)
                review.assert_called_once_with(str(src))
            self.assertEqual(main(['review-admin-snapshot','--input',str(src),'--out',str(src)]),2)


if __name__=='__main__':
    unittest.main()
