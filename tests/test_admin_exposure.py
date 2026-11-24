import unittest
from auditor.admin_exposure import inspect_admin_exposure, CODE
from auditor.network import Response


class TestAdminExposure(unittest.TestCase):
    def inspect(self, html, content_type='text/html', status=200, extra=()):
        return inspect_admin_exposure(Response(status, [('Content-Type', content_type), *extra], html.encode('utf-8')), 'example.com')

    def test_advertised_admin_link_is_low_and_url_redacted(self):
        status, findings = self.inspect('<a href="/private-owner-route?secret=REDACT">Admin login</a>')
        self.assertEqual(status['status'], 'warning')
        self.assertEqual(findings[0]['code'], CODE)
        self.assertEqual(findings[0]['severity'], 'low')
        self.assertNotIn('private-owner-route', repr((status, findings)))
        self.assertNotIn('REDACT', repr((status, findings)))

    def test_vietnamese_label_and_nested_markup(self):
        status, findings = self.inspect('<a href="/owner"><span>Đăng nhập</span> quản trị</a>')
        self.assertEqual(status['status'], 'warning')
        self.assertEqual(len(findings), 1)

    def test_no_route_guessing_or_generic_login(self):
        status, findings = self.inspect('<a href="/admin">Products</a><a href="/login">Login</a>')
        self.assertEqual(status['status'], 'not_found')
        self.assertEqual(findings, [])

    def test_external_and_non_https_links_ignored(self):
        status, findings = self.inspect('<a href="https://other.example/owner">Admin login</a><a href="javascript:void(0)">Admin portal</a>')
        self.assertEqual(status['status'], 'not_found')
        self.assertEqual(findings, [])

    def test_script_template_and_comments_are_not_links(self):
        status, findings = self.inspect('<!-- <a href="/x">Admin login</a> --><template><a href="/y">Admin login</a></template><script>const x="<a href=\'/z\'>Admin login</a>"</script>')
        self.assertEqual(status['status'], 'not_found')
        self.assertEqual(findings, [])

    def test_unsuitable_response_not_tested(self):
        for html, ctype, code, extra in [('', 'text/html', 200, ()), ('{}', 'application/json', 200, ()), ('blocked', 'text/html', 403, ()), ('abc', 'text/html', 200, (('Content-Encoding','gzip'),)), ('<base href="https://other.example/"><a href="/x">Admin login</a>', 'text/html', 200, ())]:
            with self.subTest(html=html):
                status, findings = self.inspect(html, ctype, code, extra)
                self.assertEqual(status['status'], 'not_tested')
                self.assertEqual(findings, [])

    def test_explicit_descendant_link_is_classified_without_disclosing_host(self):
        status, findings = self.inspect('<a href="https://management.example.com/private?token=REDACT">Admin portal</a>')
        self.assertEqual(status['status'], 'warning')
        self.assertEqual(status['evidence_types'], ['descendant_host_advertised_link'])
        self.assertEqual(status['destination_verification'], 'not_tested')
        self.assertEqual(status['hostname_discovery'], 'not_tested')
        self.assertNotIn('management.example.com', repr((status, findings)))
        self.assertNotIn('REDACT', repr((status, findings)))

    def test_accessible_labels_are_considered(self):
        status, findings = self.inspect('<a href="/owner" aria-label="Admin portal"><svg></svg></a>')
        self.assertEqual(status['status'], 'warning')

    def test_hostname_suffix_confusion_not_classified(self):
        status, findings = self.inspect('<a href="https://example.com.other.example/">Admin login</a><a href="https://notexample.com/">Admin portal</a>')
        self.assertEqual(status['status'], 'not_found')
        self.assertEqual(findings, [])

    def test_public_descendant_count_is_capped_and_deduplicated(self):
        html = ''.join('<a href="https://published%d.example.com/">Admin portal</a>' % i for i in range(12))
        status, findings = self.inspect(html)
        summary = status['advertised_subdomains']
        self.assertEqual(summary['observed_count_capped'], 10)
        self.assertTrue(summary['more_than_limit'])
        self.assertNotIn('published0.example.com', repr((status, findings)))
        html = '<a href="https://published.example.com/">Admin portal</a>' * 12
        summary = self.inspect(html)[0]['advertised_subdomains']
        self.assertEqual(summary['observed_count_capped'], 1)
        self.assertFalse(summary['more_than_limit'])

    def test_public_count_unknown_for_unusable_html(self):
        summary = self.inspect('{}', 'application/json')[0]['advertised_subdomains']
        self.assertIsNone(summary['observed_count_capped'])
        self.assertEqual(summary['status'], 'not_tested')

    def test_duplicate_observations_are_single_finding(self):
        status, findings = self.inspect('<a href="/x">Admin login</a><a href="/y">Admin panel</a>')
        self.assertEqual(len(findings), 1)

if __name__ == '__main__':
    unittest.main()
