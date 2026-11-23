import unittest
from auditor.checks import check_headers, certificate_findings, fingerprints
from auditor.network import Response

class TestChecks(unittest.TestCase):
    def test_missing_header_config_is_actionable_but_not_certification(self):
        issues=check_headers(Response(200,[('Content-Type','text/html')],b'<html>Test</html>'))
        codes={x['code'] for x in issues}
        self.assertIn('HSTS_MISSING', codes)
        self.assertIn('CSP_MISSING', codes)
        self.assertIn('NOSNIFF_MISSING', codes)
        self.assertTrue(all(x['confidence']=='confirmed-configuration' for x in issues))

    def test_short_hsts_is_observed_as_weak(self):
        response=Response(200,[('Strict-Transport-Security','max-age=1'),('Content-Type','text/html')],b'')
        self.assertIn('HSTS_WEAK_MAX_AGE',{x['code'] for x in check_headers(response)})

    def test_cookie_values_are_not_echoed(self):
        issues=check_headers(Response(200,[('Strict-Transport-Security','max-age=31536000'),
        ('Content-Security-Policy',"default-src 'self'"),('X-Content-Type-Options','nosniff'),
        ('Set-Cookie','sessionId=SUPERSENSITIVE; Path=/')],b''))
        self.assertIn('COOKIE_SECURE_MISSING',{x['code'] for x in issues})
        self.assertNotIn('SUPERSENSITIVE',str(issues))
        self.assertNotIn('sessionId',str(issues))

    def test_headers_fingerprint_is_not_cve_assertion(self):
        seen=fingerprints(Response(200,[('Server','nginx/1.24.0'),('X-Powered-By','PHP/8.2.7')],b''))
        self.assertTrue(any(x['name']=='nginx' for x in seen))
        self.assertFalse(any('cve' in x for x in seen))

    def test_certificate_expiry_is_conditional(self):
        self.assertIn('TLS_CERT_EXPIRING',{x['code'] for x in certificate_findings(5)})
        self.assertNotIn('TLS_CERT_EXPIRING',{x['code'] for x in certificate_findings(90)})

if __name__=='__main__':unittest.main()
