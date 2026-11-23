import unittest
from datetime import datetime, timezone, timedelta
from auditor.authorization import validate_authorization, AuthorizationError
from auditor.budget import Budget, BudgetError


NOW=datetime(2026,11,23,10,0,0,tzinfo=timezone.utc)
TOKEN='C' * 32


def consent(**overrides):
    base={
        'version': 1, 'domain': 'example.com', 'authorization_id': TOKEN,
        'authorized_auditor': 'Web Security Auditor NVN', 'authorized_by': 'Example Website Owner',
        'consent_confirmed': True, 'not_before':'2026-11-23T09:00:00Z',
        'expires_at':'2026-11-24T09:00:00Z',
        'allowed_tests':['sql_injection_low_impact','xss_low_impact','authentication_basic'],
        'test_paths':[{'path':'/search?q=test','tests':['sql_injection_low_impact','xss_low_impact']},
                      {'path':'/private','tests':['authentication_basic'], 'expected_protected_marker':'PrivateAccount'}],
        'max_requests':12,
    }
    base.update(overrides)
    return base


class TestAuthorization(unittest.TestCase):
    def test_valid_consent_and_explicit_urls(self):
        x=validate_authorization(consent(), 'example.com', TOKEN, NOW)
        self.assertEqual(x.max_requests,12)
        self.assertEqual(len(x.test_paths),2)

    def test_expired_not_yet_valid_or_missing_agreement_denied(self):
        bad=[consent(expires_at='2026-11-22T00:00:00Z'),consent(not_before='2026-11-24T00:00:00Z'),
             consent(consent_confirmed=False),consent(authorization_id='wrong'),consent(domain='other.com'),
             consent(allowed_tests=['rce']),consent(test_paths=[{'path':'https://evil.com','tests':['xss_low_impact']}]),
             consent(test_paths=[{'path':'/search?q=x','tests':['unknown']}]),consent(max_requests=999)]
        for x in bad:
            with self.subTest(x=x),self.assertRaises(AuthorizationError):
                validate_authorization(x,'example.com',TOKEN,NOW)

    def test_malformed_arrays_fail_closed_not_type_error(self):
        for payload in [consent(allowed_tests=[{}]), consent(test_paths=[{'path':'/search?q=x','tests':[{}]}]),
                        consent(allowed_tests='sql_injection_low_impact'),
                        consent(test_paths=[{'path':'/search?q=x','tests':['xss_low_impact',{}]}])]:
            with self.subTest(payload=payload), self.assertRaises(AuthorizationError):
                validate_authorization(payload, 'example.com', TOKEN, NOW)

    def test_unknown_extra_fields_rejected(self):
        with self.assertRaises(AuthorizationError):
            validate_authorization(consent(execute_shell='rm -rf'), 'example.com', TOKEN, NOW)

    def test_other_auditor_identity_is_not_authorized(self):
        with self.assertRaises(AuthorizationError):
            validate_authorization(consent(authorized_auditor='Unknown Scanner'), 'example.com', TOKEN, NOW)

    def test_no_star_subdomain_scopes_or_userinfo(self):
        for path in ['//evil.com/', '/admin#frag', '/a\\b', '/%0afoo']:
            with self.subTest(path=path),self.assertRaises(AuthorizationError):
                validate_authorization(consent(test_paths=[{'path':path,'tests':['xss_low_impact']}]),'example.com',TOKEN,NOW)

    def test_cannot_run_more_than_budget(self):
        b=Budget(max_requests=2,min_interval_seconds=0, now=lambda:0, sleep=lambda _:None)
        b.before();b.before()
        with self.assertRaises(BudgetError): b.before()

    def test_throttle_429_and_server_error(self):
        b=Budget(max_requests=5,min_interval_seconds=0, now=lambda:0, sleep=lambda _:None)
        b.before()
        with self.assertRaises(BudgetError): b.after(429)
        with self.assertRaises(BudgetError): b.before()
        c=Budget(max_requests=5,min_interval_seconds=0, now=lambda:0, sleep=lambda _:None)
        c.before()
        with self.assertRaises(BudgetError): c.after(503)
        with self.assertRaises(BudgetError): c.before()

if __name__=='__main__':unittest.main()
