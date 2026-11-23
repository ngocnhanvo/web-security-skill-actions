import unittest
from auditor.network import Response
from auditor.authorization import AllowedPath, Authorization
from auditor.budget import Budget
from auditor.probes import probe_sql, probe_xss, probe_guest_auth
from datetime import datetime,timezone

class FakeClient:
    def __init__(self, fn): self.fn=fn; self.urls=[]
    def get(self,url):
        self.urls.append(url)
        return self.fn(url)

def budget(): return Budget(10,0,now=lambda:0,sleep=lambda _:None)

class TestProbes(unittest.TestCase):
    def test_sql_error_probe_is_suspected_only(self):
        c=FakeClient(lambda u:Response(200,[],b'You have an error in your SQL syntax') if '%27' in u else Response(200,[],b'ok'))
        issue=probe_sql(c,'https://example.com',AllowedPath('/search?q=test',frozenset({'sql_injection_low_impact'})),budget())
        self.assertEqual(issue['confidence'],'suspected')
        self.assertEqual(len(c.urls),2)
        self.assertNotIn('search?q=',str(issue))

    def test_xss_canary_never_executes_javascript(self):
        c=FakeClient(lambda u:Response(200,[],b'<html>&lt;audit-marker&gt;</html>'))
        self.assertIsNone(probe_xss(c,'https://example.com', AllowedPath('/search?q=test',frozenset({'xss_low_impact'})), budget()))
        self.assertTrue(all('script' not in x and 'onerror' not in x for x in c.urls))

    def test_guest_access_marker_is_suspected_not_confirmed(self):
        c=FakeClient(lambda u:Response(200,[],b'PrivateAccount details'))
        issue=probe_guest_auth(c,'https://example.com',AllowedPath('/private',frozenset({'authentication_basic'}),'PrivateAccount'),budget())
        self.assertEqual(issue['confidence'],'suspected')

if __name__=='__main__':unittest.main()
