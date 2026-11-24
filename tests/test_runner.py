import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from auditor.network import Response, AuditError
from auditor.runner import audit, public_report
from auditor.budget import Budget
from test_authorization import consent, TOKEN, NOW


class FakeTransport:
    def __init__(self, host, ips, authorization=None):
        self.host=host;self.ips=ips;self.requests=[];self.authorization=authorization
    def get(self,url):
        self.requests.append(url)
        if url.endswith('/permission/custom.json'):
            return Response(200,[('Content-Type','application/json')],json.dumps(self.authorization or {}).encode())
        if '/search?' in url:
            if '%27' in url: return Response(200,[],b'You have an error in your SQL syntax')
            return Response(200,[],b'ok')
        if url.endswith('/private'):
            return Response(403,[],b'Forbidden')
        return Response(200,[('Content-Type','text/html'),('Set-Cookie','Secret=VERYSECRET; Path=/')],b'<html>ok</html>')

class TestRunner(unittest.TestCase):
    def _audit(self,transport,**kwargs):
        return audit('example.com', client=transport, resolve=lambda hostname:['8.8.8.8'], now=NOW,
                     budget=Budget(30,0,now=lambda:0,sleep=lambda _:None),**kwargs)

    def test_without_auth_only_gets_homepage(self):
        c=FakeTransport('example.com',['8.8.8.8'])
        r=self._audit(c)
        self.assertEqual(r['authorization']['status'],'public_only')
        self.assertEqual(c.requests,['https://example.com/'])
        self.assertEqual(r['active']['status'],'not_run')
        self.assertNotIn('VERYSECRET',json.dumps(r))

    def test_admin_link_check_never_fetches_advertised_destination(self):
        class Advertised(FakeTransport):
            def get(self, url):
                self.requests.append(url)
                return Response(200,[('Content-Type','text/html')],b'<a href="/owner-only?key=SECRET">Admin login</a>')
        c=Advertised('example.com',['8.8.8.8'])
        r=self._audit(c)
        self.assertEqual(c.requests,['https://example.com/'])
        self.assertEqual(r['public']['admin_interface_exposure']['status'],'warning')
        summary=json.dumps(public_report(r))
        self.assertIn('ADMIN_INTERFACE_EXPOSURE', summary)
        self.assertNotIn('owner-only', summary)
        self.assertNotIn('SECRET', summary)
        self.assertEqual(r['active']['status'],'not_run')

    def test_waf_block_page_not_scored_as_real_site(self):
        class Blocked(FakeTransport):
            def get(self, url):
                self.requests.append(url)
                return Response(403,[('Content-Type','text/html')],b'WAF blocked')
        c=Blocked('example.com',['8.8.8.8'])
        r=self._audit(c)
        self.assertEqual(r['scan_status'],'halted')
        self.assertEqual(r['public']['findings'],[])
        self.assertEqual(c.requests,['https://example.com/'])

    def test_invalid_auth_does_not_trigger_probe(self):
        c=FakeTransport('example.com',['8.8.8.8'],authorization=consent(authorization_id='wrong'))
        r=self._audit(c,authorization_url='https://example.com/permission/custom.json',challenge=TOKEN)
        self.assertEqual(r['authorization']['status'],'invalid')
        self.assertEqual(r['active']['status'],'not_run')
        self.assertFalse(any('/search?' in x or '/private' in x for x in c.requests))

    def test_authorized_scan_uses_only_explicit_paths_and_no_secret_in_public_report(self):
        c=FakeTransport('example.com',['8.8.8.8'],authorization=consent())
        r=self._audit(c,authorization_url='https://example.com/permission/custom.json',challenge=TOKEN)
        self.assertEqual(r['authorization']['status'],'authorized')
        self.assertEqual(r['active']['status'],'completed')
        self.assertTrue(any(x['confidence']=='suspected' for x in r['active']['findings']))
        public=public_report(r)
        self.assertNotIn('/search?',json.dumps(public))
        self.assertNotIn('VERYSECRET',json.dumps(public))
        self.assertNotIn('SQL_ERROR_AFTER_QUOTE',json.dumps(public))

    def test_foreign_authorization_path_never_requested(self):
        c=FakeTransport('example.com',['8.8.8.8'])
        r=self._audit(c, authorization_url='https://bad.example.com/permission.json',challenge=TOKEN)
        self.assertEqual(r['authorization']['status'],'invalid')
        self.assertEqual(c.requests,['https://example.com/'])

if __name__=='__main__':unittest.main()
