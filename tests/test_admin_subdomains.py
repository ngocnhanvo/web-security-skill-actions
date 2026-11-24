import unittest
from auditor.admin_subdomains import PREFIXES, review_common_admin_hosts
from auditor.network import AuditError, Response
from auditor.budget import Budget


def budget():
    return Budget(30, 0, now=lambda:0,sleep=lambda _:None)


class Client:
    def __init__(self, host, ips, calls, response):
        self.host, self.calls, self.response = host, calls, response
    def get_unfollowed(self, url):
        self.calls.append(url)
        return self.response


class TestAdminSubdomainReview(unittest.TestCase):
    def test_exact_top_ten_fixed_and_unique(self):
        self.assertEqual(PREFIXES,('admin','quantri','administrator','cms','backend',
                                  'panel','manage','dashboard','portal','cpanel'))
        seen=[]
        def resolver(host):
            seen.append(host)
            raise AuditError('DNS lookup failed')
        result=review_common_admin_hosts('esc.vn', resolve=resolver,budget=budget())
        self.assertEqual(seen,[p+'.esc.vn' for p in PREFIXES])
        self.assertEqual([x['hostname'] for x in result['results']],seen)
        self.assertEqual(result['http_attempted_count'],0)
        self.assertEqual(result['status'],'completed')
        self.assertTrue(all(x['browser_status']=='not_tested' for x in result['results']))

    def test_nested_host_only_not_parent_duckdns(self):
        result=review_common_admin_hosts('taphoatuoiduynh.duckdns.org',
                                         resolve=lambda host: (_ for _ in ()).throw(AuditError('DNS lookup failed')),
                                         budget=budget())
        self.assertEqual(result['results'][0]['hostname'],'admin.taphoatuoiduynh.duckdns.org')
        self.assertEqual(result['results'][-1]['hostname'],'cpanel.taphoatuoiduynh.duckdns.org')

    def test_one_get_per_live_host_and_browser_gate(self):
        calls=[]
        response=Response(200,[('Content-Type','text/html')],b'<title>Admin Login</title>')
        factory=lambda host,ips:Client(host,ips,calls,response)
        result=review_common_admin_hosts('example.com',resolve=lambda host:['8.8.8.8'],
               client_factory=factory,render=lambda raw:{'status':'admin_login_candidate'},budget=budget())
        self.assertEqual(len(calls),10)
        self.assertEqual(len(set(calls)),10)
        self.assertEqual(result['admin_login_candidates'],10)
        self.assertEqual(result['results'][0]['risk'],'low')
        self.assertEqual(result['authentication_attempts'],0)
        self.assertTrue(all(x.endswith('/') for x in calls))

    def test_dns_non_global_never_sends_requests(self):
        def resolve(_):
            raise AuditError('DNS includes a private, reserved or otherwise non-global address')
        r=review_common_admin_hosts('example.com',resolve=resolve,
            client_factory=lambda *a:(_ for _ in ()).throw(AssertionError('transport created')),budget=budget())
        self.assertEqual(r['results'][0]['dns_status'],'blocked_non_global')

    def test_redirect_never_rendered_and_code_recorded(self):
        calls=[]
        response=Response(302,[('Location','https://outside.example/path')],b'')
        result=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
             client_factory=lambda host,ips:Client(host,ips,calls,response),
             render=lambda raw:(_ for _ in ()).throw(AssertionError('browser called')),budget=budget())
        self.assertEqual(result['http_attempted_count'],10)
        self.assertTrue(all(x['http_status']==302 and x['https_status']=='redirect_not_followed'
                            for x in result['results']))

    def test_429_stops_and_records_not_attempted(self):
        calls=[]
        response=Response(429,[],b'')
        result=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
             client_factory=lambda host,ips:Client(host,ips,calls,response),budget=budget())
        self.assertEqual(len(calls),1)
        self.assertEqual(result['status'],'halted')
        self.assertEqual(result['results'][0]['http_status'],429)
        self.assertEqual(sum(x['dns_status']=='skipped_after_stop' for x in result['results']),9)

    def test_generic_page_is_not_low(self):
        response=Response(200,[('Content-Type','text/html')],b'<title>Customer Login</title>')
        result=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
             client_factory=lambda host,ips:Client(host,ips,[],response),
             render=lambda raw:{'status':'ordinary_login'},budget=budget())
        self.assertEqual(result['admin_login_candidates'],0)
        self.assertTrue(all(x['risk'] is None for x in result['results']))


if __name__=='__main__':
    unittest.main()
