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

    def test_safe_same_host_redirect_and_browser_classification(self):
        calls=[]
        class RedirectClient:
            def get_unfollowed(self,url):
                calls.append(url)
                if url.endswith('/'):
                    return Response(302,[('Location','/login')],b'')
                return Response(200,[('Content-Type','text/html')],b'<title>Admin Login</title>')
        report=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
                client_factory=lambda host,ips:RedirectClient(),
                render=lambda body:{'status':'admin_login_candidate'},budget=budget())
        self.assertEqual(report['http_attempted_count'],20)
        self.assertEqual(report['admin_login_candidates'],10)
        self.assertEqual(report['results'][0]['first_http_status'],302)
        self.assertEqual(report['results'][0]['http_status'],200)
        self.assertTrue(report['results'][0]['redirect_followed'])
        self.assertEqual(calls[:2],['https://admin.example.com/','https://admin.example.com/login'])

    def test_query_redirect_is_not_followed(self):
        calls=[]
        response=Response(302,[('Location','/login?token=hidden')],b'')
        report=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
          client_factory=lambda host,ips:Client(host,ips,calls,response),budget=budget())
        self.assertEqual(len(calls),10)
        self.assertEqual(report['results'][0]['redirect_scope'],'different_host_or_unsafe')
        self.assertNotIn('hidden',repr(report))

    def test_tls_certificate_error_is_distinct(self):
        class CertError:
            def __init__(self,host,ips): pass
            def get_unfollowed(self,url): raise AuditError('TLS certificate verification failed')
        report=review_common_admin_hosts('example.com',resolve=lambda _:['8.8.8.8'],
              client_factory=CertError,budget=budget())
        self.assertEqual(report['results'][0]['https_status'],'tls_certificate_error')
        self.assertEqual(report['http_attempted_count'],10)

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


class TestWordPressRedirectChain(unittest.TestCase):
    def test_realistic_wp_chain_ends_in_login_candidate(self):
        from auditor.admin_subdomains import _same_host_target
        from urllib.parse import quote
        calls = []
        host = 'admin.esc.vn'
        wp = '/wp-login.php?redirect_to=' + quote('https://' + host + '/wp-admin/', safe='') + '&reauth=1'

        class WordPressClient:
            def __init__(self, hostname, ips): self.hostname = hostname
            def get_unfollowed(self, url):
                calls.append(url)
                if url == 'https://' + host + '/':
                    return Response(302, [('Location', '/wp-admin/')], b'')
                if url == 'https://' + host + '/wp-admin/':
                    return Response(302, [('Location', wp)], b'')
                return Response(200, [('Content-Type','text/html; charset=UTF-8')], b'<form id="loginform"><input id="user_login"><input id="user_pass" type="password"></form>')

        def resolver(candidate):
            if candidate == host: return ['8.8.8.8']
            raise AuditError('DNS lookup failed')
        result = review_common_admin_hosts('esc.vn', resolve=resolver,
                     client_factory=WordPressClient,
                     render=lambda body: {'status':'admin_login_candidate'}, budget=budget())
        found = result['results'][0]
        self.assertEqual(found['request_count'], 3)
        self.assertEqual(found['redirect_count'], 2)
        self.assertEqual(found['first_http_status'], 302)
        self.assertEqual(found['http_status'], 200)
        self.assertEqual(found['browser_status'], 'admin_login_candidate')
        self.assertEqual(found['risk'], 'low')
        self.assertEqual(result['http_attempted_count'], 3)
        self.assertNotIn('redirect_to', repr(result))
        self.assertEqual(len(calls), 3)
        self.assertEqual(_same_host_target(calls[1], wp, host), calls[2])

    def test_rejects_unsafe_redirect_to_queries_and_paths(self):
        from auditor.admin_subdomains import _same_host_target
        from urllib.parse import quote
        host='admin.example.com'
        base='https://' + host + '/wp-admin/'
        bad=[
            '/wp-login.php?redirect_to=' + quote('https://evil.com/wp-admin/', safe='') + '&reauth=1',
            '/wp-login.php?redirect_to=' + quote('http://'+host+'/wp-admin/', safe=''),
            '/wp-login.php?redirect_to=' + quote('https://'+host+'/user/', safe=''),
            '/wp-login.php?redirect_to=' + quote('https://'+host+'/wp-admin/?x=1', safe=''),
            '/wp-login.php?redirect_to=' + quote('https://'+host+'/wp-admin/', safe='')+'&token=secret',
            '/wp-login.php?reauth=1&reauth=1',
            '/anything?param=hello',
            'https://other.example.com/wp-login.php',
            '/wp-login.php?reauth=0%0D%0AHeader:%20bad',
        ]
        for location in bad:
            with self.subTest(location=location):
                self.assertIsNone(_same_host_target(base, location, host))

    def test_redirect_limit_still_enforced(self):
        host='admin.example.com'
        class Loops:
            def __init__(self, hostname, ips): self.count=0
            def get_unfollowed(self, url):
                self.count+=1
                return Response(302,[('Location','/r'+str(self.count))],b'')
        report=review_common_admin_hosts('example.com',
              resolve=lambda h: ['8.8.8.8'] if h==host else (_ for _ in ()).throw(AuditError('DNS lookup failed')),
              client_factory=Loops,budget=budget())
        self.assertEqual(report['results'][0]['request_count'],3)
        self.assertEqual(report['results'][0]['https_status'],'redirect_limit_reached')
