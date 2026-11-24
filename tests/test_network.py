import socket
import unittest
from unittest.mock import patch

from auditor.network import AuditError, validate_target, resolve_global_ips, PinnedHTTP


class TestNetwork(unittest.TestCase):
    def test_target_accepts_domain_and_https(self):
        self.assertEqual(validate_target('https://ExAmple.com'), 'example.com')
        self.assertEqual(validate_target('example.com'), 'example.com')

    def test_rejects_internal_hosts_and_url_features(self):
        for input_value in ['localhost', '127.0.0.1', '10.0.0.1', 'https://example.com:8443', 'http://example.com',
                            'https://user:password@example.com', 'https://example.com/path', 'https://example.com/?foo=1',
                            'http://127.0.0.1', 'example.com#frag', 'example.com@127.0.0.1']:
            with self.subTest(input_value=input_value), self.assertRaises(AuditError):
                validate_target(input_value)

    def test_dns_private_address_and_mixed_results_blocked(self):
        def addr_info(value):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (ip, 443)) for ip in value]
        with patch('auditor.network.socket.getaddrinfo',return_value=addr_info(['93.184.215.14', '127.0.0.1'])):
            with self.assertRaises(AuditError):
                resolve_global_ips('example.com')
        with patch('auditor.network.socket.getaddrinfo',return_value=addr_info(['10.0.0.2'])):
            with self.assertRaises(AuditError):
                resolve_global_ips('example.com')

    def test_dns_public_ip_allowed(self):
        with patch('auditor.network.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,0,'',('8.8.8.8',443))]):
            self.assertEqual(resolve_global_ips('example.com'),['8.8.8.8'])

    def test_request_rejects_offsite_url_without_network(self):
        with self.assertRaises(AuditError):
            PinnedHTTP('example.com', ['8.8.8.8']).get('https://evil.com/')

    def test_get_unfollowed_records_3xx_without_redirect_request(self):
        from auditor.network import Response
        with patch('auditor.network.resolve_global_ips',return_value=['8.8.8.8']), patch.object(PinnedHTTP, '_get_path',return_value=Response(302,[('Location','https://other.example/')],b'')) as get:
            value=PinnedHTTP('example.com',['8.8.8.8']).get_unfollowed('https://example.com/')
        self.assertEqual(value.status,302)
        get.assert_called_once_with('/')

    def test_request_rejects_redirects_without_following(self):
        class Dummy:
            status=302
            headers=[('Location','https://evil.com/')]
            body=b''
        with patch.object(PinnedHTTP, '_get_path', return_value=Dummy()):
            with self.assertRaises(AuditError):
                PinnedHTTP('example.com', ['8.8.8.8']).get('https://example.com/')

if __name__=='__main__':
    unittest.main()
