import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from auditor.public_bridge import parse_public_request, discover_new_request, RequestError


class TestPublicRequest(unittest.TestCase):
    def test_valid_exact_domain_only(self):
        self.assertEqual(parse_public_request(json.dumps({'version': 1, 'mode': 'public', 'domain': 'esc.vn'})), 'esc.vn')
        self.assertEqual(parse_public_request(json.dumps({'version': 1, 'mode': 'public', 'domain': 'https://esc.vn/'})), 'esc.vn')

    def test_reject_active_and_unknown_fields(self):
        for payload in [
            {'version': 1, 'mode': 'authorized', 'domain': 'esc.vn'},
            {'version': 1, 'mode': 'public', 'domain': 'esc.vn', 'authorization_url': 'https://esc.vn/file'},
            {'version': 1, 'mode': 'public', 'domain': 'localhost'},
            {'version': 1, 'mode': 'public', 'domain': 'http://esc.vn'},
            {'version': True, 'mode': 'public', 'domain': 'esc.vn'},
            {'version': 1, 'mode': 'public', 'domain': 'esc.vn', 'args': ['--out', '/etc/passwd']},
        ]:
            with self.subTest(payload=payload), self.assertRaises(RequestError):
                parse_public_request(json.dumps(payload))

    def test_one_new_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=pathlib.Path(tmp)
            p=base/'requests/public/20261123-esc-vn.json'
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps({'version': 1, 'mode': 'public', 'domain': 'esc.vn'}))
            with patch('auditor.public_bridge._added_paths', return_value=['requests/public/20261123-esc-vn.json']):
                self.assertEqual(discover_new_request(base), 'esc.vn')
            with patch('auditor.public_bridge._added_paths', return_value=['requests/public/20261123-esc-vn.json','requests/public/another.json']):
                with self.assertRaises(RequestError): discover_new_request(base)
            with patch('auditor.public_bridge._added_paths', return_value=['../x.json']):
                with self.assertRaises(RequestError): discover_new_request(base)
            with patch('auditor.public_bridge._added_paths', return_value=['requests/public/20261123-esc-vn.json']):
                p.write_text('not json')
                with self.assertRaises(RequestError): discover_new_request(base)

if __name__=='__main__': unittest.main()
