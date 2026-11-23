import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from auditor.__main__ import main
from auditor.network import AuditError

class TestCLI(unittest.TestCase):
    def test_challenge_generates_random_token_and_unapproved_template(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a.json'
            self.assertEqual(main(['challenge','--domain','https://example.com','--out',str(a)]),0)
            doc=json.loads(a.read_text())
            self.assertEqual(doc['domain'],'example.com')
            self.assertGreaterEqual(len(doc['authorization_id']),24)
            self.assertIs(doc['consent_confirmed'],False)
            self.assertEqual(doc['test_paths'],[])

    def test_invalid_target_does_not_write_report(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'public.json'
            code=main(['scan','--domain','localhost','--public-out',str(out)])
            self.assertNotEqual(code,0)
            self.assertFalse(out.exists())

if __name__=='__main__':unittest.main()
