import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from auditor.admin_inventory import review_inventory, review_inventory_file, InventoryError
from auditor.__main__ import main


def sample(**changes):
    data={'id':'interface_01','exposure':'internet','https_enforced':'yes',
          'authentication_required':'yes','mfa_required':'unknown',
          'network_access_restricted':'no','server_side_authorization':'unknown'}
    data.update(changes)
    return data


class TestAdminInventory(unittest.TestCase):
    def review(self,*items):
        return review_inventory({'version':1,'interfaces':list(items)})

    def test_public_login_is_low_not_bypass(self):
        report=self.review(sample())
        self.assertEqual(report['network_requests'],0)
        self.assertEqual(report['live_verification'],'not_tested')
        checks={x['control']:x for x in report['interfaces'][0]['checks']}
        self.assertEqual(checks['internet_exposure']['severity'],'low')
        self.assertEqual(checks['authentication_required']['status'],'reported_configured')
        self.assertEqual(checks['mfa_required']['status'],'not_verified')
        self.assertIsNone(checks['mfa_required']['severity'])

    def test_reported_gaps_are_not_confirmed_exploits(self):
        report=self.review(sample(authentication_required='no',https_enforced='no'))
        checks={x['control']:x for x in report['interfaces'][0]['checks']}
        self.assertEqual(checks['authentication_required']['status'],'reported_gap')
        self.assertEqual(checks['https_enforced']['severity'],'medium')
        self.assertEqual(report['evidence'],'owner_reported_not_independently_verified')

    def test_multiple_records_are_independent(self):
        r=self.review(sample(),sample(id='interface_02',exposure='restricted'))
        self.assertEqual(r['interface_count'],2)
        self.assertEqual(r['counts']['reported_exposures'],1)

    def test_priority_top_ten_only_owner_declared_and_deterministic(self):
        rows = [sample(id='item_%02d' % i, name_prevalence='medium') for i in range(15)]
        rows.extend([sample(id='preferred', publicly_advertised='yes', name_prevalence='low'),
                     sample(id='high_priority', name_prevalence='high'),
                     sample(id='unknown'), sample(id='low', name_prevalence='low')])
        result = self.review(*rows)['priority_review']
        self.assertEqual(result['eligible_count'], 17)
        self.assertEqual(result['omitted_count'], 7)
        self.assertEqual(len(result['interfaces']), 10)
        self.assertEqual([x['id'] for x in result['interfaces'][:2]], ['preferred','high_priority'])
        self.assertEqual(result, self.review(*reversed(rows))['priority_review'])
        self.assertEqual(self.review(*rows)['interface_count'], 19)

    def test_no_owner_metadata_does_not_invent_prevalence(self):
        r = self.review(sample())['priority_review']
        self.assertEqual(r['eligible_count'], 0)
        self.assertEqual(r['interfaces'], [])
        self.assertIn('not_measured', r['basis'])

    def test_invalid_priority_metadata_is_rejected(self):
        for row in [sample(publicly_advertised=True), sample(name_prevalence='very_high')]:
            with self.assertRaises(InventoryError): self.review(row)

    def test_reject_secret_fields_and_invalid_values(self):
        for row in [sample(password='secret'),sample(id='https://example.com'),sample(exposure=[]),sample(mfa_required=True),sample(https_enforced='maybe')]:
            with self.subTest(row=row),self.assertRaises(InventoryError):
                self.review(row)

    def test_reject_duplicate_or_empty_inventory(self):
        with self.assertRaises(InventoryError): self.review(sample(),sample())
        with self.assertRaises(InventoryError): self.review()

    def test_reject_duplicate_keys_and_large_files(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input.json'
            path.write_text('{"version":1,"version":1,"interfaces":[]}')
            with self.assertRaises(InventoryError): review_inventory_file(path)
            path.write_bytes(b' '*65537)
            with self.assertRaises(InventoryError): review_inventory_file(path)

    def test_cli_never_calls_network_runner(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'input.json'
            out=Path(d)/'report.json'
            src.write_text(json.dumps({'version':1,'interfaces':[sample()]}))
            with patch('auditor.__main__.audit',side_effect=AssertionError('network audit called')), patch('socket.getaddrinfo',side_effect=AssertionError('DNS called')):
                self.assertEqual(main(['review-admin-inventory','--input',str(src),'--out',str(out)]),0)
            self.assertEqual(json.loads(out.read_text())['network_requests'],0)
            self.assertEqual(main(['review-admin-inventory','--input',str(src),'--out',str(src)]),2)

if __name__=='__main__':
    unittest.main()
