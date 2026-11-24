"""python -m auditor challenge|scan"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import secrets
import sys

from auditor.network import AuditError,validate_target
from auditor.runner import audit,public_report
from auditor.admin_inventory import review_inventory_file, InventoryError
from auditor.admin_snapshot import review_snapshot, SnapshotError


def write_json(path: str, value: dict) -> None:
    file=Path(path)
    file.parent.mkdir(parents=True,exist_ok=True)
    file.write_text(json.dumps(value,indent=2,ensure_ascii=False,sort_keys=True)+'\n', encoding='utf-8')


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description='Low-impact domain-only web audit; authorization required for active probes')
    sub=parser.add_subparsers(dest='action',required=True)
    challenge=sub.add_parser('challenge',help='Create a one-time permission file for the site owner to edit and upload')
    challenge.add_argument('--domain',required=True)
    challenge.add_argument('--out',required=True)
    scan=sub.add_parser('scan',help='Run a passive scan; active checks gated by fresh owner-hosted permission JSON')
    scan.add_argument('--domain',required=True)
    scan.add_argument('--authorization-url',default='')
    scan.add_argument('--challenge',default='')
    scan.add_argument('--out',help='LOCAL/PRIVATE full report path; never upload to a public repo')
    scan.add_argument('--public-out',required=True,help='Sanitized report safe for public GitHub Actions artifacts')
    inventory=sub.add_parser('review-admin-inventory',help='Offline review of owner-provided administration controls; no network')
    inventory.add_argument('--input',required=True,help='PRIVATE owner inventory JSON')
    inventory.add_argument('--out',required=True,help='PRIVATE local review report; never publish')
    snapshot=sub.add_parser('review-admin-snapshot',help='Offline Playwright review of owner-provided HTML; no website navigation')
    snapshot.add_argument('--input',required=True,help='Private UTF-8 HTML snapshot')
    snapshot.add_argument('--out',required=True,help='Private JSON report')
    args=parser.parse_args(argv)
    try:
        if args.action=='review-admin-snapshot':
            if Path(args.input).resolve() == Path(args.out).resolve():
                raise SnapshotError('Input and output must differ')
            write_json(args.out,review_snapshot(args.input))
            print('Offline interface review saved; live verification not tested')
            return 0
        if args.action=='review-admin-inventory':
            if Path(args.input).resolve() == Path(args.out).resolve():
                raise InventoryError('Input and report must be different files')
            report=review_inventory_file(args.input)
            write_json(args.out,report)
            print('Offline inventory review saved; owner-reported evidence only; no network verification')
            return 0
        host=validate_target(args.domain)
        if args.action=='challenge':
            now=datetime.now(timezone.utc)
            data={
                'version':1,'domain':host,'authorization_id':secrets.token_urlsafe(32),
                'authorized_auditor':'Web Security Auditor NVN',
                'authorized_by':'REPLACE_WITH_AUTHORIZED_WEBSITE_OWNER',
                'consent_confirmed':False,
                'not_before':now.isoformat(),
                'expires_at':(now+timedelta(days=1)).isoformat(),
                'allowed_tests':['sql_injection_low_impact','xss_low_impact','authentication_basic'],
                'test_paths':[],
                'max_requests':15,
            }
            write_json(args.out,data)
            print('Authorization template created; site owner MUST review, specify test_paths, and affirm consent. Do not upload blindly.')
            return 0
        result=audit(host,authorization_url=args.authorization_url or None,challenge=args.challenge or None)
        write_json(args.public_out,public_report(result))
        if args.out:
            write_json(args.out,result)
        print('Audit saved; scan_status=' + result['scan_status'] + '; authorization=' + result['authorization']['status']
              + '; active=' + result['active']['status'])
        return 0 if result['scan_status']=='completed' else 2
    except (AuditError,ValueError,InventoryError,SnapshotError) as exc:
        print('Audit rejected: ' + str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
