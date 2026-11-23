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
    args=parser.parse_args(argv)
    try:
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
    except (AuditError,ValueError) as exc:
        print('Audit rejected: ' + str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
