"""Orchestrate passive audit and conditionally scoped authorized checks."""
from __future__ import annotations
from datetime import datetime,timezone
import time
from urllib.parse import urlsplit

from auditor.authorization import AuthorizationError, decode_authorization, validate_authorization
from auditor.budget import Budget, BudgetError
from auditor.checks import check_headers, certificate_findings, fingerprints, issue
from auditor.admin_exposure import inspect_admin_exposure
from auditor.admin_snapshot import review_html_bytes, SnapshotError
from auditor.admin_subdomains import review_common_admin_hosts
from auditor.network import AuditError, PinnedHTTP, resolve_global_ips, validate_target, validate_https_url, tls_days_until_expiry
from auditor.probes import probe_sql, probe_xss, probe_guest_auth


def _read(client, url, budget):
    budget.before()
    response=client.get(url)
    budget.after(response.status)
    return response


def audit(domain: str, *, authorization_url: str | None = None, challenge: str | None = None,
          client=None, resolve=resolve_global_ips, now: datetime | None = None,
          budget: Budget | None = None, offline_browser: bool = False,
          admin_subdomains: bool = False) -> dict:
    """Always start public. Active checks require on-host authorization revalidation."""
    host=validate_target(domain)
    now=now or datetime.now(timezone.utc)
    public_ips=resolve(host)
    use_real_transport=client is None
    client=client or PinnedHTTP(host,public_ips)
    budget=budget or Budget(max_requests=30,min_interval_seconds=1.0)
    report={
        'schema_version':'1.0.0', 'target_hostname':host,
        'scan_status':'completed', 'public':{'status':'completed','findings':[],'technology_hints':[],
                                             'admin_interface_exposure':{'status':'not_tested','scope':'homepage HTML only','note':'No suitable HTML response was inspected','evidence_types':[],'destination_verification':'not_tested','hostname_discovery':'not_tested'},
                                             'homepage_browser_review':{'status':'not_tested','scope':'homepage HTML offline','live_reachability':'not_tested','authentication':'not_tested'},
                                             'admin_subdomain_review':{'status':'not_tested','reason':'Not requested'},
                                             'checks_not_performed':['CVE exploitability','source code','database','business logic']},
        'authorization':{'status':'public_only'},
        'active':{'status':'not_run','findings':[],'tests_executed':0},
        'limits':{'max_requests':budget.max_requests,'minimum_request_spacing_seconds':budget.min_interval_seconds},
    }
    base='https://'+host
    try:
        home=_read(client,base+'/',budget)
        if not 200 <= home.status < 300:
            raise AuditError('Homepage was not accessible as 2xx; configuration scoring skipped')
        report['public']['findings']=check_headers(home)
        report['public']['technology_hints']=fingerprints(home)
        admin_status, admin_findings = inspect_admin_exposure(home, host)
        report['public']['admin_interface_exposure'] = admin_status
        report['public']['findings'] += admin_findings
        if offline_browser and (home.header('Content-Type') or '').split(';',1)[0].strip().lower() == 'text/html' and (home.header('Content-Encoding') or 'identity').strip().lower() == 'identity':
            try:
                browser_result=review_html_bytes(home.body)
                browser_result['scope']='homepage HTML offline'
                report['public']['homepage_browser_review']=browser_result
            except SnapshotError:
                report['public']['homepage_browser_review']['note']='Offline browser review could not be completed'
        if use_real_transport:
            report['public']['findings']+=certificate_findings(tls_days_until_expiry(host,public_ips,now.timestamp()))
    except (BudgetError, AuditError) as exc:
        report['scan_status']='halted'
        report['public']['status']='halted'
        report['public']['error']=str(exc)
        return report
    if admin_subdomains and not authorization_url:
        sub_report = review_common_admin_hosts(host, budget=budget)
        report['public']['admin_subdomain_review'] = sub_report
        # A verified visible login should appear in the primary finding list
        # as well as the detailed hostname-by-hostname review.
        if sub_report.get('admin_login_candidates', 0) > 0 or any(
            row.get('browser_status') == 'admin_login_candidate'
            for row in sub_report.get('results', [])
        ):
            report['public']['findings'].append(issue(
                'ADMIN_LOGIN_INTERFACE_PUBLIC',
                'Public-facing administration login interface observed', 'low',
                'confirmed-configuration',
                'HTTPS login form and administration-specific visual evidence observed; '
                'see public.admin_subdomain_review for checked hostnames. '
                'No login or authentication bypass attempted.'
            ))
    if not authorization_url:
        return report

    # An arbitrary user-supplied permission URL is permitted ONLY on exact target host.
    try:
        permission_path=validate_https_url(authorization_url,host)
        if '?' in permission_path or len(permission_path)>250:
            raise AuthorizationError('Authorization file must be a small direct path without query')
        raw=_read(client,authorization_url,budget)
        if raw.status != 200:
            raise AuthorizationError('Authorization file did not return HTTP 200')
        consent=validate_authorization(decode_authorization(raw.body),host,challenge or '',now)
    except (AuditError,AuthorizationError,BudgetError) as exc:
        report['authorization']={'status':'invalid','reason':'Authorization file failed validation'}
        if isinstance(exc,BudgetError): report['scan_status']='halted'
        return report
    budget.max_requests=min(budget.max_requests,consent.max_requests)
    report['authorization']={'status':'authorized','expires_at':consent.expires_at.isoformat(),
                             'allowed_tests':sorted(consent.allowed_tests)}
    report['limits']['max_requests']=budget.max_requests
    report['active']['status']='running'
    try:
        for path in consent.test_paths:
            # Each approved URL and test uses GET only; content never logged.
            for allowed_test,probe in [('sql_injection_low_impact',probe_sql),
                                       ('xss_low_impact',probe_xss),('authentication_basic',probe_guest_auth)]:
                if allowed_test not in path.tests:
                    continue
                finding=probe(client,base,path,budget)
                report['active']['tests_executed']+=1
                if finding:
                    report['active']['findings'].append({**finding,'location_path':path.path.split('?')[0]})
        report['active']['status']='completed'
    except (AuditError,BudgetError,ValueError) as exc:
        report['active']['status']='halted'
        report['scan_status']='halted'
        # Only expose the category of the error, not the vulnerable request/payload.
        report['active']['stop_reason']='Request budget or network safety rule interrupted scan'
    return report


def public_report(full: dict) -> dict:
    """Whitelist public fields only; public Actions artifacts must NEVER contain active details."""
    active=full['active']
    return {
        'schema_version':full['schema_version'],
        'target_hostname':full['target_hostname'],
        'scan_status':full['scan_status'],
        'public':full['public'],
        'authorization':{'status':full['authorization']['status']},
        'active':{'status':active['status'],
                  'tests_executed':active['tests_executed'],
                  'possible_issue_count':len(active['findings']),
                  'note':'Detailed active findings, paths and payloads intentionally withheld from public artifacts'},
        'disclaimer':'Limited observable checks only; not a penetration-test certification or proof of no vulnerabilities',
    }
