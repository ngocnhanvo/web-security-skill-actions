"""Passive HTTP security observations. Findings are not OWASP certifications."""
from __future__ import annotations
import re
from auditor.network import Response


def issue(code: str, title: str, severity: str, confidence: str, evidence: str) -> dict[str,str]:
    return {'code':code, 'title':title, 'severity':severity, 'confidence':confidence, 'evidence':evidence}


def check_headers(response: Response) -> list[dict[str,str]]:
    headers = [(k.lower(),v) for k,v in response.headers]
    got = {k for k,_ in headers}
    findings = []
    hsts = next((v for k,v in headers if k=='strict-transport-security'), '')
    if not re.search(r'\bmax-age\s*=\s*\d+', hsts, re.I) or re.search(r'\bmax-age\s*=\s*0\b',hsts,re.I):
        findings.append(issue('HSTS_MISSING','HSTS not configured','medium','confirmed-configuration','No effective Strict-Transport-Security max-age detected'))
    else:
        age=re.search(r'\bmax-age\s*=\s*(\d+)',hsts,re.I)
        if age and int(age.group(1)) < 15552000:
            findings.append(issue('HSTS_WEAK_MAX_AGE','HSTS max-age too short','low','confirmed-configuration',
                                  'Strict-Transport-Security max-age is shorter than 180 days'))
    csp = next((v for k,v in headers if k=='content-security-policy'), '')
    ctype = next((v for k,v in headers if k=='content-type'),'').lower()
    if 'text/html' in ctype and not csp:
        findings.append(issue('CSP_MISSING','Content Security Policy absent','medium','confirmed-configuration','HTML response has no Content-Security-Policy header'))
    if not any(k=='x-content-type-options' and v.lower().strip()=='nosniff' for k,v in headers):
        findings.append(issue('NOSNIFF_MISSING','MIME nosniff absent','low','confirmed-configuration','X-Content-Type-Options: nosniff not found'))
    if 'referrer-policy' not in got:
        findings.append(issue('REFERRER_POLICY_MISSING','Referrer Policy not explicit','low','confirmed-configuration','Referrer-Policy header missing'))
    if 'text/html' in ctype and not ('x-frame-options' in got or 'frame-ancestors' in csp.lower()):
        findings.append(issue('CLICKJACKING_POLICY_MISSING','No frame embedding restriction observed','medium','confirmed-configuration','Neither X-Frame-Options nor CSP frame-ancestors present'))
    for key, val in headers:
        if key != 'set-cookie':
            continue
        directives = [x.strip().lower() for x in val.split(';')[1:]]
        if 'secure' not in directives:
            findings.append(issue('COOKIE_SECURE_MISSING','Cookie missing Secure flag','medium','confirmed-configuration','A Set-Cookie header lacks Secure; cookie name and value omitted'))
        if 'httponly' not in directives:
            findings.append(issue('COOKIE_HTTPONLY_MISSING','Cookie missing HttpOnly flag','low','confirmed-configuration','A Set-Cookie header lacks HttpOnly; may be intentional for client-accessible cookies'))
        if not any(x.startswith('samesite=') for x in directives):
            findings.append(issue('COOKIE_SAMESITE_MISSING','Cookie missing explicit SameSite','low','confirmed-configuration','A Set-Cookie header lacks explicit SameSite'))
    # Deduplicate by type: neither cookie values nor cookie names should appear.
    return list({x['code']:x for x in findings}.values())


def certificate_findings(days_left: float) -> list[dict[str,str]]:
    if days_left < 0:
        return [issue('TLS_CERT_EXPIRED','TLS certificate expired','high','confirmed-configuration','Certificate expiry observed from TLS handshake')]
    if days_left < 14:
        return [issue('TLS_CERT_EXPIRING','TLS certificate expires soon','medium','confirmed-configuration','Certificate validity ends in fewer than 14 days')]
    return []


def fingerprints(response: Response) -> list[dict[str,str]]:
    """Unverified technology hints, deliberately not CVE assertions."""
    headers = [(k.lower(),v) for k,v in response.headers]
    rules = [(r'\b(nginx)/([0-9][\w.\-]+)', 'server'),
             (r'\b(Apache)/([0-9][\w.\-]+)', 'server'),
             (r'\b(PHP)/([0-9][\w.\-]+)', 'x-powered-by')]
    results=[]
    for pattern, header in rules:
        for k,val in headers:
            if k != header: continue
            match=re.search(pattern,val,re.I)
            if match:
                results.append({'name':match.group(1), 'version_hint':match.group(2), 'source':header, 'status':'unverified'})
    # No version certainty can be obtained from headers alone. No automatic CVE claim.
    return results
