"""Offline review of owner-reported administration controls.

No discovery, network access, hostname expansion, credential processing, or
live access-control verification. Results are self-reported configuration gaps.
"""
from pathlib import Path
import json
import re


class InventoryError(Exception):
    """Input rejected without echoing private values."""


CONTROLS = ('https_enforced', 'authentication_required', 'mfa_required',
            'network_access_restricted', 'server_side_authorization')
STATES = frozenset({'yes', 'no', 'unknown'})
EXPOSURES = frozenset({'internet', 'restricted', 'unknown'})
MAX_BYTES = 65536
MAX_INTERFACES = 100
PRIORITY_LIMIT = 10
PREVALENCE = frozenset({'high', 'medium', 'low', 'unknown'})


def _check(record, control, severity, advice):
    value = record[control]
    status = {'yes': 'reported_configured', 'no': 'reported_gap',
              'unknown': 'not_verified'}[value]
    return {'control': control, 'status': status,
            'severity': severity if value == 'no' else None,
            'recommendation': advice if value != 'yes' else None}


def review_inventory(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'interfaces'}
            or type(value['version']) is not int or value['version'] != 1):
        raise InventoryError('Expected version 1 owner inventory')
    records = value['interfaces']
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_INTERFACES:
        raise InventoryError('Inventory requires 1 to 100 explicit interface records')
    seen = set()
    output = []
    candidates = []
    required = {'id', 'exposure', *CONTROLS}
    optional = {'publicly_advertised', 'name_prevalence'}
    for record in records:
        if (not isinstance(record, dict) or not required.issubset(record)
                or not set(record).issubset(required | optional)):
            raise InventoryError('Invalid interface fields; no URLs or secrets accepted')
        identifier = record['id']
        if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', identifier)
                or identifier in seen):
            raise InventoryError('Interface IDs must be unique non-sensitive aliases')
        seen.add(identifier)
        exposure = record['exposure']
        if not isinstance(exposure, str) or exposure not in EXPOSURES:
            raise InventoryError('Invalid exposure classification')
        if any(not isinstance(record[k], str) or record[k] not in STATES for k in CONTROLS):
            raise InventoryError('Controls must be yes, no or unknown')
        advertised = record.get('publicly_advertised', 'unknown')
        prevalence = record.get('name_prevalence', 'unknown')
        if not isinstance(advertised, str) or advertised not in STATES:
            raise InventoryError('Public advertisement must be yes, no or unknown')
        if not isinstance(prevalence, str) or prevalence not in PREVALENCE:
            raise InventoryError('Name prevalence must be high, medium, low or unknown')
        if advertised == 'yes' or prevalence in ('high', 'medium'):
            candidates.append({'id': identifier, 'publicly_advertised': advertised,
                               'name_prevalence': prevalence, 'evidence': 'owner_reported'})
        public = exposure == 'internet'
        # Public access to a login interface is not itself an auth bypass.
        checks = [
            {'control':'internet_exposure', 'status': {'internet':'reported_exposure','restricted':'reported_restricted','unknown':'not_verified'}[exposure],
             'severity':'low' if public else None,
             'recommendation':'Review whether Internet exposure is necessary; prefer restricted access where feasible' if exposure != 'restricted' else None},
            _check(record, 'https_enforced', 'medium', 'Enforce trusted HTTPS on all administration traffic'),
            _check(record, 'authentication_required', 'high' if public else 'medium', 'Require authentication before serving protected administration functions'),
            _check(record, 'mfa_required', 'medium', 'Require MFA for privileged accounts'),
            _check(record, 'network_access_restricted', 'low', 'Evaluate VPN, identity-aware proxy or an appropriate network allowlist'),
            _check(record, 'server_side_authorization', 'high' if public else 'medium', 'Enforce least privilege and server-side authorization for privileged functions'),
        ]
        output.append({'id':identifier, 'evidence':'owner_reported', 'checks':checks})
    counts = {'reported_gaps':0, 'reported_exposures':0, 'not_verified':0, 'reported_controls':0}
    for row in output:
        for item in row['checks']:
            key = {'reported_gap':'reported_gaps','reported_exposure':'reported_exposures',
                   'not_verified':'not_verified','reported_configured':'reported_controls',
                   'reported_restricted':'reported_controls'}[item['status']]
            counts[key] += 1
    # Priority uses only declared records, never a generated hostname or wordlist.
    order = {'high': 0, 'medium': 1, 'low': 2, 'unknown': 3}
    candidates.sort(key=lambda x: (x['publicly_advertised'] != 'yes', order[x['name_prevalence']], x['id']))
    priority = {'limit': PRIORITY_LIMIT, 'eligible_count': len(candidates),
                'omitted_count': max(0, len(candidates) - PRIORITY_LIMIT),
                'basis': 'owner_reported_advertisement_and_name_prevalence_not_measured',
                'interfaces': candidates[:PRIORITY_LIMIT]}
    return {'schema_version':'1.0.0', 'mode':'offline_admin_inventory',
            'priority_review': priority,
            'evidence':'owner_reported_not_independently_verified',
            'network_requests':0, 'live_verification':'not_tested',
            'interface_count':len(output), 'counts':counts, 'interfaces':output,
            'disclaimer':'Owner-reported controls only; not proof of reachability, absence of vulnerabilities or authentication bypass. Keep this report private.'}


def review_inventory_file(path):
    try:
        with Path(path).open('rb') as source:
            raw=source.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:
            raise InventoryError('Inventory exceeds size limit')
        # Reject duplicate keys rather than silently selecting a value.
        def unique_pairs(pairs):
            obj={}
            for key, val in pairs:
                if key in obj:
                    raise InventoryError('Duplicate inventory field')
                obj[key]=val
            return obj
        value=json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise InventoryError('Unable to read valid inventory JSON') from exc
    return review_inventory(value)
