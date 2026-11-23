"""Public-only audit requests triggered by a real GitHub file commit.

This bridge is intentionally incapable of accepting authorization URLs,
active-test mode, arbitrary shell arguments, or workflow code from requests.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess

from auditor.network import AuditError, validate_target


class RequestError(Exception):
    """Malformed or out-of-scope request; never invoke scanner."""


def parse_public_request(raw: str) -> str:
    if len(raw.encode('utf-8')) > 1024:
        raise RequestError('Public audit request too large')
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RequestError('Invalid JSON request') from exc
    if (not isinstance(value, dict) or set(value) != {'version', 'mode', 'domain'}
            or type(value['version']) is not int or value['version'] != 1
            or value['mode'] != 'public' or not isinstance(value['domain'], str)):
        raise RequestError('Only a version 1 public-domain request is allowed')
    try:
        return validate_target(value['domain'])
    except AuditError as exc:
        raise RequestError('Invalid public HTTPS hostname') from exc


def _added_paths(root: pathlib.Path) -> list[str]:
    result = subprocess.run(
        ['git', '-C', str(root), 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD'],
        check=True, capture_output=True, text=True,
    )
    return [p.strip() for p in result.stdout.splitlines() if p.strip()]


def discover_new_request(root: pathlib.Path) -> str:
    """Require the triggering commit to change precisely one request file."""
    paths = _added_paths(root)
    if len(paths) != 1:
        raise RequestError('Exactly one changed public request file required')
    path = paths[0]
    if not re.fullmatch(r'requests/public/[A-Za-z0-9_-]{5,100}\.json', path):
        raise RequestError('Only a public JSON request path is permitted')
    resolved_root = root.resolve()
    candidate = (resolved_root / path)
    if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(resolved_root):
        raise RequestError('Unsafe request file')
    try:
        return parse_public_request(candidate.read_text(encoding='utf-8'))
    except (OSError, UnicodeError) as exc:
        raise RequestError('Unable to read request file') from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        domain = discover_new_request(pathlib.Path.cwd())
        # validate_target restricts this value to [a-z0-9.-] before writing GITHUB_OUTPUT.
        with open(args.output, 'a', encoding='utf-8') as f:
            f.write('domain=' + domain + '\n')
        print('Validated public-only audit target: ' + domain)
        return 0
    except RequestError as exc:
        print('Request rejected: ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
