"""Offline release checks. Never imports the controller or accesses a device.

Review changes before using --write-manifest. Hashes detect drift, not trust.
This allowlist and pattern scan do not replace a staged-content privacy review.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys


FILES = frozenset('''
.gitignore ADAPTING.md AGENTS.md EVIDENCE.md LICENSE LICENSE-APACHE-2.0.txt
LICENSE-TUYA-PANEL.txt NOTICES.md PROTOCOL.md README.md SECURITY.md
activation_store.py activation_transport.py activation_verification.py
activation_wire_study.py bardi.py cached_information.py check_release.py
info_probe_codec.py legacy_demo_study.py legacy_state_report.py
lighting_control.py lighting_demo.py lighting_state.py lighting_test_support.py
requirements.txt test_activation_store.py test_cached_information.py
test_legacy_demo_study.py test_lighting_control.py
'''.split())
MANIFEST = 'SOURCE-MANIFEST.json'
IGNORED = {'.git', '.venv', '__pycache__', '.amp', '.DS_Store'}
EXTERNAL_IMPORTS = {'bleak', 'Foundation'}
PATTERNS = {
    'personal absolute path': re.compile(r'/(?:Users|home)/[\w.-]+/'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'GitHub token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    'AWS access key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'email address': re.compile(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b'),
    'radio MAC address': re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b'),
}
UUID = re.compile(r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b')
PUBLIC_UUIDS = {
    '11111111-1111-4111-8111-111111111111',  # Synthetic peer.
    '0000fd50-0000-1000-8000-00805f9b34fb',  # Public GATT service.
    '00000001-0000-1001-8001-00805f9b07d0',
    '00000002-0000-1001-8001-00805f9b07d0',
    '00000003-0000-1001-8001-00805f9b07d0',
}


def inspect(root):
    entries = {path.name for path in root.iterdir()} - IGNORED
    if entries != FILES | {MANIFEST}:
        raise ValueError('Release file allowlist differs: ' + ', '.join(sorted(entries ^ (FILES | {MANIFEST}))))
    hashes = {}
    modules = {Path(name).stem for name in FILES if name.endswith('.py')}
    for name in sorted(FILES):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Expected a regular release file: {name}')
        raw = path.read_bytes()
        text = raw.decode('utf-8')
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                raise ValueError(f'Possible {label} in {name}; value withheld')
        if any(value.lower() not in PUBLIC_UUIDS for value in UUID.findall(text)):
            raise ValueError(f'Unreviewed UUID in {name}; value withheld')
        if name.endswith('.py'):
            for node in ast.walk(ast.parse(text, filename=name)):
                imports = ([node.module or ''] if isinstance(node, ast.ImportFrom) else
                           [item.name for item in node.names] if isinstance(node, ast.Import) else [])
                for imported in imports:
                    module = imported.split('.')[0]
                    if module not in modules | sys.stdlib_module_names | EXTERNAL_IMPORTS:
                        raise ValueError(f'Unreleased import in {name}: {module}')
        if name.endswith('.md'):
            for link in re.findall(r'\]\(([^)]+)\)', text):
                if '://' not in link and not link.startswith('#'):
                    target = link.split('#', 1)[0]
                    if target not in FILES:
                        raise ValueError(f'Broken local documentation link in {name}: {target}')
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-manifest', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    hashes = inspect(root)
    manifest = root / MANIFEST
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('Expected a regular source manifest')
    if args.write_manifest:
        manifest.write_text(json.dumps(hashes, indent=2, sort_keys=True) + '\n')
    elif json.loads(manifest.read_text()) != hashes:
        raise ValueError('Manifest differs. Review changes before using --write-manifest.')
    print(f'Checked {len(hashes)} allowlisted files, imports, links, privacy patterns, and hashes; no device access')


if __name__ == '__main__':
    main()
