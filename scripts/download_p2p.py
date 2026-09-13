from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import requests

RECORD_ID = 8412920
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = REPO_ROOT / 'data' / 'raw' / 'p2p'
EXPECTED_FILES: dict[str, dict[str, Any]] = {
    'ocel2-p2p.json': {
        'bytes': 14263783,
        'md5': '26a8a29333c191d239a7b0fdc44b818f',
        'sha256': '33a8a412ad9d7b124c50e89581f243344dc4d7b80f5bdd38b5306edb9b9fa2ec',
        'url': 'https://zenodo.org/api/records/8412920/files/ocel2-p2p.json/content',
    },
    'ocel2-p2p.sqlite': {
        'bytes': 13746176,
        'md5': '1a4238260019939239488b0b4befb515',
        'sha256': '0017c34aeecdcb7712004d4364b11b372f2cc1a9cf2639ffe295f95a0df1ee74',
        'url': 'https://zenodo.org/api/records/8412920/files/ocel2-p2p.sqlite/content',
    },
}


def _hashes(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open('rb') as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b''):
            md5.update(block)
            sha256.update(block)
    return md5.hexdigest(), sha256.hexdigest()


def verify_file(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return {'path': str(path), 'present': False, 'hashes_match': False}
    md5, sha256 = _hashes(path)
    size = path.stat().st_size
    return {
        'path': str(path),
        'present': True,
        'bytes': size,
        'md5': md5,
        'sha256': sha256,
        'bytes_match': size == int(expected['bytes']),
        'md5_match': md5 == str(expected['md5']),
        'sha256_match': sha256 == str(expected['sha256']),
        'hashes_match': size == int(expected['bytes']) and md5 == str(expected['md5']) and sha256 == str(expected['sha256']),
    }


def verify_existing(dest: str | Path = DEFAULT_DEST) -> dict[str, Any]:
    root = Path(dest)
    files = {name: verify_file(root / name, expected) for name, expected in EXPECTED_FILES.items()}
    return {
        'record_id': RECORD_ID,
        'dest': str(root),
        'files': files,
        'all_present': all(row.get('present') for row in files.values()),
        'all_hashes_match': all(row.get('hashes_match') for row in files.values()),
    }


def download(dest: str | Path = DEFAULT_DEST, *, overwrite_bad: bool = False) -> dict[str, Any]:
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    for name, expected in EXPECTED_FILES.items():
        target = root / name
        current = verify_file(target, expected)
        if current.get('hashes_match'):
            continue
        if target.exists() and not overwrite_bad:
            raise RuntimeError(f'existing file fails frozen verification; refuse overwrite without --overwrite-bad: {target}')
        partial = target.with_suffix(target.suffix + '.part')
        if partial.exists():
            partial.unlink()
        with requests.get(str(expected['url']), stream=True, timeout=120) as response:
            response.raise_for_status()
            with partial.open('wb') as fh:
                for block in response.iter_content(chunk_size=1024 * 1024):
                    if block:
                        fh.write(block)
        check = verify_file(partial, expected)
        if not check.get('hashes_match'):
            partial.unlink(missing_ok=True)
            raise RuntimeError(f'downloaded file fails frozen hash verification: {name}')
        if target.exists():
            target.unlink()
        partial.replace(target)
    report = verify_existing(root)
    if not report['all_hashes_match']:
        raise RuntimeError('one or more P2P files failed final verification')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description='Download and verify the version-pinned P2P OCEL 2.0 files used by SSCV.')
    parser.add_argument('--dest', default=str(DEFAULT_DEST))
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--overwrite-bad', action='store_true')
    args = parser.parse_args()
    report = verify_existing(args.dest) if args.verify_only else download(args.dest, overwrite_bad=args.overwrite_bad)
    print(json.dumps(report, indent=2))
    return 0 if report['all_hashes_match'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
