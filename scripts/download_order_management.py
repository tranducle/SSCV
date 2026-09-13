from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import urllib.request
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
URL = 'https://zenodo.org/api/records/8428112/files/order-management.sqlite/content'
EXPECTED_BYTES = 30601216
EXPECTED_MD5 = '4635d8689ce03687866210afa41457b2'
EXPECTED_SHA256 = '4b624713ba4c81c0e098fa1c7cc770bccee5d7d1864e35908661d765cbfce0ac'
DEFAULT_TARGET = REPO_ROOT / 'data' / 'raw' / 'order_management' / 'order-management.sqlite'


def _digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {'path': str(path), 'valid': False, 'reason': 'missing'}
    size = path.stat().st_size
    md5 = _digest(path, 'md5')
    sha256 = _digest(path, 'sha256')
    return {
        'path': str(path),
        'bytes': size,
        'md5': md5,
        'sha256': sha256,
        'valid': size == EXPECTED_BYTES and md5 == EXPECTED_MD5 and sha256 == EXPECTED_SHA256,
    }


def download(target: str | Path = DEFAULT_TARGET) -> dict[str, Any]:
    target = Path(target)
    existing = verify_file(target)
    if existing.get('valid'):
        return existing
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + '.partial')
    if partial.exists():
        partial.unlink()
    urllib.request.urlretrieve(URL, partial)
    report = verify_file(partial)
    if not report.get('valid'):
        partial.unlink(missing_ok=True)
        raise RuntimeError(f'downloaded Order Management artifact failed pinned verification: {report}')
    partial.replace(target)
    return verify_file(target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Download or verify the version-pinned Order Management OCEL 2.0 SQLite file used by SSCV.'
    )
    parser.add_argument('--target', default=str(DEFAULT_TARGET))
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args(argv)
    report = verify_file(args.target) if args.verify_only else download(args.target)
    print(report)
    return 0 if report.get('valid') else 2


if __name__ == '__main__':
    raise SystemExit(main())
