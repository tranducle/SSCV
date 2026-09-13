from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
from sscv import order_management_raw as source

DEFAULT_OUT = REPO_ROOT / 'data' / 'normalized' / 'order_management'


def build_normalized_bundle(sqlite_path: str | Path = source.DEFAULT_SQLITE) -> dict[str, list[dict[str, Any]]]:
    index = source.load_index(sqlite_path)

    events = [
        {
            'event_id': event_id,
            'activity': str(row['activity']),
            'time': str(row['time']),
            'resource': None,
        }
        for event_id, row in index.events.items()
    ]
    events.sort(key=lambda row: row['event_id'].encode('utf-8'))

    objects = [
        {'object_id': object_id, 'object_type': object_type}
        for object_id, object_type in index.object_types.items()
    ]
    objects.sort(key=lambda row: row['object_id'].encode('utf-8'))

    event_object: list[dict[str, Any]] = []
    for event_id, relationships in index.event_object_qualifiers.items():
        for object_id, qualifier in relationships:
            event_object.append(
                {
                    'event_id': event_id,
                    'object_id': object_id,
                    'qualifier': qualifier,
                }
            )
    event_object.sort(key=lambda row: (row['event_id'], row['object_id'], row['qualifier']))

    object_object = [
        {
            'source_object_id': left,
            'target_object_id': right,
            'qualifier': qualifier,
            'admissible_for_sscv': True,
        }
        for qualifier, left, right in index.object_relations
    ]
    object_object.sort(
        key=lambda row: (row['source_object_id'], row['target_object_id'], row['qualifier'])
    )

    time_counts = Counter(row['time'] for row in events)
    event_order = []
    for rank, row in enumerate(sorted(events, key=lambda item: (item['time'], item['event_id'])), 1):
        event_order.append(
            {
                'event_id': row['event_id'],
                'time': row['time'],
                'serialization_rank': rank,
                'tie_group_size': time_counts[row['time']],
                'strict_precedence_rule': 'earlier_timestamp_only',
            }
        )

    return {
        'events': events,
        'objects': objects,
        'event_object': event_object,
        'object_object': object_object,
        'event_order': event_order,
    }


def bundle_digest(bundle: dict[str, list[dict[str, Any]]]) -> str:
    canonical = json.dumps(
        bundle,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open('w', encoding='utf-8', newline='\n') as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
            handle.write('\n')


def write_normalized(out_dir: str | Path = DEFAULT_OUT) -> dict[str, Any]:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    bundle = build_normalized_bundle()
    filenames = {
        'events': 'events.jsonl',
        'objects': 'objects.jsonl',
        'event_object': 'event_object.jsonl',
        'object_object': 'object_object.jsonl',
        'event_order': 'event_order.jsonl',
    }
    for key, filename in filenames.items():
        _write_jsonl(root / filename, bundle[key])

    field_map = {
        'version': 'OM_G1_FIELD_MAP_V1_1',
        'source': '10.5281/zenodo.8428112',
        'event': {'ocel_id': 'event_id', 'ocel_type': 'activity', 'typed_event_table.ocel_time': 'time'},
        'object': {'ocel_id': 'object_id', 'ocel_type': 'object_type'},
        'event_relationship': {
            'ocel_event_id': 'event_id',
            'ocel_object_id': 'object_id',
            'ocel_qualifier': 'qualifier',
        },
        'object_relationship': {
            'ocel_source_id': 'source_object_id',
            'ocel_target_id': 'target_object_id',
            'ocel_qualifier': 'qualifier',
        },
        'temporal_semantics': 'strict precedence iff timestamp is strictly earlier; equal timestamp means no semantic precedence; event_id tie order is serialization only',
        'resource_policy': 'no event-level resource field is normalized because the M2 mapping does not use actor semantics; employee objects and qualifiers remain in relationship tables',
    }
    (root / 'source_field_mapping.json').write_text(
        json.dumps(field_map, indent=2, ensure_ascii=False) + '\n', encoding='utf-8'
    )

    output_files = [*filenames.values(), 'source_field_mapping.json']
    output_hashes = {filename: _sha256(root / filename) for filename in output_files}
    counts = {key: len(rows) for key, rows in bundle.items()}
    log = {
        'version': 'OM_G1_NORMALIZATION_LOG_V1_1',
        'source_record': '10.5281/zenodo.8428112',
        'input_sqlite_sha256': _sha256(source.DEFAULT_SQLITE),
        'pre_counts': {
            'events': 21008,
            'objects': 10840,
            'event_object': 147463,
            'object_object': 28391,
        },
        'post_counts': counts,
        'bundle_sha256': bundle_digest(bundle),
        'output_sha256': output_hashes,
        'outcome_blind': True,
        'policy': 'No source fact is invented or imputed. All source relationships resolve in the version-pinned Zenodo artifact.',
    }
    (root / 'normalization_log.json').write_text(
        json.dumps(log, indent=2) + '\n', encoding='utf-8'
    )
    log['normalization_log_sha256'] = _sha256(root / 'normalization_log.json')
    return log


def main() -> int:
    print(json.dumps(write_normalized(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
