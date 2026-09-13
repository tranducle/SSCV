from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / 'data' / 'raw' / 'p2p'
RAW_JSON = SOURCE_ROOT / 'ocel2-p2p.json'
DEFAULT_OUT = REPO_ROOT / 'data' / 'normalized' / 'p2p'
PROBLEM_QUALIFIERS = {
    'Invoice Receipt of Goods Receipt',
    'Invoice Receipts of Purchase Order',
}


def _load() -> dict[str, Any]:
    return json.loads(RAW_JSON.read_text(encoding='utf-8'))


def _norm_time(value: str) -> str:
    dt = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
    return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _canon_attrs(attrs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for attr in attrs:
        row = {'name': attr.get('name'), 'value': attr.get('value')}
        if attr.get('time') is not None:
            row['time'] = _norm_time(str(attr['time']))
        rows.append(row)
    rows.sort(key=lambda x: (str(x.get('name')), str(x.get('time', '')), json.dumps(x.get('value'), sort_keys=True, ensure_ascii=False)))
    return rows


def build_normalized_bundle() -> dict[str, list[dict[str, Any]]]:
    data = _load()
    object_ids = {str(obj['id']) for obj in data['objects']}

    events = []
    event_object = []
    for event in data['events']:
        attrs = {str(a.get('name')): a.get('value') for a in event.get('attributes', [])}
        events.append({
            'event_id': str(event['id']),
            'activity': str(event['type']),
            'time': _norm_time(str(event['time'])),
            'resource': attrs.get('resource'),
            'lifecycle': attrs.get('lifecycle'),
            'attributes': _canon_attrs(list(event.get('attributes', []))),
        })
        for rel in event.get('relationships', []):
            event_object.append({
                'event_id': str(event['id']),
                'object_id': str(rel['objectId']),
                'qualifier': str(rel.get('qualifier', '')),
            })

    objects = []
    object_object = []
    excluded = []
    for obj in data['objects']:
        oid = str(obj['id'])
        objects.append({
            'object_id': oid,
            'object_type': str(obj['type']),
            'attributes': _canon_attrs(list(obj.get('attributes', []))),
        })
        for rel in obj.get('relationships', []):
            target = str(rel['objectId'])
            qualifier = str(rel.get('qualifier', ''))
            base = {
                'source_object_id': oid,
                'target_object_id': target,
                'qualifier': qualifier,
            }
            if target not in object_ids:
                excluded.append({
                    **base,
                    'exclusion_reason': 'dangling_target_not_in_source_object_table',
                    'admissible_for_sscv': False,
                })
            else:
                object_object.append({
                    **base,
                    'admissible_for_sscv': qualifier not in PROBLEM_QUALIFIERS,
                })

    events.sort(key=lambda r: r['event_id'].encode('utf-8'))
    objects.sort(key=lambda r: r['object_id'].encode('utf-8'))
    event_object.sort(key=lambda r: (r['event_id'], r['object_id'], r['qualifier']))
    object_object.sort(key=lambda r: (r['source_object_id'], r['target_object_id'], r['qualifier']))
    excluded.sort(key=lambda r: (r['source_object_id'], r['target_object_id'], r['qualifier']))

    time_counts = Counter(row['time'] for row in events)
    order_rows = []
    for serialization_rank, row in enumerate(sorted(events, key=lambda r: (r['time'], r['event_id'])), 1):
        order_rows.append({
            'event_id': row['event_id'],
            'time': row['time'],
            'serialization_rank': serialization_rank,
            'tie_group_size': time_counts[row['time']],
            'strict_precedence_rule': 'earlier_timestamp_only',
        })

    return {
        'events': events,
        'objects': objects,
        'event_object': event_object,
        'object_object': object_object,
        'excluded_invalid_object_object': excluded,
        'event_order': order_rows,
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open('w', encoding='utf-8', newline='\n') as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
            f.write('\n')


def write_normalized(out_dir: Path = DEFAULT_OUT) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = build_normalized_bundle()
    filenames = {
        'events': 'events.jsonl',
        'objects': 'objects.jsonl',
        'event_object': 'event_object.jsonl',
        'object_object': 'object_object.jsonl',
        'excluded_invalid_object_object': 'excluded_invalid_object_object.jsonl',
        'event_order': 'event_order.jsonl',
    }
    for key, name in filenames.items():
        _write_jsonl(out_dir / name, bundle[key])

    field_map = {
        'version': 'P2P_G1_FIELD_MAP_V1_2',
        'event': {'id': 'event_id', 'type': 'activity', 'time': 'time', 'attributes.resource': 'resource', 'attributes.lifecycle': 'lifecycle'},
        'object': {'id': 'object_id', 'type': 'object_type', 'attributes': 'attributes'},
        'event_relationship': {'event.id': 'event_id', 'relationships.objectId': 'object_id', 'relationships.qualifier': 'qualifier'},
        'object_relationship': {'object.id': 'source_object_id', 'relationships.objectId': 'target_object_id', 'relationships.qualifier': 'qualifier'},
        'temporal_semantics': 'strict precedence iff timestamp is strictly earlier; equal timestamp means no semantic precedence; event_id tie order is serialization only',
        'admissibility_policy': {'problem_qualifiers': sorted(PROBLEM_QUALIFIERS), 'dangling_targets': 'excluded and logged, never imputed'},
    }
    (out_dir / 'source_field_mapping.json').write_text(json.dumps(field_map, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

    output_files = [*filenames.values(), 'source_field_mapping.json']
    output_hashes = {name: _sha256(out_dir / name) for name in output_files}
    counts = {key: len(rows) for key, rows in bundle.items()}
    log = {
        'version': 'P2P_G1_NORMALIZATION_LOG_V1_2',
        'source_record': '10.5281/zenodo.8412920',
        'input_json_sha256': _sha256(RAW_JSON),
        'pre_counts': {'events': 14671, 'objects': 9543, 'event_object': 35927, 'object_object': 20402},
        'post_counts': counts,
        'admissible_object_object': sum(1 for r in bundle['object_object'] if r['admissible_for_sscv']),
        'nonadmissible_valid_object_object': sum(1 for r in bundle['object_object'] if not r['admissible_for_sscv']),
        'excluded_invalid_object_object': len(bundle['excluded_invalid_object_object']),
        'output_sha256': output_hashes,
        'outcome_blind': True,
        'policy': 'No source fact is invented. Invalid target relations are isolated. Problem qualifier families are retained when endpoints resolve but marked nonadmissible for SSCV.',
    }
    (out_dir / 'normalization_log.json').write_text(json.dumps(log, indent=2) + '\n', encoding='utf-8')
    log['normalization_log_sha256'] = _sha256(out_dir / 'normalization_log.json')
    return log


def main() -> int:
    report = write_normalized(DEFAULT_OUT)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
