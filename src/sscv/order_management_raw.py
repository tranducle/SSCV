from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE = REPO_ROOT / 'data' / 'raw' / 'order_management' / 'order-management.sqlite'


@dataclass(frozen=True)
class OMIndex:
    events: dict[str, dict[str, Any]]
    object_types: dict[str, str]
    event_objects: dict[str, tuple[str, ...]]
    event_object_qualifiers: dict[str, tuple[tuple[str, str], ...]]
    object_events: dict[str, tuple[str, ...]]
    object_relations: tuple[tuple[str, str, str], ...]
    relation_type_counts: Counter
    dangling_event_object_count: int
    dangling_object_object_count: int


def _table_rows(cur: sqlite3.Cursor, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return list(cur.execute(query, params))


def load_index(sqlite_path: str | Path = DEFAULT_SQLITE) -> OMIndex:
    path = Path(sqlite_path)
    con = sqlite3.connect(path)
    cur = con.cursor()
    try:
        type_map = dict(_table_rows(cur, 'select ocel_type, ocel_type_map from event_map_type'))
        event_times: dict[str, str] = {}
        for activity, mapped in type_map.items():
            table = f'event_{mapped}'
            for event_id, event_time in _table_rows(cur, f'select ocel_id, ocel_time from "{table}"'):
                event_times[str(event_id)] = str(event_time)

        events = {
            str(event_id): {
                'event_id': str(event_id),
                'activity': str(activity),
                'time': event_times[str(event_id)],
            }
            for event_id, activity in _table_rows(cur, 'select ocel_id, ocel_type from event')
        }
        object_types = {
            str(object_id): str(object_type)
            for object_id, object_type in _table_rows(cur, 'select ocel_id, ocel_type from object')
        }

        event_objects_tmp: dict[str, list[str]] = defaultdict(list)
        event_qual_tmp: dict[str, list[tuple[str, str]]] = defaultdict(list)
        object_events_tmp: dict[str, list[str]] = defaultdict(list)
        dangling_event_object_count = 0
        for event_id, object_id, qualifier in _table_rows(
            cur,
            'select ocel_event_id, ocel_object_id, ocel_qualifier from event_object',
        ):
            event_id = str(event_id)
            object_id = str(object_id)
            if event_id not in events or object_id not in object_types:
                dangling_event_object_count += 1
                continue
            event_objects_tmp[event_id].append(object_id)
            event_qual_tmp[event_id].append((object_id, str(qualifier)))
            object_events_tmp[object_id].append(event_id)

        relations: list[tuple[str, str, str]] = []
        relation_type_counts: Counter = Counter()
        dangling_object_object_count = 0
        for source, target, qualifier in _table_rows(
            cur,
            'select ocel_source_id, ocel_target_id, ocel_qualifier from object_object',
        ):
            source = str(source)
            target = str(target)
            qualifier = str(qualifier)
            if source not in object_types or target not in object_types:
                dangling_object_object_count += 1
                continue
            relations.append((qualifier, source, target))
            relation_type_counts[(qualifier, object_types[source], object_types[target])] += 1

        return OMIndex(
            events=events,
            object_types=object_types,
            event_objects={k: tuple(v) for k, v in event_objects_tmp.items()},
            event_object_qualifiers={k: tuple(v) for k, v in event_qual_tmp.items()},
            object_events={k: tuple(v) for k, v in object_events_tmp.items()},
            object_relations=tuple(relations),
            relation_type_counts=relation_type_counts,
            dangling_event_object_count=dangling_event_object_count,
            dangling_object_object_count=dangling_object_object_count,
        )
    finally:
        con.close()


def _objects_for_event_with_qualifier(index: OMIndex, event_id: str, qualifier: str) -> tuple[str, ...]:
    return tuple(
        object_id
        for object_id, current in index.event_object_qualifiers.get(event_id, ())
        if current == qualifier
    )


def package_lifecycle_report(index: OMIndex) -> dict[str, int]:
    creates: dict[str, list[str]] = defaultdict(list)
    sends: dict[str, list[str]] = defaultdict(list)
    for event_id, row in index.events.items():
        activity = row['activity']
        if activity == 'create package':
            for package_id in _objects_for_event_with_qualifier(index, event_id, 'creates'):
                creates[package_id].append(event_id)
        elif activity == 'send package':
            for package_id in _objects_for_event_with_qualifier(index, event_id, 'shipped package'):
                sends[package_id].append(event_id)

    packages = sorted(set(creates) | set(sends))
    exactly_one_create = sum(len(creates.get(package_id, ())) == 1 for package_id in packages)
    exactly_one_send = sum(len(sends.get(package_id, ())) == 1 for package_id in packages)
    earlier = equal = reversed_count = 0
    for package_id in packages:
        if len(creates.get(package_id, ())) != 1 or len(sends.get(package_id, ())) != 1:
            continue
        c = creates[package_id][0]
        s = sends[package_id][0]
        ct = str(index.events[c]['time'])
        st = str(index.events[s]['time'])
        if ct < st:
            earlier += 1
        elif ct == st:
            equal += 1
        else:
            reversed_count += 1
    return {
        'package_count': len(packages),
        'exactly_one_create_count': exactly_one_create,
        'exactly_one_send_count': exactly_one_send,
        'create_strictly_before_send_count': earlier,
        'equal_timestamp_count': equal,
        'send_before_create_count': reversed_count,
    }


def build_candidate_anchors(index: OMIndex) -> list[dict[str, Any]]:
    package_items: dict[str, set[str]] = defaultdict(set)
    item_orders: dict[str, set[str]] = defaultdict(set)
    for qualifier, source, target in index.object_relations:
        if qualifier == 'contains' and index.object_types.get(source) == 'packages' and index.object_types.get(target) == 'items':
            package_items[source].add(target)
        elif qualifier == 'comprises' and index.object_types.get(source) == 'orders' and index.object_types.get(target) == 'items':
            item_orders[target].add(source)

    rows: list[dict[str, Any]] = []
    for event_id, event in index.events.items():
        if event['activity'] != 'send package':
            continue
        packages = _objects_for_event_with_qualifier(index, event_id, 'shipped package')
        for package_id in packages:
            overlap_by_order: Counter = Counter()
            for item_id in package_items.get(package_id, ()):
                for order_id in item_orders.get(item_id, ()):
                    overlap_by_order[order_id] += 1
            for order_id, overlap in overlap_by_order.items():
                rows.append(
                    {
                        'stable_anchor_id': f'{event_id}|{order_id}',
                        'send_event_id': event_id,
                        'package_id': package_id,
                        'order_id': order_id,
                        'item_overlap_count': int(overlap),
                    }
                )
    rows.sort(key=lambda row: row['stable_anchor_id'].encode('utf-8'))
    return rows


def deterministic_sample(rows: list[dict[str, Any]], n: int, domain: str) -> list[dict[str, Any]]:
    if n < 0 or n > len(rows):
        raise ValueError('sample size outside population')
    ranked = sorted(
        rows,
        key=lambda row: (
            hashlib.sha256(f"{domain}|{row['stable_anchor_id']}".encode('utf-8')).digest(),
            row['stable_anchor_id'],
        ),
    )
    return [dict(row) for row in ranked[:n]]
