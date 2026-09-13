from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from . import case_views as cvc
from . import completion_models as fb
from . import witness_validation as iwv
from . import order_management_comparators as comp
from . import smt_verifier as smt
CONTROL_ACTIVITY = 'create package'
ACTION_ACTIVITY = 'send package'
ORDER_TYPE = 'orders'
ITEM_TYPE = 'items'
PACKAGE_TYPE = 'packages'
CASE_RELATION = 'comprises'

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NORM = REPO_ROOT / 'data' / 'normalized' / 'order_management'
DEFAULT_SOURCE = REPO_ROOT / 'configs' / 'order_management'


@dataclass(frozen=True)
class OMIndex:
    events: dict[str, dict[str, Any]]
    object_types: dict[str, str]
    event_objects: dict[str, tuple[str, ...]]
    object_events: dict[str, tuple[str, ...]]
    relations: tuple[tuple[str, str, str], ...]
    order_items: dict[str, tuple[str, ...]]
    package_items: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class RObsAudit:
    stable_anchor_id: str
    anchor_event_id: str
    order_id: str
    package_id: str
    overlap_item_ids: tuple[str, ...]
    constructor_id: str
    source_execution: fb.SourceExecution
    underlying_execution_sha256: str
    view: Any
    spec: fb.Spec
    motif: fb.MissingControlMotif
    realized_b0: str
    same_timestamp_case_event_pairs: int


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def load_index(norm_root: str | Path = DEFAULT_NORM) -> OMIndex:
    root = Path(norm_root)
    event_rows = _read_jsonl(root / 'events.jsonl')
    object_rows = _read_jsonl(root / 'objects.jsonl')
    eo_rows = _read_jsonl(root / 'event_object.jsonl')
    oo_rows = _read_jsonl(root / 'object_object.jsonl')

    events = {str(row['event_id']): row for row in event_rows}
    object_types = {str(row['object_id']): str(row['object_type']) for row in object_rows}
    event_objects_tmp: dict[str, list[str]] = defaultdict(list)
    object_events_tmp: dict[str, list[str]] = defaultdict(list)
    for row in eo_rows:
        event_id = str(row['event_id'])
        object_id = str(row['object_id'])
        event_objects_tmp[event_id].append(object_id)
        object_events_tmp[object_id].append(event_id)

    relations: list[tuple[str, str, str]] = []
    order_items_tmp: dict[str, set[str]] = defaultdict(set)
    package_items_tmp: dict[str, set[str]] = defaultdict(set)
    for row in oo_rows:
        qualifier = str(row['qualifier'])
        left = str(row['source_object_id'])
        right = str(row['target_object_id'])
        relations.append((qualifier, left, right))
        if qualifier == 'comprises' and object_types.get(left) == ORDER_TYPE and object_types.get(right) == ITEM_TYPE:
            order_items_tmp[left].add(right)
        if qualifier == 'contains' and object_types.get(left) == PACKAGE_TYPE and object_types.get(right) == ITEM_TYPE:
            package_items_tmp[left].add(right)

    return OMIndex(
        events=events,
        object_types=object_types,
        event_objects={k: tuple(v) for k, v in event_objects_tmp.items()},
        object_events={k: tuple(v) for k, v in object_events_tmp.items()},
        relations=tuple(relations),
        order_items={k: tuple(sorted(v)) for k, v in order_items_tmp.items()},
        package_items={k: tuple(sorted(v)) for k, v in package_items_tmp.items()},
    )


def load_manifest(name: str, source_root: str | Path = DEFAULT_SOURCE) -> dict[str, Any]:
    return json.loads((Path(source_root) / name).read_text(encoding='utf-8-sig'))


def _canonical_source_execution(execution: fb.SourceExecution) -> tuple[Any, ...]:
    return (
        tuple(sorted((str(obj.object_id), str(obj.object_type)) for obj in execution.objects)),
        tuple(sorted((str(event.event_id), str(event.activity), event.actor, tuple(sorted(str(x) for x in event.object_ids))) for event in execution.events)),
        tuple(sorted(tuple(str(x) for x in relation) for relation in execution.relations)),
        tuple(str(x) for x in execution.order),
    )


def source_execution_sha256(execution: fb.SourceExecution) -> str:
    raw = json.dumps(_canonical_source_execution(execution), separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _anchor_items(index: OMIndex, anchor: dict[str, Any]) -> tuple[str, ...]:
    order_id = str(anchor['order_id'])
    package_id = str(anchor['package_id'])
    return tuple(sorted(set(index.order_items.get(order_id, ())).intersection(index.package_items.get(package_id, ()))))


def _source_execution(index: OMIndex, anchor: dict[str, Any]) -> fb.SourceExecution:
    order_id = str(anchor['order_id'])
    overlap_items = _anchor_items(index, anchor)
    if not overlap_items:
        raise ValueError(f"anchor has no frozen item overlap: {anchor['stable_anchor_id']}")
    core_objects = {order_id, *overlap_items}
    event_ids: set[str] = set()
    for object_id in core_objects:
        event_ids.update(index.object_events.get(object_id, ()))
    anchor_event_id = str(anchor['send_event_id'])
    if anchor_event_id not in event_ids:
        raise ValueError(f'anchor send event not in order-item neighborhood: {anchor_event_id}')

    object_ids = set(core_objects)
    for event_id in event_ids:
        object_ids.update(index.event_objects.get(event_id, ()))
    objects = tuple(
        fb.SourceObject(object_id, index.object_types[object_id])
        for object_id in sorted(object_ids)
    )
    events = tuple(
        fb.SourceEvent(
            event_id,
            str(index.events[event_id]['activity']),
            None,
            tuple(index.event_objects.get(event_id, ())),
        )
        for event_id in sorted(event_ids)
    )
    relations = tuple(
        relation
        for relation in index.relations
        if relation[1] in object_ids and relation[2] in object_ids
    )
    order = tuple(sorted(event_ids, key=lambda event_id: (str(index.events[event_id]['time']), event_id)))
    return fb.SourceExecution(events, objects, relations, order)


def _strict_realized_b0(index: OMIndex, anchor: dict[str, Any]) -> str:
    anchor_event_id = str(anchor['send_event_id'])
    package_id = str(anchor['package_id'])
    action = index.events.get(anchor_event_id)
    if action is None or str(action['activity']) != ACTION_ACTIVITY:
        return 'unknown'
    if package_id not in index.event_objects.get(anchor_event_id, ()):
        return 'unknown'
    anchor_time = str(action['time'])
    for event_id in index.object_events.get(package_id, ()):
        row = index.events[event_id]
        if str(row['activity']) == CONTROL_ACTIVITY and str(row['time']) < anchor_time:
            return 'safe'
    return 'violation'


def _case_tie_pairs(index: OMIndex, view: Any) -> int:
    by_case: dict[str, list[Any]] = defaultdict(list)
    for row in view.rows:
        by_case[str(row.case_id)].append(row)
    count = 0
    for rows in by_case.values():
        for i, left in enumerate(rows):
            left_time = str(index.events[str(left.event_id)]['time'])
            for right in rows[i + 1:]:
                if str(index.events[str(right.event_id)]['time']) == left_time:
                    count += 1
    return count


def build_r_obs_audit(index: OMIndex, anchor: dict[str, Any], constructor_id: str) -> RObsAudit:
    if constructor_id not in {'CV-D', 'CV-R1'}:
        raise ValueError(constructor_id)
    anchor_event_id = str(anchor['send_event_id'])
    order_id = str(anchor['order_id'])
    package_id = str(anchor['package_id'])
    overlap_items = _anchor_items(index, anchor)
    source_execution = _source_execution(index, anchor)
    if constructor_id == 'CV-D':
        constructor = cvc.CaseViewConstructor.cv_d(ORDER_TYPE)
    else:
        constructor = cvc.CaseViewConstructor.cv_r1(ORDER_TYPE, (CASE_RELATION,))
    view = cvc.flatten_with_constructor(source_execution, constructor)

    visible_ids = {str(row.event_id) for row in view.rows}
    event_map = {str(event.event_id): event for event in source_execution.events}
    binding_domains = []
    for event_id in sorted(visible_ids):
        package_ids = tuple(
            sorted(
                object_id
                for object_id in event_map[event_id].object_ids
                if index.object_types.get(str(object_id)) == PACKAGE_TYPE
            )
        )
        binding_domains.append((event_id, (package_ids,)))

    spec = fb.Spec(
        hidden_binding_domains=tuple(binding_domains),
        hidden_relation_domain=((),),
        optional_deleted_events=(),
    )
    motif = fb.MissingControlMotif(
        sensitive_activity=ACTION_ACTIVITY,
        control_activity=CONTROL_ACTIVITY,
        require_shared_hidden_object=True,
        control_must_be_before=True,
        required_hidden_relation=None,
        anchor_event_id=anchor_event_id,
    )
    return RObsAudit(
        stable_anchor_id=str(anchor['stable_anchor_id']),
        anchor_event_id=anchor_event_id,
        order_id=order_id,
        package_id=package_id,
        overlap_item_ids=overlap_items,
        constructor_id=constructor_id,
        source_execution=source_execution,
        underlying_execution_sha256=source_execution_sha256(source_execution),
        view=view,
        spec=spec,
        motif=motif,
        realized_b0=_strict_realized_b0(index, anchor),
        same_timestamp_case_event_pairs=_case_tie_pairs(index, view),
    )


def _labels(verdicts: tuple[bool, ...]) -> list[str]:
    return ['violation' if value else 'safe' for value in verdicts]


def run_anchor_view(index: OMIndex, anchor: dict[str, Any], constructor_id: str) -> dict[str, Any]:
    audit = build_r_obs_audit(index, anchor, constructor_id)
    start = time.perf_counter()
    result = smt.verify_smt(audit.view, audit.spec, audit.motif)
    elapsed = time.perf_counter() - start
    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            audit.view,
            audit.spec,
            audit.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(report.valid)
        witness_errors = list(report.errors)
        witness_objective = list(report.objective) if report.objective is not None else None
    return {
        'stable_anchor_id': audit.stable_anchor_id,
        'anchor_event_id': audit.anchor_event_id,
        'order_id': audit.order_id,
        'package_id': audit.package_id,
        'case_view': constructor_id,
        'overlap_item_count': len(audit.overlap_item_ids),
        'underlying_execution_sha256': audit.underlying_execution_sha256,
        'visible_event_count': len({row.event_id for row in audit.view.rows}),
        'same_timestamp_case_event_pairs': audit.same_timestamp_case_event_pairs,
        'b0': audit.realized_b0,
        'b1': comp.b1_anchor(audit.view, audit.anchor_event_id),
        'b2': comp.b2_anchor(audit.view, audit.anchor_event_id),
        'sscv_decision': result.decision,
        'sscv_verdicts': _labels(result.verdicts),
        'sscv_complete': bool(result.complete),
        'solver_statuses': list(result.solver_statuses),
        'unknown_reason': result.unknown_reason,
        'backend': result.backend,
        'runtime_seconds': elapsed,
        'witness_returned': result.witness is not None,
        'witness_valid': witness_valid,
        'witness_errors': witness_errors,
        'witness_objective': witness_objective,
        'witness_minimal_claimed': bool(result.witness is not None and result.witness.minimal),
    }


def run_anchor_manifest(index: OMIndex, manifest: dict[str, Any], limit: int | None = None) -> list[dict[str, Any]]:
    anchors = list(manifest.get('anchors', ()))
    if limit is not None:
        anchors = anchors[:limit]
    rows: list[dict[str, Any]] = []
    for anchor in anchors:
        for constructor_id in ('CV-D', 'CV-R1'):
            rows.append(run_anchor_view(index, anchor, constructor_id))
    return rows


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_view: dict[str, Any] = {}
    for view in ('CV-D', 'CV-R1'):
        selected = [row for row in rows if row['case_view'] == view]
        by_view[view] = {
            'row_count': len(selected),
            'decision_counts': dict(sorted(__import__('collections').Counter(row['sscv_decision'] for row in selected).items())),
            'b0_counts': dict(sorted(__import__('collections').Counter(row['b0'] for row in selected).items())),
            'b1_counts': dict(sorted(__import__('collections').Counter(row['b1'] for row in selected).items())),
            'b2_counts': dict(sorted(__import__('collections').Counter(row['b2'] for row in selected).items())),
            'witness_count': sum(bool(row['witness_returned']) for row in selected),
            'invalid_witness_count': sum(row['witness_valid'] is False for row in selected),
            'unknown_count': sum(row['sscv_decision'] == 'unknown' for row in selected),
        }
    paired: dict[str, dict[str, str]] = defaultdict(dict)
    for row in rows:
        paired[str(row['stable_anchor_id'])][str(row['case_view'])] = str(row['sscv_decision'])
    transitions: dict[str, int] = defaultdict(int)
    for pair in paired.values():
        if {'CV-D', 'CV-R1'} <= set(pair):
            transitions[f"{pair['CV-D']}->{pair['CV-R1']}"] += 1
    return {
        'row_count': len(rows),
        'anchor_count': len(paired),
        'decision_counts': dict(sorted(__import__('collections').Counter(row['sscv_decision'] for row in rows).items())),
        'paired_view_transition_counts': dict(sorted(transitions.items())),
        'by_case_view': by_view,
    }
