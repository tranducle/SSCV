from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from . import case_views as cvc
from . import completion_models as fb
from . import witness_validation as iwv
from . import order_management_base as legacy_source
from . import smt_verifier as smt
CONTROL_ACTIVITY = 'pick item'
ACTION_ACTIVITY = 'send package'
PACKAGE_TYPE = 'packages'
ITEM_TYPE = 'items'
CASE_RELATION = 'contains'

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NORM = REPO_ROOT / 'data' / 'normalized' / 'order_management'
DEFAULT_SOURCE = REPO_ROOT / 'configs' / 'order_management'


@dataclass(frozen=True)
class RObsAudit:
    stable_anchor_id: str
    anchor_event_id: str
    package_id: str
    item_ids: tuple[str, ...]
    control_event_ids: tuple[str, ...]
    constructor_id: str
    source_execution: fb.SourceExecution
    underlying_execution_sha256: str
    view: Any
    spec: fb.Spec
    motif: fb.MissingControlMotif
    realized_b0: str


def load_index(norm_root: str | Path = DEFAULT_NORM):
    return legacy_source.load_index(norm_root)


def load_manifest(name: str, source_root: str | Path = DEFAULT_SOURCE) -> dict[str, Any]:
    return json.loads((Path(source_root) / name).read_text(encoding='utf-8-sig'))


def _canonical_source_execution(execution: fb.SourceExecution) -> tuple[Any, ...]:
    return legacy_source._canonical_source_execution(execution)


def source_execution_sha256(execution: fb.SourceExecution) -> str:
    raw = json.dumps(_canonical_source_execution(execution), separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _pick_events_for_items(index: Any, item_ids: tuple[str, ...]) -> tuple[str, ...]:
    result: set[str] = set()
    for item_id in item_ids:
        candidates = [
            str(event_id)
            for event_id in index.object_events.get(item_id, ())
            if str(index.events[event_id]['activity']) == CONTROL_ACTIVITY
        ]
        if len(candidates) != 1:
            raise ValueError(f'expected exactly one pick event for {item_id}, got {candidates}')
        result.add(candidates[0])
    return tuple(sorted(result))


def _source_execution(index: Any, anchor: dict[str, Any]) -> tuple[fb.SourceExecution, tuple[str, ...], tuple[str, ...]]:
    package_id = str(anchor['package_id'])
    anchor_event_id = str(anchor['send_event_id'])
    item_ids = tuple(index.package_items.get(package_id, ()))
    if not item_ids:
        raise ValueError(f'package has no contained items: {package_id}')
    if anchor_event_id not in index.events or str(index.events[anchor_event_id]['activity']) != ACTION_ACTIVITY:
        raise ValueError(f'invalid send anchor: {anchor_event_id}')
    if package_id not in index.event_objects.get(anchor_event_id, ()):
        raise ValueError(f'send anchor not directly bound to package: {anchor_event_id}')
    control_ids = _pick_events_for_items(index, item_ids)
    event_ids = (anchor_event_id,) + control_ids
    object_ids = {package_id, *item_ids}
    objects = tuple(fb.SourceObject(object_id, index.object_types[object_id]) for object_id in sorted(object_ids))
    events = []
    for event_id in event_ids:
        relevant = tuple(sorted(set(index.event_objects.get(event_id, ())).intersection(object_ids)))
        events.append(
            fb.SourceEvent(
                event_id=str(event_id),
                activity=str(index.events[event_id]['activity']),
                actor=None,
                object_ids=relevant,
            )
        )
    relations = tuple(
        sorted(
            (qualifier, left, right)
            for qualifier, left, right in index.relations
            if qualifier == CASE_RELATION and left == package_id and right in set(item_ids)
        )
    )
    if len(relations) != len(item_ids):
        raise ValueError(f'contains relation mismatch for {package_id}: {len(relations)} vs {len(item_ids)}')
    order = tuple(sorted(event_ids, key=lambda event_id: (str(index.events[event_id]['time']), str(event_id))))
    execution = fb.SourceExecution(tuple(events), objects, relations, order)
    return execution, item_ids, control_ids


def _strict_realized_b0(index: Any, anchor: dict[str, Any], item_ids: tuple[str, ...], control_ids: tuple[str, ...]) -> str:
    anchor_id = str(anchor['send_event_id'])
    anchor_time = str(index.events[anchor_id]['time'])
    item_set = set(item_ids)
    for event_id in control_ids:
        row = index.events[event_id]
        bound_items = item_set.intersection(index.event_objects.get(event_id, ()))
        if bound_items and str(row['time']) < anchor_time:
            return 'safe'
    return 'violation'


def _constructor(constructor_id: str):
    if constructor_id == 'CV-D':
        return cvc.CaseViewConstructor.cv_d(PACKAGE_TYPE)
    if constructor_id == 'CV-R1':
        return cvc.CaseViewConstructor.cv_r1(PACKAGE_TYPE, (CASE_RELATION,))
    raise ValueError(constructor_id)


def build_r_obs_audit(index: Any, anchor: dict[str, Any], constructor_id: str) -> RObsAudit:
    execution, item_ids, control_ids = _source_execution(index, anchor)
    constructor = _constructor(constructor_id)
    view = cvc.flatten_with_constructor(execution, constructor)
    anchor_id = str(anchor['send_event_id'])
    package_id = str(anchor['package_id'])
    package_rows = [row for row in view.rows if str(row.case_id) == package_id]
    if anchor_id not in {str(row.event_id) for row in package_rows}:
        raise ValueError(f'V2 invariant violated: anchor absent from {constructor_id}: {anchor_id}')

    visible_ids = {str(row.event_id) for row in view.rows}
    item_set = set(item_ids)
    binding_domains = []
    event_map = {str(event.event_id): event for event in execution.events}
    for event_id in sorted(visible_ids):
        relevant_items = tuple(sorted(item_set.intersection(event_map[event_id].object_ids)))
        if event_id == anchor_id or str(event_map[event_id].activity) == CONTROL_ACTIVITY:
            if not relevant_items:
                raise ValueError(f'motif-relevant visible event lacks item binding: {event_id}')
            binding_domains.append((event_id, (relevant_items,)))

    deleted = []
    for event_id in control_ids:
        if event_id in visible_ids:
            continue
        event = event_map[event_id]
        relevant_items = tuple(sorted(item_set.intersection(event.object_ids)))
        if len(relevant_items) != 1:
            raise ValueError(f'pick event must bind exactly one contained item: {event_id}')
        deleted.append(
            fb.DeletedEventTemplate(
                fb.Event(
                    event_id=event_id,
                    activity=CONTROL_ACTIVITY,
                    actor=None,
                    case_ids=(),
                    hidden_objects=relevant_items,
                )
            )
        )

    spec = fb.Spec(
        hidden_binding_domains=tuple(binding_domains),
        hidden_relation_domain=((),),
        optional_deleted_events=tuple(deleted),
        reference_order=tuple(str(event_id) for event_id in execution.order),
        order_free_pairs=(),
    )
    motif = fb.MissingControlMotif(
        sensitive_activity=ACTION_ACTIVITY,
        control_activity=CONTROL_ACTIVITY,
        require_shared_hidden_object=True,
        control_must_be_before=True,
        required_hidden_relation=None,
        anchor_event_id=anchor_id,
    )
    return RObsAudit(
        stable_anchor_id=str(anchor['stable_anchor_id']),
        anchor_event_id=anchor_id,
        package_id=package_id,
        item_ids=item_ids,
        control_event_ids=control_ids,
        constructor_id=constructor_id,
        source_execution=execution,
        underlying_execution_sha256=source_execution_sha256(execution),
        view=view,
        spec=spec,
        motif=motif,
        realized_b0=_strict_realized_b0(index, anchor, item_ids, control_ids),
    )


def _rows_by_case(view: Any) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for row in view.rows:
        grouped.setdefault(str(row.case_id), []).append(row)
    for rows in grouped.values():
        rows.sort(key=lambda row: (int(row.rank), str(row.event_id)))
    return grouped


def _find_anchor(view: Any, anchor_event_id: str) -> tuple[str, Any] | None:
    matches = []
    for case_id, rows in _rows_by_case(view).items():
        for row in rows:
            if str(row.event_id) == str(anchor_event_id) and str(row.activity) == ACTION_ACTIVITY:
                matches.append((case_id, row))
    if not matches:
        return None
    matches.sort(key=lambda item: (item[0], int(item[1].rank)))
    return matches[0]


def b1_anchor(view: Any, anchor_event_id: str) -> str:
    found = _find_anchor(view, anchor_event_id)
    if found is None:
        return 'unknown'
    case_id, action = found
    rows = _rows_by_case(view)[case_id]
    protected = any(str(row.activity) == CONTROL_ACTIVITY and int(row.rank) < int(action.rank) for row in rows)
    return 'safe' if protected else 'violation'


def b2_anchor(view: Any, anchor_event_id: str) -> str:
    found = _find_anchor(view, anchor_event_id)
    if found is None:
        return 'unknown'
    case_id, action = found
    rows = _rows_by_case(view)[case_id]
    protected = any(str(row.activity) == CONTROL_ACTIVITY and int(row.rank) < int(action.rank) for row in rows)
    return 'safe' if protected else 'unknown'


def run_anchor_view(index: Any, anchor: dict[str, Any], constructor_id: str) -> dict[str, Any]:
    audit = build_r_obs_audit(index, anchor, constructor_id)
    start = time.perf_counter()
    result = smt.verify_smt(audit.view, audit.spec, audit.motif, query_order=('safe', 'violation'))
    elapsed = time.perf_counter() - start
    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        validation = iwv.validate_witness(
            audit.view,
            audit.spec,
            audit.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(validation.valid)
        witness_errors = list(validation.errors)
        witness_objective = list(validation.objective) if validation.objective is not None else None
    return {
        'stable_anchor_id': audit.stable_anchor_id,
        'anchor_event_id': audit.anchor_event_id,
        'package_id': audit.package_id,
        'case_view': constructor_id,
        'contained_item_count': len(audit.item_ids),
        'control_event_count': len(audit.control_event_ids),
        'underlying_execution_sha256': audit.underlying_execution_sha256,
        'visible_event_count': len({str(row.event_id) for row in audit.view.rows if str(row.case_id) == audit.package_id}),
        'optional_hidden_control_count': len(audit.spec.optional_deleted_events),
        'b0': audit.realized_b0,
        'b1': b1_anchor(audit.view, audit.anchor_event_id),
        'b2': b2_anchor(audit.view, audit.anchor_event_id),
        'sscv_decision': result.decision,
        'sscv_verdicts': ['violation' if value else 'safe' for value in result.verdicts],
        'sscv_complete': bool(result.complete),
        'solver_statuses': list(result.solver_statuses),
        'unknown_reason': result.unknown_reason,
        'runtime_seconds': elapsed,
        'witness_returned': result.witness is not None,
        'witness_valid': witness_valid,
        'witness_errors': witness_errors,
        'witness_objective': witness_objective,
        'witness_minimal_claimed': bool(result.witness is not None and result.witness.minimal),
        'backend': result.backend,
    }
