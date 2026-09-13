from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any

from . import case_views as cvc
from . import completion_models as fb
from . import witness_validation as iwv
from . import p2p_comparators as acomp
from . import smt_verifier as smt
CONTROL_ACTIVITY = 'Approve Purchase Requisition'
ACTION_ACTIVITY = 'Create Purchase Order'
PR_TYPE = 'purchase_requisition'
QUOTATION_TYPE = 'quotation'
SOURCE_RELATION = 'Quotation of PR'
INTERNAL_RELATION = 'linked'

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NORM = REPO_ROOT / 'data' / 'normalized' / 'p2p'
DEFAULT_SOURCE = REPO_ROOT / 'configs' / 'p2p'


@dataclass(frozen=True)
class P2PIndex:
    events: dict[str, dict[str, Any]]
    object_types: dict[str, str]
    event_objects: dict[str, tuple[str, ...]]
    object_events: dict[str, tuple[str, ...]]
    admissible_relations: tuple[tuple[str, str, str], ...]
    linked_pr_by_quotation: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class RObsAudit:
    stable_anchor_id: str
    anchor_event_id: str
    quotation_id: str
    constructor_id: str
    linked_pr_ids: tuple[str, ...]
    source_execution: fb.SourceExecution
    view: Any
    spec: fb.Spec
    motif: fb.MissingControlMotif
    realized_b0: str
    same_timestamp_case_event_pairs: int


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def load_index(norm_root: str | Path = DEFAULT_NORM) -> P2PIndex:
    root = Path(norm_root)
    event_rows = _read_jsonl(root / 'events.jsonl')
    object_rows = _read_jsonl(root / 'objects.jsonl')
    event_object_rows = _read_jsonl(root / 'event_object.jsonl')
    relation_rows = _read_jsonl(root / 'object_object.jsonl')

    events = {str(row['event_id']): row for row in event_rows}
    object_types = {str(row['object_id']): str(row['object_type']) for row in object_rows}
    event_objects_tmp: dict[str, list[str]] = defaultdict(list)
    object_events_tmp: dict[str, list[str]] = defaultdict(list)
    for row in event_object_rows:
        event_id = str(row['event_id'])
        object_id = str(row['object_id'])
        event_objects_tmp[event_id].append(object_id)
        object_events_tmp[object_id].append(event_id)
    event_objects = {k: tuple(v) for k, v in event_objects_tmp.items()}
    object_events = {k: tuple(v) for k, v in object_events_tmp.items()}

    admissible: list[tuple[str, str, str]] = []
    pr_by_q: dict[str, set[str]] = defaultdict(set)
    for row in relation_rows:
        if not row.get('admissible_for_sscv', False):
            continue
        qualifier = str(row['qualifier'])
        left = str(row['source_object_id'])
        right = str(row['target_object_id'])
        admissible.append((qualifier, left, right))
        if qualifier != SOURCE_RELATION:
            continue
        if object_types.get(left) == PR_TYPE and object_types.get(right) == QUOTATION_TYPE:
            pr_by_q[right].add(left)
        elif object_types.get(right) == PR_TYPE and object_types.get(left) == QUOTATION_TYPE:
            pr_by_q[left].add(right)

    return P2PIndex(
        events=events,
        object_types=object_types,
        event_objects=event_objects,
        object_events=object_events,
        admissible_relations=tuple(admissible),
        linked_pr_by_quotation={k: tuple(sorted(v)) for k, v in pr_by_q.items()},
    )


def load_manifest(name: str, source_root: str | Path = DEFAULT_SOURCE) -> dict[str, Any]:
    return json.loads((Path(source_root) / name).read_text(encoding='utf-8'))


def _neighborhood_event_ids(index: P2PIndex, quotation_id: str, pr_ids: tuple[str, ...]) -> tuple[str, ...]:
    core = (quotation_id,) + tuple(pr_ids)
    ids: set[str] = set()
    for object_id in core:
        ids.update(index.object_events.get(object_id, ()))
    return tuple(sorted(ids))


def _source_execution(index: P2PIndex, quotation_id: str, pr_ids: tuple[str, ...]) -> fb.SourceExecution:
    event_ids = _neighborhood_event_ids(index, quotation_id, pr_ids)
    object_ids: set[str] = {quotation_id, *pr_ids}
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
            index.events[event_id].get('resource'),
            tuple(index.event_objects.get(event_id, ())),
        )
        for event_id in event_ids
    )
    relations = tuple(
        relation
        for relation in index.admissible_relations
        if relation[1] in object_ids and relation[2] in object_ids
    )
    order = tuple(
        sorted(
            event_ids,
            key=lambda event_id: (
                str(index.events[event_id]['time']),
                event_id,
            ),
        )
    )
    return fb.SourceExecution(events, objects, relations, order)


def _strict_realized_b0(index: P2PIndex, anchor_event_id: str, quotation_id: str, pr_ids: tuple[str, ...]) -> str:
    action = index.events.get(anchor_event_id)
    if action is None or str(action.get('activity')) != ACTION_ACTIVITY:
        return 'unknown'
    if quotation_id not in index.event_objects.get(anchor_event_id, ()):
        return 'unknown'
    anchor_time = str(action.get('time'))
    for pr_id in pr_ids:
        for event_id in index.object_events.get(pr_id, ()):
            row = index.events[event_id]
            if str(row.get('activity')) != CONTROL_ACTIVITY:
                continue
            if str(row.get('time')) < anchor_time:
                return 'safe'
    return 'violation'


def _powerset_single_edge(edge: tuple[str, str, str]) -> tuple[tuple[tuple[str, str, str], ...], ...]:
    return ((), (edge,))


def _case_tie_pairs(index: P2PIndex, view: Any) -> int:
    rows_by_case: dict[str, list[Any]] = defaultdict(list)
    for row in view.rows:
        rows_by_case[str(row.case_id)].append(row)
    pairs = 0
    for rows in rows_by_case.values():
        for i, left in enumerate(rows):
            left_time = str(index.events[str(left.event_id)]['time'])
            for right in rows[i + 1:]:
                if str(index.events[str(right.event_id)]['time']) == left_time:
                    pairs += 1
    return pairs


def build_r_obs_audit(index: P2PIndex, anchor: dict[str, Any], constructor_id: str) -> RObsAudit:
    if constructor_id not in {'CV-D', 'CV-R1'}:
        raise ValueError(f'unsupported constructor: {constructor_id}')
    anchor_event_id = str(anchor['event_id'])
    quotation_id = str(anchor['quotation_id'])
    stable_anchor_id = str(anchor.get('stable_anchor_id', f'{anchor_event_id}|{quotation_id}'))
    pr_ids = index.linked_pr_by_quotation.get(quotation_id, ())
    if not pr_ids:
        raise ValueError(f'no frozen {SOURCE_RELATION} relation for {quotation_id}')

    source_execution = _source_execution(index, quotation_id, pr_ids)
    if constructor_id == 'CV-D':
        constructor = cvc.CaseViewConstructor.cv_d(QUOTATION_TYPE)
    else:
        constructor = cvc.CaseViewConstructor.cv_r1(QUOTATION_TYPE, (SOURCE_RELATION,))
    view = cvc.flatten_with_constructor(source_execution, constructor)

    visible_ids = {str(row.event_id) for row in view.rows}
    relevant_objects = {quotation_id, *pr_ids}
    binding_domains = []
    for event_id in sorted(visible_ids):
        relevant = tuple(
            sorted(set(index.event_objects.get(event_id, ())).intersection(relevant_objects))
        )
        binding_domains.append((event_id, (relevant,)))

    edge = (INTERNAL_RELATION, pr_ids[0], quotation_id)
    if len(pr_ids) != 1:
        raise ValueError('P2P V1.3 runner is frozen to one linked PR per E8 anchor')
    relation_domain = _powerset_single_edge(edge) if constructor_id == 'CV-D' else ((edge,),)

    deleted = []
    for event in source_execution.events:
        event_id = str(event.event_id)
        if event_id in visible_ids:
            continue
        relevant = tuple(
            sorted(set(index.event_objects.get(event_id, ())).intersection(relevant_objects))
        )
        deleted.append(
            fb.DeletedEventTemplate(
                fb.Event(
                    event_id=event_id,
                    activity=str(event.activity),
                    actor=event.actor,
                    case_ids=(),
                    hidden_objects=relevant,
                )
            )
        )

    spec = fb.Spec(
        hidden_binding_domains=tuple(binding_domains),
        hidden_relation_domain=relation_domain,
        optional_deleted_events=tuple(deleted),
    )
    motif = fb.MissingControlMotif(
        sensitive_activity=ACTION_ACTIVITY,
        control_activity=CONTROL_ACTIVITY,
        require_shared_hidden_object=False,
        control_must_be_before=True,
        required_hidden_relation=INTERNAL_RELATION,
        anchor_event_id=anchor_event_id,
    )
    return RObsAudit(
        stable_anchor_id=stable_anchor_id,
        anchor_event_id=anchor_event_id,
        quotation_id=quotation_id,
        constructor_id=constructor_id,
        linked_pr_ids=tuple(pr_ids),
        source_execution=source_execution,
        view=view,
        spec=spec,
        motif=motif,
        realized_b0=_strict_realized_b0(index, anchor_event_id, quotation_id, tuple(pr_ids)),
        same_timestamp_case_event_pairs=_case_tie_pairs(index, view),
    )


def _labels(verdicts: tuple[bool, ...]) -> list[str]:
    return ['violation' if value else 'safe' for value in verdicts]


def run_anchor_view(index: P2PIndex, anchor: dict[str, Any], constructor_id: str) -> dict[str, Any]:
    audit = build_r_obs_audit(index, anchor, constructor_id)
    t0 = time.perf_counter()
    result = smt.verify_smt(audit.view, audit.spec, audit.motif)
    elapsed = time.perf_counter() - t0
    witness_valid = None
    witness_objective = None
    witness_errors: list[str] = []
    if result.witness is not None:
        report = iwv.validate_witness(
            audit.view,
            audit.spec,
            audit.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = report.valid
        witness_objective = list(report.objective) if report.objective is not None else None
        witness_errors = list(report.errors)
    return {
        'stable_anchor_id': audit.stable_anchor_id,
        'anchor_event_id': audit.anchor_event_id,
        'quotation_id': audit.quotation_id,
        'case_view': constructor_id,
        'linked_pr_ids': list(audit.linked_pr_ids),
        'visible_event_count': len({row.event_id for row in audit.view.rows}),
        'deleted_event_candidate_count': len(audit.spec.optional_deleted_events),
        'relation_choice_count': len(audit.spec.hidden_relation_domain),
        'same_timestamp_case_event_pairs': audit.same_timestamp_case_event_pairs,
        'b0': audit.realized_b0,
        'b1': acomp.b1_anchor(audit.view, audit.anchor_event_id),
        'b2': acomp.b2_anchor(audit.view, audit.anchor_event_id),
        'sscv_decision': result.decision,
        'sscv_verdicts': _labels(result.verdicts),
        'sscv_complete': result.complete,
        'solver_statuses': list(result.solver_statuses),
        'unknown_reason': result.unknown_reason,
        'backend': result.backend,
        'runtime_seconds': elapsed,
        'witness_returned': result.witness is not None,
        'witness_valid': witness_valid,
        'witness_objective': witness_objective,
        'witness_errors': witness_errors,
        'witness_minimal_claimed': bool(result.witness is not None and result.witness.minimal),
    }


def run_anchor_manifest(
    index: P2PIndex,
    manifest: dict[str, Any],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    anchors = list(manifest.get('anchors', ()))
    if limit is not None:
        anchors = anchors[:limit]
    rows: list[dict[str, Any]] = []
    for anchor in anchors:
        for constructor_id in ('CV-D', 'CV-R1'):
            rows.append(run_anchor_view(index, anchor, constructor_id))
    return rows


def _decision_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {'sound': 0, 'unsound': 0, 'unknown': 0}
    for row in rows:
        decision = str(row['sscv_decision'])
        out[decision] = out.get(decision, 0) + 1
    return out


def _state_counts(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        state = str(row[key])
        out[state] = out.get(state, 0) + 1
    return dict(sorted(out.items()))


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    anchor_ids = sorted({str(row['stable_anchor_id']) for row in rows})
    by_view: dict[str, Any] = {}
    for view_id in ('CV-D', 'CV-R1'):
        current = [row for row in rows if row['case_view'] == view_id]
        runtimes = sorted(float(row['runtime_seconds']) for row in current)
        by_view[view_id] = {
            'row_count': len(current),
            'decision_counts': _decision_counts(current),
            'b0_counts': _state_counts(current, 'b0'),
            'b1_counts': _state_counts(current, 'b1'),
            'b2_counts': _state_counts(current, 'b2'),
            'witness_count': sum(bool(row['witness_returned']) for row in current),
            'invalid_witness_count': sum(row['witness_valid'] is False for row in current),
            'unknown_count': sum(row['sscv_decision'] == 'unknown' for row in current),
            'same_timestamp_row_count': sum(int(row['same_timestamp_case_event_pairs'] > 0) for row in current),
            'runtime_seconds_total': sum(runtimes),
            'runtime_seconds_median': runtimes[len(runtimes) // 2] if runtimes else None,
            'runtime_seconds_max': max(runtimes) if runtimes else None,
        }
    transition: dict[str, int] = {}
    paired: dict[str, dict[str, str]] = defaultdict(dict)
    for row in rows:
        paired[str(row['stable_anchor_id'])][str(row['case_view'])] = str(row['sscv_decision'])
    for anchor_id, pair in paired.items():
        if {'CV-D', 'CV-R1'} <= set(pair):
            key = f"{pair['CV-D']}->{pair['CV-R1']}"
            transition[key] = transition.get(key, 0) + 1
    return {
        'row_count': len(rows),
        'anchor_count': len(anchor_ids),
        'case_view_count': len({row['case_view'] for row in rows}),
        'decision_counts': _decision_counts(rows),
        'b0_counts': _state_counts(rows, 'b0'),
        'b1_counts': _state_counts(rows, 'b1'),
        'b2_counts': _state_counts(rows, 'b2'),
        'witness_count': sum(bool(row['witness_returned']) for row in rows),
        'invalid_witness_count': sum(row['witness_valid'] is False for row in rows),
        'unknown_count': sum(row['sscv_decision'] == 'unknown' for row in rows),
        'paired_view_transition_counts': dict(sorted(transition.items())),
        'by_case_view': by_view,
    }
