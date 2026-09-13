from __future__ import annotations

import hashlib
import json
from itertools import combinations
from typing import Any

from . import completion_models as fb
NEUTRAL_ACTIVITY = '__SSCV_NEUTRAL_HIDDEN_EVENT__'


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def motif_activity_set(motif: Any) -> set[str]:
    if hasattr(motif, 'first_activity') and hasattr(motif, 'second_activity'):
        return {str(motif.first_activity), str(motif.second_activity)}
    if hasattr(motif, 'sensitive_activity') and hasattr(motif, 'control_activity'):
        return {str(motif.sensitive_activity), str(motif.control_activity)}
    raise ValueError(f'unsupported motif: {type(motif).__name__}')


def _filler_event_id(cell: Any, index: int) -> str:
    return f'{cell.cell_id}:slack-fill:{int(index)}'


def _filler_object_id(cell: Any, index: int) -> str:
    return f'{cell.cell_id}:slack-object:{int(index)}'


def materialize_hidden_event_templates(cell: Any, target_slack: int) -> tuple[fb.DeletedEventTemplate, ...]:
    target = int(target_slack)
    if target < 0:
        raise ValueError('hidden_event_slack must be non-negative')
    original = tuple(cell.spec.optional_deleted_events)
    if len(original) > target:
        raise ValueError(
            f'cell {cell.cell_id} already requires {len(original)} hidden-event candidates, exceeding target slack {target}'
        )
    templates = list(original)
    filler_index = 1
    existing_ids = {str(t.event.event_id) for t in templates}
    while len(templates) < target:
        event_id = _filler_event_id(cell, filler_index)
        if event_id in existing_ids:
            filler_index += 1
            continue
        templates.append(
            fb.DeletedEventTemplate(
                fb.Event(
                    event_id=event_id,
                    activity=NEUTRAL_ACTIVITY,
                    actor=None,
                    case_ids=(),
                    hidden_objects=(_filler_object_id(cell, filler_index),),
                )
            )
        )
        existing_ids.add(event_id)
        filler_index += 1
    return tuple(templates)


def slack_filler_ids(templates: tuple[fb.DeletedEventTemplate, ...] | list[fb.DeletedEventTemplate]) -> tuple[str, ...]:
    return tuple(
        str(template.event.event_id)
        for template in templates
        if str(template.event.activity) == NEUTRAL_ACTIVITY
    )


def _visible_precedence(view: Any) -> set[tuple[str, str]]:
    by_case: dict[str, list[Any]] = {}
    for row in view.rows:
        by_case.setdefault(str(row.case_id), []).append(row)
    edges: set[tuple[str, str]] = set()
    for rows in by_case.values():
        ordered = sorted(rows, key=lambda row: (int(row.rank), str(row.event_id)))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1:]:
                if str(left.event_id) != str(right.event_id):
                    edges.add((str(left.event_id), str(right.event_id)))
    return edges


def _mandatory_precedence(view: Any, templates: tuple[fb.DeletedEventTemplate, ...]) -> set[tuple[str, str]]:
    edges = _visible_precedence(view)
    for template in templates:
        event_id = str(template.event.event_id)
        if template.before_event_id is not None:
            edges.add((event_id, str(template.before_event_id)))
        if template.after_event_id is not None:
            edges.add((str(template.after_event_id), event_id))
    return edges


def _closure(ids: tuple[str, ...], edges: set[tuple[str, str]]) -> set[tuple[str, str]]:
    reach = {event_id: set() for event_id in ids}
    for left, right in edges:
        if left in reach and right in reach:
            reach[left].add(right)
    changed = True
    while changed:
        changed = False
        for left in ids:
            expanded: set[str] = set()
            for right in tuple(reach[left]):
                expanded.update(reach[right])
            before = len(reach[left])
            reach[left].update(expanded)
            changed = changed or len(reach[left]) != before
    return {(left, right) for left in ids for right in reach[left]}


def _reference_order(cell: Any, templates: tuple[fb.DeletedEventTemplate, ...]) -> tuple[str, ...]:
    visible_ids = {str(row.event_id) for row in cell.view.rows}
    optional_ids = {str(template.event.event_id) for template in templates}
    possible = visible_ids | optional_ids
    original = [
        str(event_id)
        for event_id in cell.underlying_execution.order
        if str(event_id) in possible
    ]
    filler_ids = sorted(set(slack_filler_ids(templates)))
    reference = tuple(original + [event_id for event_id in filler_ids if event_id not in original])
    if len(reference) != len(set(reference)) or set(reference) != possible:
        missing = sorted(possible.difference(reference))
        extra = sorted(set(reference).difference(possible))
        raise ValueError(f'reference order mismatch for {cell.cell_id}: missing={missing} extra={extra}')
    mandatory = _mandatory_precedence(cell.view, templates)
    positions = {event_id: index for index, event_id in enumerate(reference)}
    bad = [
        (left, right)
        for left, right in mandatory
        if left not in positions or right not in positions or positions[left] >= positions[right]
    ]
    if bad:
        raise ValueError(f'reference order violates mandatory precedence for {cell.cell_id}: {bad[:3]}')
    return reference


def build_order_contract(cell: Any, templates: tuple[fb.DeletedEventTemplate, ...], order_width: int) -> dict[str, Any]:
    templates = tuple(templates)
    reference = _reference_order(cell, templates)
    mandatory = _mandatory_precedence(cell.view, templates)
    closure = _closure(reference, mandatory)
    motif_ids = tuple(str(value) for value in cell.motif_event_ids_value)
    motif_set = set(motif_ids)
    fillers = set(slack_filler_ids(templates))

    eligible: list[tuple[str, str]] = []
    for left, right in combinations(sorted(reference), 2):
        if left in fillers or right in fillers:
            continue
        if (left, right) in closure or (right, left) in closure:
            continue
        eligible.append((left, right))

    def priority(pair: tuple[str, str]) -> tuple[int, str, str]:
        count = int(pair[0] in motif_set) + int(pair[1] in motif_set)
        category = 0 if count == 2 else 1 if count == 1 else 2
        return category, pair[0], pair[1]

    eligible.sort(key=priority)
    selected = eligible[:max(0, int(order_width))]
    return {
        'reference_order': list(reference),
        'reference_order_sha256': _canonical_sha(list(reference)),
        'visible_precedence_closure': [list(edge) for edge in sorted(closure)],
        'motif_event_ids': list(motif_ids),
        'filler_event_ids': sorted(fillers),
        'filler_event_count': len(fillers),
        'eligible_pair_count': len(eligible),
        'eligible_pairs': [list(pair) for pair in eligible],
        'order_width': int(order_width),
        'selected_pairs': [list(pair) for pair in selected],
        'selected_pair_count': len(selected),
    }


def build_spec(cell: Any, target_slack: int, order_width: int) -> tuple[fb.Spec, dict[str, Any]]:
    templates = materialize_hidden_event_templates(cell, target_slack)
    contract = build_order_contract(cell, templates, order_width)
    spec = fb.Spec(
        hidden_binding_domains=tuple(cell.spec.hidden_binding_domains),
        hidden_relation_domain=tuple(cell.spec.hidden_relation_domain),
        optional_deleted_events=templates,
        max_completions=cell.spec.max_completions,
        reference_order=tuple(str(value) for value in contract['reference_order']),
        order_free_pairs=tuple(tuple(str(item) for item in pair) for pair in contract['selected_pairs']),
        required_deleted_event_ids=tuple(getattr(cell.spec, 'required_deleted_event_ids', ())),
    )
    return spec, contract
