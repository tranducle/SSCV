from __future__ import annotations

from typing import Any

CONTROL_ACTIVITY = 'Approve Purchase Requisition'
ACTION_ACTIVITY = 'Create Purchase Order'
PR_TYPE = 'purchase_requisition'
QUOTATION_TYPE = 'quotation'
RELATION = 'Quotation of PR'


def _object_types(execution: Any) -> dict[str, str]:
    return {str(obj.object_id): str(obj.object_type) for obj in execution.objects}


def _positions(execution: Any) -> dict[str, int]:
    positions = {str(event_id): i for i, event_id in enumerate(execution.order)}
    event_ids = {str(event.event_id) for event in execution.events}
    if set(positions) != event_ids or len(positions) != len(event_ids):
        raise ValueError('execution order must contain every event exactly once')
    return positions


def _linked_pr_quote_pairs(execution: Any) -> set[tuple[str, str]]:
    types = _object_types(execution)
    pairs: set[tuple[str, str]] = set()
    for qualifier, left, right in execution.relations:
        if qualifier != RELATION:
            continue
        left = str(left)
        right = str(right)
        if types.get(left) == PR_TYPE and types.get(right) == QUOTATION_TYPE:
            pairs.add((left, right))
        elif types.get(right) == PR_TYPE and types.get(left) == QUOTATION_TYPE:
            pairs.add((right, left))
    return pairs


def b0_anchor(execution: Any, anchor_event_id: str) -> str:
    """Anchor-specific realized object-centric M2 verdict."""
    event_map = {str(event.event_id): event for event in execution.events}
    action = event_map.get(str(anchor_event_id))
    if action is None or action.activity != ACTION_ACTIVITY:
        return 'unknown'
    types = _object_types(execution)
    positions = _positions(execution)
    linked = _linked_pr_quote_pairs(execution)
    quotations = {
        str(object_id)
        for object_id in action.object_ids
        if types.get(str(object_id)) == QUOTATION_TYPE
    }
    if not quotations:
        return 'unknown'
    for control in execution.events:
        if control.activity != CONTROL_ACTIVITY:
            continue
        prs = {
            str(object_id)
            for object_id in control.object_ids
            if types.get(str(object_id)) == PR_TYPE
        }
        if not any((pr, q) in linked for pr in prs for q in quotations):
            continue
        if positions[str(control.event_id)] < positions[str(action.event_id)]:
            return 'safe'
    return 'violation'


def _rows_by_case(view: Any) -> dict[str, list[Any]]:
    by_case: dict[str, list[Any]] = {}
    for row in view.rows:
        by_case.setdefault(str(row.case_id), []).append(row)
    for rows in by_case.values():
        rows.sort(key=lambda row: (int(row.rank), str(row.event_id)))
    return by_case


def _find_anchor(view: Any, anchor_event_id: str) -> tuple[str, Any] | None:
    matches = []
    for case_id, rows in _rows_by_case(view).items():
        for row in rows:
            if str(row.event_id) == str(anchor_event_id) and row.activity == ACTION_ACTIVITY:
                matches.append((case_id, row))
    if not matches:
        return None
    matches.sort(key=lambda item: (item[0], int(item[1].rank)))
    return matches[0]


def b1_anchor(view: Any, anchor_event_id: str) -> str:
    """Closed-world case-local verdict for one frozen action anchor."""
    found = _find_anchor(view, anchor_event_id)
    if found is None:
        return 'unknown'
    case_id, action = found
    rows = _rows_by_case(view)[case_id]
    protected = any(
        row.activity == CONTROL_ACTIVITY and int(row.rank) < int(action.rank)
        for row in rows
    )
    return 'safe' if protected else 'violation'


def b2_anchor(view: Any, anchor_event_id: str) -> str:
    """Open-world case-local verdict for one frozen action anchor."""
    found = _find_anchor(view, anchor_event_id)
    if found is None:
        return 'unknown'
    case_id, action = found
    rows = _rows_by_case(view)[case_id]
    protected = any(
        row.activity == CONTROL_ACTIVITY and int(row.rank) < int(action.rank)
        for row in rows
    )
    return 'safe' if protected else 'unknown'
