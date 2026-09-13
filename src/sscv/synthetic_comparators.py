from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import witness_validation as iwv
from . import smt_verifier as smt
from . import synthetic_generator as gen
def _full_execution(cell: gen.SyntheticCell) -> smt.SMTExecution:
    object_types = {
        str(obj.object_id): str(obj.object_type)
        for obj in cell.underlying_execution.objects
    }
    events = []
    for event in cell.underlying_execution.events:
        hidden_objects = tuple(
            str(object_id)
            for object_id in event.object_ids
            if object_types.get(str(object_id)) not in {gen.CASE_TYPE, gen.SUPPORT_TYPE}
        )
        events.append(
            smt.SMTEvent(
                event_id=str(event.event_id),
                activity=str(event.activity),
                actor=event.actor,
                case_ids=(),
                hidden_objects=hidden_objects,
            )
        )
    hidden_relations = tuple(
        (str(kind), str(left), str(right))
        for kind, left, right in cell.underlying_execution.relations
        if str(kind) == gen.INTERNAL_RELATION
    )
    return smt.SMTExecution(
        tuple(events),
        tuple(str(event_id) for event_id in cell.underlying_execution.order),
        hidden_relations,
    )


def b0_realized(cell: gen.SyntheticCell) -> str:
    violation = iwv.evaluate_motif_independent(_full_execution(cell), cell.motif)
    return "violation" if violation else "safe"


def _rows_by_case(cell: gen.SyntheticCell) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = defaultdict(list)
    for row in cell.view.rows:
        result[str(row.case_id)].append(row)
    for rows in result.values():
        rows.sort(key=lambda row: (int(row.rank), str(row.event_id)))
    return result


def _pair_case_results(cell: gen.SyntheticCell) -> tuple[bool, bool]:
    """Return (jointly_evaluable, violation_visible) for M1/M3."""
    motif = cell.motif
    jointly_evaluable = False
    violation_visible = False
    for rows in _rows_by_case(cell).values():
        first_rows = [row for row in rows if row.activity == motif.first_activity]
        second_rows = [row for row in rows if row.activity == motif.second_activity]
        for first in first_rows:
            for second in second_rows:
                if first.event_id == second.event_id:
                    continue
                jointly_evaluable = True
                actor_relation = getattr(motif, "actor_relation", "any")
                actor_ok = (
                    actor_relation == "any"
                    or (actor_relation == "same" and first.actor == second.actor)
                    or (actor_relation == "different" and first.actor != second.actor)
                )
                order_relation = getattr(motif, "order_relation", "any")
                order_ok = (
                    order_relation == "any"
                    or (order_relation == "before" and int(first.rank) < int(second.rank))
                    or (order_relation == "after" and int(second.rank) < int(first.rank))
                )
                if actor_ok and order_ok:
                    violation_visible = True
    return jointly_evaluable, violation_visible


def _m2_case_result(cell: gen.SyntheticCell) -> tuple[bool, bool | None]:
    """Return (sensitive_visible, protected_visible_or_none)."""
    motif = cell.motif
    anchor = getattr(motif, "anchor_event_id", None)
    for rows in _rows_by_case(cell).values():
        sensitive_rows = [
            row
            for row in rows
            if row.activity == motif.sensitive_activity
            and (anchor is None or str(row.event_id) == str(anchor))
        ]
        for sensitive in sensitive_rows:
            controls = [row for row in rows if row.activity == motif.control_activity]
            if not controls:
                return True, None
            protected = any(int(control.rank) < int(sensitive.rank) for control in controls)
            return True, protected
    return False, None


def b1_closed_world(cell: gen.SyntheticCell) -> str:
    if cell.motif_id in {"M1", "M3"}:
        _, violation = _pair_case_results(cell)
        return "violation" if violation else "safe"
    sensitive_visible, protected = _m2_case_result(cell)
    if not sensitive_visible:
        return "safe"
    return "safe" if protected is True else "violation"


def b2_open_world(cell: gen.SyntheticCell) -> str:
    if cell.motif_id in {"M1", "M3"}:
        evaluable, violation = _pair_case_results(cell)
        if not evaluable:
            return "unknown"
        return "violation" if violation else "safe"
    sensitive_visible, protected = _m2_case_result(cell)
    if not sensitive_visible or protected is None:
        return "unknown"
    return "safe" if protected else "violation"
