from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WitnessValidationReport:
    valid: bool
    errors: tuple[str, ...]
    safe_verdict: bool | None
    violating_verdict: bool | None
    objective: tuple[int, int, int, int, int, int, int] | None


def _view_records(view: Any) -> tuple[dict[str, dict[str, Any]], bool]:
    records: dict[str, dict[str, Any]] = {}
    consistent = True
    for row in view.rows:
        rec = records.get(row.event_id)
        if rec is None:
            records[row.event_id] = {
                "activity": row.activity,
                "actor": row.actor,
                "case_ids": {row.case_id},
            }
        else:
            if rec["activity"] != row.activity or rec["actor"] != row.actor:
                consistent = False
            rec["case_ids"].add(row.case_id)
    return records, consistent


def _view_canonical(view: Any) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (r.case_id, int(r.rank), r.event_id, r.activity, r.actor)
            for r in view.rows
        )
    )


def _flatten_canonical(execution: Any) -> tuple[tuple[Any, ...], ...]:
    if len(set(execution.order)) != len(execution.order):
        return ()
    positions = {event_id: i for i, event_id in enumerate(execution.order)}
    if set(positions) != {event.event_id for event in execution.events}:
        return ()
    rows: list[tuple[Any, ...]] = []
    case_ids = sorted(
        {case_id for event in execution.events for case_id in event.case_ids}
    )
    for case_id in case_ids:
        events = [event for event in execution.events if case_id in event.case_ids]
        events.sort(key=lambda event: (positions[event.event_id], event.event_id))
        for rank, event in enumerate(events):
            rows.append(
                (case_id, rank, event.event_id, event.activity, event.actor)
            )
    return tuple(sorted(rows))


def _visible_precedence(view: Any) -> set[tuple[str, str]]:
    by_case: dict[str, list[Any]] = {}
    for row in view.rows:
        by_case.setdefault(row.case_id, []).append(row)
    edges: set[tuple[str, str]] = set()
    for rows in by_case.values():
        ordered = sorted(rows, key=lambda row: (int(row.rank), row.event_id))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if left.event_id != right.event_id:
                    edges.add((left.event_id, right.event_id))
    return edges


def _order_pair_key(left: str, right: str) -> tuple[str, str]:
    return tuple(sorted((left, right)))


def _precedence_closure(
    event_ids: tuple[str, ...], edges: set[tuple[str, str]]
) -> dict[str, set[str]]:
    reach = {event_id: set() for event_id in event_ids}
    for left, right in edges:
        if left in reach and right in reach:
            reach[left].add(right)
    changed = True
    while changed:
        changed = False
        for left in event_ids:
            expanded: set[str] = set()
            for right in tuple(reach[left]):
                expanded.update(reach[right])
            before = len(reach[left])
            reach[left].update(expanded)
            if len(reach[left]) != before:
                changed = True
    return reach


def _order_contract_admissible(view: Any, spec: Any, execution: Any) -> bool:
    reference = getattr(spec, "reference_order", None)
    free_pairs = getattr(spec, "order_free_pairs", None)
    if reference is None and free_pairs is None:
        return True
    if reference is None or free_pairs is None:
        return False

    records, consistent = _view_records(view)
    if not consistent:
        return False
    templates = tuple(getattr(spec, "optional_deleted_events", ()))
    possible_ids = tuple(
        sorted(
            set(records).union(template.event.event_id for template in templates)
        )
    )
    reference = tuple(reference)
    if len(reference) != len(set(reference)) or set(reference) != set(possible_ids):
        return False
    reference_pos = {event_id: index for index, event_id in enumerate(reference)}

    mandatory = set(_visible_precedence(view))
    for template in templates:
        event_id = template.event.event_id
        if template.before_event_id is not None:
            mandatory.add((event_id, template.before_event_id))
        if template.after_event_id is not None:
            mandatory.add((template.after_event_id, event_id))
    if any(
        left not in reference_pos
        or right not in reference_pos
        or reference_pos[left] >= reference_pos[right]
        for left, right in mandatory
    ):
        return False
    reach = _precedence_closure(possible_ids, mandatory)
    normalized_free: set[tuple[str, str]] = set()
    for raw_pair in tuple(free_pairs):
        pair = tuple(raw_pair)
        if (
            len(pair) != 2
            or pair[0] == pair[1]
            or pair[0] not in reference_pos
            or pair[1] not in reference_pos
        ):
            return False
        key = _order_pair_key(pair[0], pair[1])
        if key in normalized_free:
            return False
        left, right = key
        if right in reach[left] or left in reach[right]:
            return False
        normalized_free.add(key)

    active = tuple(execution.order)
    active_set = set(active)
    local_mandatory = {
        edge for edge in mandatory if edge[0] in active_set and edge[1] in active_set
    }
    local_reach = _precedence_closure(active, local_mandatory)
    actual_pos = {event_id: index for index, event_id in enumerate(active)}
    for index, left in enumerate(active):
        for right in active[index + 1 :]:
            if (
                right in local_reach[left]
                or left in local_reach[right]
                or _order_pair_key(left, right) in normalized_free
            ):
                continue
            expected_left_first = reference_pos[left] < reference_pos[right]
            actual_left_first = actual_pos[left] < actual_pos[right]
            if expected_left_first != actual_left_first:
                return False
    return True


def _event_map(execution: Any) -> dict[str, Any]:
    return {event.event_id: event for event in execution.events}


def _before(execution: Any, first_id: str, second_id: str) -> bool:
    positions = {event_id: i for i, event_id in enumerate(execution.order)}
    return (
        first_id in positions
        and second_id in positions
        and positions[first_id] < positions[second_id]
    )


def _has_relation(
    execution: Any,
    relation_type: str,
    left_objects: tuple[str, ...],
    right_objects: tuple[str, ...],
) -> bool:
    relations = set(tuple(relation) for relation in execution.hidden_relations)
    for left in left_objects:
        for right in right_objects:
            if (
                (relation_type, left, right) in relations
                or (relation_type, right, left) in relations
            ):
                return True
    return False


def _motif_kind(motif: Any) -> str:
    if hasattr(motif, "first_activity") and hasattr(motif, "second_activity"):
        return "pair"
    if hasattr(motif, "sensitive_activity") and hasattr(motif, "control_activity"):
        return "missing_control"
    raise ValueError(f"unsupported motif type: {type(motif).__name__}")


def _evaluate_pair(execution: Any, motif: Any) -> bool:
    for first in execution.events:
        if first.activity != motif.first_activity:
            continue
        for second in execution.events:
            if (
                second.event_id == first.event_id
                or second.activity != motif.second_activity
            ):
                continue
            actor_relation = getattr(motif, "actor_relation", "any")
            if actor_relation == "same" and first.actor != second.actor:
                continue
            if actor_relation == "different" and first.actor == second.actor:
                continue
            if actor_relation not in {"any", "same", "different"}:
                raise ValueError(
                    f"unsupported actor relation: {actor_relation}"
                )
            order_relation = getattr(motif, "order_relation", "any")
            if order_relation == "before" and not _before(
                execution, first.event_id, second.event_id
            ):
                continue
            if order_relation == "after" and not _before(
                execution, second.event_id, first.event_id
            ):
                continue
            if order_relation not in {"any", "before", "after"}:
                raise ValueError(
                    f"unsupported order relation: {order_relation}"
                )
            if getattr(motif, "require_shared_hidden_object", True):
                if not set(first.hidden_objects).intersection(second.hidden_objects):
                    continue
            relation = getattr(motif, "required_hidden_relation", None)
            if relation is not None and not _has_relation(
                execution,
                relation,
                tuple(first.hidden_objects),
                tuple(second.hidden_objects),
            ):
                continue
            return True
    return False


def _evaluate_missing_control(execution: Any, motif: Any) -> bool:
    for sensitive in execution.events:
        if sensitive.activity != motif.sensitive_activity:
            continue
        anchor_event_id = getattr(motif, "anchor_event_id", None)
        if anchor_event_id is not None and sensitive.event_id != anchor_event_id:
            continue
        protected = False
        for control in execution.events:
            if (
                control.event_id == sensitive.event_id
                or control.activity != motif.control_activity
            ):
                continue
            if getattr(motif, "require_shared_hidden_object", True):
                if not set(sensitive.hidden_objects).intersection(
                    control.hidden_objects
                ):
                    continue
            required_relation = getattr(motif, "required_hidden_relation", None)
            if required_relation is not None and not _has_relation(
                execution,
                required_relation,
                tuple(control.hidden_objects),
                tuple(sensitive.hidden_objects),
            ):
                continue
            if getattr(motif, "control_must_be_before", True):
                if not _before(
                    execution, control.event_id, sensitive.event_id
                ):
                    continue
            protected = True
            break
        if not protected:
            return True
    return False


def evaluate_motif_independent(execution: Any, motif: Any) -> bool:
    if _motif_kind(motif) == "pair":
        return _evaluate_pair(execution, motif)
    return _evaluate_missing_control(execution, motif)


def _admissible(view: Any, spec: Any, execution: Any) -> bool:
    records, consistent = _view_records(view)
    if not consistent or not records:
        return False
    event_map = _event_map(execution)
    if len(event_map) != len(execution.events):
        return False
    if set(execution.order) != set(event_map) or len(execution.order) != len(event_map):
        return False

    optional_templates = {
        template.event.event_id: template
        for template in getattr(spec, "optional_deleted_events", ())
    }
    required_deleted = tuple(getattr(spec, "required_deleted_event_ids", ()))
    if (
        len(required_deleted) != len(set(required_deleted))
        or not set(required_deleted).issubset(set(optional_templates))
    ):
        return False
    allowed_ids = set(records).union(optional_templates)
    if not set(event_map).issubset(allowed_ids):
        return False
    if not set(records).issubset(event_map):
        return False
    if not set(required_deleted).issubset(set(event_map)):
        return False

    domains = dict(getattr(spec, "hidden_binding_domains", ()))
    for event_id, record in records.items():
        event = event_map[event_id]
        if event.activity != record["activity"] or event.actor != record["actor"]:
            return False
        if tuple(sorted(event.case_ids)) != tuple(sorted(record["case_ids"])):
            return False
        domain = tuple(
            tuple(sorted(choice))
            for choice in domains.get(event_id, ((),))
        )
        if tuple(sorted(event.hidden_objects)) not in domain:
            return False

    for event_id in set(event_map).difference(records):
        template = optional_templates.get(event_id)
        if template is None:
            return False
        event = event_map[event_id]
        template_event = template.event
        if (
            event.activity != template_event.activity
            or event.actor != template_event.actor
            or tuple(event.case_ids) != tuple(template_event.case_ids)
            or tuple(sorted(event.hidden_objects))
            != tuple(sorted(template_event.hidden_objects))
        ):
            return False

    relation_domain = (
        tuple(
            tuple(sorted(tuple(relation) for relation in choice))
            for choice in getattr(spec, "hidden_relation_domain", ())
        )
        or ((),)
    )
    actual_relations = tuple(
        sorted(tuple(relation) for relation in execution.hidden_relations)
    )
    if actual_relations not in relation_domain:
        return False

    for left, right in _visible_precedence(view):
        if not _before(execution, left, right):
            return False
    for event_id, template in optional_templates.items():
        if event_id not in event_map:
            continue
        if template.before_event_id is not None and not _before(
            execution, event_id, template.before_event_id
        ):
            return False
        if template.after_event_id is not None and not _before(
            execution, template.after_event_id, event_id
        ):
            return False
    if not _order_contract_admissible(view, spec, execution):
        return False
    return True


def _hidden_binding_facts(execution: Any) -> set[tuple[str, str]]:
    return {
        (event.event_id, object_id)
        for event in execution.events
        for object_id in event.hidden_objects
    }


def _deleted_event_facts(view: Any, execution: Any) -> set[str]:
    visible_ids = {row.event_id for row in view.rows}
    return {
        event.event_id
        for event in execution.events
        if event.event_id not in visible_ids
    }


def _relation_facts(execution: Any) -> set[tuple[str, str, str]]:
    return {tuple(relation) for relation in execution.hidden_relations}


def _order_facts(view: Any, execution: Any) -> set[tuple[str, str]]:
    constrained_pairs = {
        frozenset((left, right)) for left, right in _visible_precedence(view)
    }
    facts: set[tuple[str, str]] = set()
    for index, left in enumerate(execution.order):
        for right in execution.order[index + 1 :]:
            if frozenset((left, right)) not in constrained_pairs:
                facts.add((left, right))
    return facts


def witness_objective_independent(
    view: Any, first: Any, second: Any
) -> tuple[int, int, int, int, int, int, int]:
    deleted = _deleted_event_facts(view, first) ^ _deleted_event_facts(view, second)
    bindings = _hidden_binding_facts(first) ^ _hidden_binding_facts(second)
    relations = _relation_facts(first) ^ _relation_facts(second)
    orders = _order_facts(view, first) ^ _order_facts(view, second)

    touched_events = {event_id for event_id, _ in bindings}.union(deleted)
    for left, right in orders:
        touched_events.add(left)
        touched_events.add(right)

    hidden_objects = {object_id for _, object_id in bindings}
    for _, left, right in relations:
        hidden_objects.add(left)
        hidden_objects.add(right)

    deleted_count = len(deleted)
    binding_count = len(bindings)
    relation_count = len(relations)
    order_count = len(orders)
    return (
        deleted_count + binding_count + relation_count + order_count,
        deleted_count,
        binding_count,
        relation_count,
        order_count,
        len(touched_events),
        len(hidden_objects),
    )


def validate_witness(
    view: Any,
    spec: Any,
    motif: Any,
    safe_execution: Any,
    violating_execution: Any,
) -> WitnessValidationReport:
    errors: list[str] = []

    safe_admissible = _admissible(view, spec, safe_execution)
    violating_admissible = _admissible(view, spec, violating_execution)
    if not safe_admissible:
        errors.append("safe_execution_not_admissible")
    if not violating_admissible:
        errors.append("violating_execution_not_admissible")

    if _flatten_canonical(safe_execution) != _view_canonical(view):
        errors.append("safe_execution_does_not_reflatten_to_view")
    if _flatten_canonical(violating_execution) != _view_canonical(view):
        errors.append("violating_execution_does_not_reflatten_to_view")

    safe_verdict: bool | None = None
    violating_verdict: bool | None = None
    try:
        safe_verdict = evaluate_motif_independent(safe_execution, motif)
        violating_verdict = evaluate_motif_independent(
            violating_execution, motif
        )
        if safe_verdict or not violating_verdict:
            errors.append("witness_verdicts_are_not_opposite")
    except Exception:
        errors.append("motif_evaluation_failed")

    objective = witness_objective_independent(
        view, safe_execution, violating_execution
    )
    return WitnessValidationReport(
        valid=not errors,
        errors=tuple(errors),
        safe_verdict=safe_verdict,
        violating_verdict=violating_verdict,
        objective=objective,
    )
