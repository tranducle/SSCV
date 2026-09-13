from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations, product
from typing import Tuple


@dataclass(frozen=True)
class Event:
    event_id: str
    activity: str
    actor: str | None
    case_ids: Tuple[str, ...] = ()
    hidden_objects: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Execution:
    events: Tuple[Event, ...]
    order: Tuple[str, ...]
    hidden_relations: Tuple[Tuple[str, str, str], ...] = ()

    def event_map(self) -> dict[str, Event]:
        return {event.event_id: event for event in self.events}


@dataclass(frozen=True, order=True)
class CaseRow:
    case_id: str
    rank: int
    event_id: str
    activity: str
    actor: str | None


@dataclass(frozen=True)
class CaseView:
    rows: Tuple[CaseRow, ...]

    def canonical(self) -> tuple[tuple[object, ...], ...]:
        return tuple(
            (row.case_id, row.rank, row.event_id, row.activity, row.actor)
            for row in sorted(self.rows)
        )


@dataclass(frozen=True)
class PairMotif:
    first_activity: str
    second_activity: str
    actor_relation: str = "any"
    order_relation: str = "any"
    require_shared_hidden_object: bool = True
    required_hidden_relation: str | None = None


@dataclass(frozen=True)
class MissingControlMotif:
    sensitive_activity: str
    control_activity: str
    require_shared_hidden_object: bool = True
    control_must_be_before: bool = True
    required_hidden_relation: str | None = None
    anchor_event_id: str | None = None


@dataclass(frozen=True)
class DeletedEventTemplate:
    event: Event
    before_event_id: str | None = None
    after_event_id: str | None = None


@dataclass(frozen=True)
class CompletionSpec:
    hidden_binding_domains: Tuple[
        Tuple[str, Tuple[Tuple[str, ...], ...]], ...
    ] = ()
    hidden_relation_domain: Tuple[
        Tuple[Tuple[str, str, str], ...], ...
    ] = ((),)
    optional_deleted_events: Tuple[DeletedEventTemplate, ...] = ()
    max_completions: int | None = None

    def binding_domains(self) -> dict[str, Tuple[Tuple[str, ...], ...]]:
        return dict(self.hidden_binding_domains)


@dataclass(frozen=True)
class AmbiguityWitness:
    safe_execution: Execution
    violating_execution: Execution
    objective: Tuple[int, int, int, int, int, int, int]
    valid: bool
    minimal: bool


@dataclass(frozen=True)
class VerificationResult:
    decision: str
    verdicts: Tuple[bool, ...]
    explored: int
    complete: bool
    witness: AmbiguityWitness | None = None
    unknown_reason: str | None = None


def flatten(execution: Execution) -> CaseView:
    event_map = execution.event_map()
    order_index = {event_id: index for index, event_id in enumerate(execution.order)}
    rows: list[CaseRow] = []

    case_ids = sorted({case_id for event in execution.events for case_id in event.case_ids})
    for case_id in case_ids:
        case_events = [
            event
            for event in execution.events
            if case_id in event.case_ids
        ]
        case_events.sort(key=lambda event: (order_index[event.event_id], event.event_id))
        for rank, event in enumerate(case_events):
            rows.append(
                CaseRow(
                    case_id=case_id,
                    rank=rank,
                    event_id=event.event_id,
                    activity=event.activity,
                    actor=event.actor,
                )
            )

    rows.sort()
    return CaseView(rows=tuple(rows))


def _visible_event_records(view: CaseView) -> tuple[dict[str, dict[str, object]], bool]:
    records: dict[str, dict[str, object]] = {}
    consistent = True
    for row in view.rows:
        existing = records.get(row.event_id)
        if existing is None:
            records[row.event_id] = {
                "activity": row.activity,
                "actor": row.actor,
                "case_ids": {row.case_id},
            }
            continue
        if existing["activity"] != row.activity or existing["actor"] != row.actor:
            consistent = False
        case_ids = existing["case_ids"]
        assert isinstance(case_ids, set)
        case_ids.add(row.case_id)
    return records, consistent


def _build_execution(
    view: CaseView,
    hidden_bindings: dict[str, Tuple[str, ...]],
    order: Tuple[str, ...],
    hidden_relations: Tuple[Tuple[str, str, str], ...] = (),
    deleted_events: Tuple[Event, ...] = (),
) -> Execution:
    records, consistent = _visible_event_records(view)
    if not consistent:
        raise ValueError("inconsistent replicated event fields")

    events: list[Event] = []
    for event_id in sorted(records):
        record = records[event_id]
        case_ids = record["case_ids"]
        assert isinstance(case_ids, set)
        events.append(
            Event(
                event_id=event_id,
                activity=str(record["activity"]),
                actor=record["actor"] if record["actor"] is None else str(record["actor"]),
                case_ids=tuple(sorted(case_ids)),
                hidden_objects=tuple(sorted(hidden_bindings.get(event_id, ()))),
            )
        )

    events.extend(deleted_events)

    return Execution(
        events=tuple(events),
        order=order,
        hidden_relations=tuple(sorted(hidden_relations)),
    )


def _visible_precedence_edges(view: CaseView) -> set[tuple[str, str]]:
    by_case: dict[str, list[CaseRow]] = {}
    for row in view.rows:
        by_case.setdefault(row.case_id, []).append(row)

    edges: set[tuple[str, str]] = set()
    for rows in by_case.values():
        ordered = sorted(rows, key=lambda row: (row.rank, row.event_id))
        for index, first in enumerate(ordered):
            for second in ordered[index + 1 :]:
                if first.event_id != second.event_id:
                    edges.add((first.event_id, second.event_id))
    return edges


def _valid_orders(
    view: CaseView,
    extra_event_ids: Tuple[str, ...] = (),
    extra_edges: Tuple[Tuple[str, str], ...] = (),
) -> tuple[Tuple[str, ...], ...]:
    records, consistent = _visible_event_records(view)
    if not consistent:
        return ()
    event_ids = tuple(sorted(set(records).union(extra_event_ids)))
    required = _visible_precedence_edges(view).union(extra_edges)
    valid: list[Tuple[str, ...]] = []
    for order in permutations(event_ids):
        positions = {event_id: index for index, event_id in enumerate(order)}
        if all(positions[first] < positions[second] for first, second in required):
            valid.append(tuple(order))
    return tuple(valid)


def _enumerate_completions(
    view: CaseView,
    spec: CompletionSpec,
) -> tuple[Execution, ...]:
    records, consistent = _visible_event_records(view)
    if not consistent:
        return ()

    domains = spec.binding_domains()
    event_ids = tuple(sorted(records))
    choices: list[Tuple[Tuple[str, ...], ...]] = []
    for event_id in event_ids:
        domain = domains.get(event_id, ((),))
        if not domain:
            return ()
        choices.append(tuple(tuple(sorted(objects)) for objects in domain))

    completions: list[Execution] = []
    deleted_presence_domains = tuple((False, True) for _ in spec.optional_deleted_events)
    deleted_presence_choices = (
        tuple(product(*deleted_presence_domains))
        if deleted_presence_domains
        else ((),)
    )
    relation_choices = spec.hidden_relation_domain or ((),)

    for selected in product(*choices):
        bindings = dict(zip(event_ids, selected))
        for presence in deleted_presence_choices:
            included_templates = tuple(
                template
                for template, present in zip(spec.optional_deleted_events, presence)
                if present
            )
            deleted_events = tuple(template.event for template in included_templates)
            extra_edges: list[tuple[str, str]] = []
            for template in included_templates:
                if template.before_event_id is not None:
                    extra_edges.append((template.event.event_id, template.before_event_id))
                if template.after_event_id is not None:
                    extra_edges.append((template.after_event_id, template.event.event_id))
            valid_orders = _valid_orders(
                view,
                tuple(event.event_id for event in deleted_events),
                tuple(extra_edges),
            )
            for relations in relation_choices:
                for order in valid_orders:
                    execution = _build_execution(
                        view,
                        bindings,
                        order,
                        hidden_relations=relations,
                        deleted_events=deleted_events,
                    )
                    if flatten(execution).canonical() == view.canonical():
                        completions.append(execution)
    return tuple(completions)


def _before(execution: Execution, first_id: str, second_id: str) -> bool:
    positions = {event_id: index for index, event_id in enumerate(execution.order)}
    return positions[first_id] < positions[second_id]


def _has_relation(
    execution: Execution,
    relation_type: str,
    first_objects: Tuple[str, ...],
    second_objects: Tuple[str, ...],
) -> bool:
    relation_set = set(execution.hidden_relations)
    for first_object in first_objects:
        for second_object in second_objects:
            if (relation_type, first_object, second_object) in relation_set:
                return True
            if (relation_type, second_object, first_object) in relation_set:
                return True
    return False


def _evaluate_pair_motif(execution: Execution, motif: PairMotif) -> bool:
    for first in execution.events:
        if first.activity != motif.first_activity:
            continue
        for second in execution.events:
            if second.event_id == first.event_id or second.activity != motif.second_activity:
                continue

            if motif.actor_relation == "same" and first.actor != second.actor:
                continue
            if motif.actor_relation == "different" and first.actor == second.actor:
                continue
            if motif.actor_relation not in {"any", "same", "different"}:
                raise ValueError(f"unsupported actor relation: {motif.actor_relation}")

            if motif.order_relation == "before" and not _before(
                execution, first.event_id, second.event_id
            ):
                continue
            if motif.order_relation == "after" and not _before(
                execution, second.event_id, first.event_id
            ):
                continue
            if motif.order_relation not in {"any", "before", "after"}:
                raise ValueError(f"unsupported order relation: {motif.order_relation}")

            if motif.require_shared_hidden_object:
                if not set(first.hidden_objects).intersection(second.hidden_objects):
                    continue
            if motif.required_hidden_relation is not None:
                if not _has_relation(
                    execution,
                    motif.required_hidden_relation,
                    first.hidden_objects,
                    second.hidden_objects,
                ):
                    continue
            return True
    return False


def _evaluate_missing_control_motif(
    execution: Execution,
    motif: MissingControlMotif,
) -> bool:
    for sensitive in execution.events:
        if sensitive.activity != motif.sensitive_activity:
            continue
        if motif.anchor_event_id is not None and sensitive.event_id != motif.anchor_event_id:
            continue
        protected = False
        for control in execution.events:
            if control.activity != motif.control_activity:
                continue
            if motif.require_shared_hidden_object:
                if not set(sensitive.hidden_objects).intersection(control.hidden_objects):
                    continue
            if motif.required_hidden_relation is not None:
                if not _has_relation(
                    execution,
                    motif.required_hidden_relation,
                    control.hidden_objects,
                    sensitive.hidden_objects,
                ):
                    continue
            if motif.control_must_be_before and not _before(
                execution, control.event_id, sensitive.event_id
            ):
                continue
            protected = True
            break
        if not protected:
            return True
    return False


def evaluate_motif(
    execution: Execution,
    motif: PairMotif | MissingControlMotif,
) -> bool:
    if isinstance(motif, PairMotif):
        return _evaluate_pair_motif(execution, motif)
    if isinstance(motif, MissingControlMotif):
        return _evaluate_missing_control_motif(execution, motif)
    raise ValueError(f"unsupported motif type: {type(motif).__name__}")


def naive_case_local_pair_monitor(view: CaseView, motif: PairMotif) -> bool:
    """Evaluate only activity, actor, and order facts visible inside one case."""
    by_case: dict[str, list[CaseRow]] = {}
    for row in view.rows:
        by_case.setdefault(row.case_id, []).append(row)

    for rows in by_case.values():
        ordered = sorted(rows, key=lambda row: (row.rank, row.event_id))
        for first in ordered:
            if first.activity != motif.first_activity:
                continue
            for second in ordered:
                if first.event_id == second.event_id or second.activity != motif.second_activity:
                    continue
                if motif.actor_relation == "same" and first.actor != second.actor:
                    continue
                if motif.actor_relation == "different" and first.actor == second.actor:
                    continue
                if motif.actor_relation not in {"any", "same", "different"}:
                    raise ValueError(f"unsupported actor relation: {motif.actor_relation}")
                if motif.order_relation == "before" and not first.rank < second.rank:
                    continue
                if motif.order_relation == "after" and not second.rank < first.rank:
                    continue
                if motif.order_relation not in {"any", "before", "after"}:
                    raise ValueError(f"unsupported order relation: {motif.order_relation}")
                return True
    return False


def _hidden_binding_facts(execution: Execution) -> set[tuple[str, str]]:
    return {
        (event.event_id, object_id)
        for event in execution.events
        for object_id in event.hidden_objects
    }


def _hidden_deleted_event_facts(view: CaseView, execution: Execution) -> set[str]:
    visible_ids = {row.event_id for row in view.rows}
    return {event.event_id for event in execution.events if event.event_id not in visible_ids}


def _hidden_relation_facts(execution: Execution) -> set[tuple[str, str, str]]:
    return set(execution.hidden_relations)


def _hidden_order_facts(view: CaseView, execution: Execution) -> set[tuple[str, str]]:
    visible_edges = _visible_precedence_edges(view)
    constrained_pairs = {
        frozenset((first, second))
        for first, second in visible_edges
    }
    facts: set[tuple[str, str]] = set()
    for left_index, left in enumerate(execution.order):
        for right in execution.order[left_index + 1 :]:
            if frozenset((left, right)) not in constrained_pairs:
                facts.add((left, right))
    return facts


def _witness_objective(
    view: CaseView,
    first: Execution,
    second: Execution,
) -> Tuple[int, int, int, int, int, int, int]:
    deleted_difference = _hidden_deleted_event_facts(view, first) ^ _hidden_deleted_event_facts(
        view, second
    )
    binding_difference = _hidden_binding_facts(first) ^ _hidden_binding_facts(second)
    relation_difference = _hidden_relation_facts(first) ^ _hidden_relation_facts(second)
    order_difference = _hidden_order_facts(view, first) ^ _hidden_order_facts(view, second)
    touched_events = {event_id for event_id, _ in binding_difference}
    touched_events.update(deleted_difference)
    for _, first_object, second_object in relation_difference:
        # Relations may be hidden without a visible event endpoint. They affect d0/dR
        # but do not manufacture a visible-event touch count.
        _ = (first_object, second_object)
    for first_id, second_id in order_difference:
        touched_events.add(first_id)
        touched_events.add(second_id)
    hidden_objects = {object_id for _, object_id in binding_difference}
    for _, first_object, second_object in relation_difference:
        hidden_objects.add(first_object)
        hidden_objects.add(second_object)
    deleted_count = len(deleted_difference)
    binding_count = len(binding_difference)
    relation_count = len(relation_difference)
    order_count = len(order_difference)
    difference_count = deleted_count + binding_count + relation_count + order_count
    return (
        difference_count,
        deleted_count,
        binding_count,
        relation_count,
        order_count,
        len(touched_events),
        len(hidden_objects),
    )


def _best_binding_witness(
    view: CaseView,
    completions: tuple[Execution, ...],
    motif: PairMotif | MissingControlMotif,
) -> AmbiguityWitness | None:
    safe = [execution for execution in completions if not evaluate_motif(execution, motif)]
    violating = [execution for execution in completions if evaluate_motif(execution, motif)]
    if not safe or not violating:
        return None

    candidates: list[
        tuple[Tuple[int, int, int, int, int, int, int], Execution, Execution]
    ] = []
    for safe_execution in safe:
        for violating_execution in violating:
            candidates.append(
                (
                    _witness_objective(view, safe_execution, violating_execution),
                    safe_execution,
                    violating_execution,
                )
            )
    objective, safe_execution, violating_execution = min(candidates, key=lambda item: item[0])
    valid = (
        flatten(safe_execution).canonical() == view.canonical()
        and flatten(violating_execution).canonical() == view.canonical()
        and not evaluate_motif(safe_execution, motif)
        and evaluate_motif(violating_execution, motif)
    )
    return AmbiguityWitness(
        safe_execution=safe_execution,
        violating_execution=violating_execution,
        objective=objective,
        valid=valid,
        minimal=True,
    )


def verify(
    view: CaseView,
    spec: CompletionSpec,
    motif: PairMotif | MissingControlMotif,
) -> VerificationResult:
    records, consistent = _visible_event_records(view)
    if not consistent:
        return VerificationResult(
            decision="unknown",
            verdicts=(),
            explored=0,
            complete=True,
            unknown_reason="inconsistent_replicated_event_fields",
        )
    if not records:
        return VerificationResult(
            decision="unknown",
            verdicts=(),
            explored=0,
            complete=True,
            unknown_reason="no_admissible_completion",
        )
    if (
        isinstance(motif, MissingControlMotif)
        and motif.anchor_event_id is not None
        and motif.anchor_event_id not in records
    ):
        return VerificationResult(
            decision="unknown",
            verdicts=(),
            explored=0,
            complete=True,
            unknown_reason="anchor_event_not_in_audit_instance",
        )

    all_completions = _enumerate_completions(view, spec)
    complete = True
    completions = all_completions
    if spec.max_completions is not None and len(all_completions) > spec.max_completions:
        completions = all_completions[: spec.max_completions]
        complete = False
    if not completions:
        return VerificationResult(
            decision="unknown",
            verdicts=(),
            explored=0,
            complete=True,
            unknown_reason="no_admissible_completion",
        )

    verdicts = tuple(sorted({evaluate_motif(execution, motif) for execution in completions}))
    if verdicts == (False, True):
        witness = _best_binding_witness(view, completions, motif)
        return VerificationResult(
            decision="unsound",
            verdicts=verdicts,
            explored=len(completions),
            complete=complete,
            witness=witness,
            unknown_reason=None if witness is not None and witness.valid else "witness_validation_failed",
        )

    if not complete:
        return VerificationResult(
            decision="unknown",
            verdicts=verdicts,
            explored=len(completions),
            complete=False,
            unknown_reason="completion_cap_reached",
        )

    return VerificationResult(
        decision="sound",
        verdicts=verdicts,
        explored=len(completions),
        complete=True,
    )
