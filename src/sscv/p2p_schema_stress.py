from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import case_views as cvc
from . import completion_models as fb
from . import witness_validation as iwv
from . import p2p_runner as pub
from . import smt_verifier as smt
HYPOTHETICAL_PR_PREFIX = "rschema_pr::"
HYPOTHETICAL_CONTROL_PREFIX = "rschema_control::"


@dataclass(frozen=True)
class SchemaState:
    present: bool
    binding_kind: str | None = None
    relation_present: bool = False
    before_anchor: bool = False


def schema_states() -> tuple[SchemaState, ...]:
    """The frozen B1 schema layer: one absent state plus 2 x 2 x 2 present states."""
    states = [SchemaState(False, None, False, False)]
    for binding_kind in ("source", "hypothetical"):
        for relation_present in (False, True):
            for before_anchor in (False, True):
                states.append(
                    SchemaState(
                        True,
                        binding_kind,
                        relation_present,
                        before_anchor,
                    )
                )
    return tuple(states)


def canonical_protecting_state(audit: pub.RObsAudit) -> SchemaState:
    """Canonical protecting extension used for deterministic witness construction."""
    return SchemaState(True, "source", True, True)


def _constructor(audit: pub.RObsAudit) -> cvc.CaseViewConstructor:
    if audit.constructor_id == "CV-D":
        return cvc.CaseViewConstructor.cv_d(pub.QUOTATION_TYPE)
    if audit.constructor_id == "CV-R1":
        return cvc.CaseViewConstructor.cv_r1(
            pub.QUOTATION_TYPE, (pub.SOURCE_RELATION,)
        )
    raise ValueError(audit.constructor_id)


def _canonical_view(view: Any) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (row.case_id, int(row.rank), row.event_id, row.activity, row.actor)
            for row in view.rows
        )
    )


def _is_relevant_source_relation(
    relation: tuple[str, str, str], audit: pub.RObsAudit
) -> bool:
    qualifier, left, right = relation
    if qualifier != pub.SOURCE_RELATION:
        return False
    pr = audit.linked_pr_ids[0]
    quote = audit.quotation_id
    return {str(left), str(right)} == {pr, quote}


def extend_source_execution(
    audit: pub.RObsAudit, state: SchemaState
) -> fb.SourceExecution:
    """Apply one frozen schema extension to the source execution.

    The hypothetical control binds exactly one purchase requisition. No new
    quotation is allowed. When the source PR branch is selected, the relation
    bit represents whether the PR-to-quotation edge is present in that
    completion. The hypothetical branch leaves all source relations untouched
    and optionally adds one new PR-to-quotation edge.
    """
    base = audit.source_execution
    relations = list(base.relations)
    objects = list(base.objects)
    events = list(base.events)
    order = list(base.order)

    if not state.present:
        return fb.SourceExecution(
            tuple(events), tuple(objects), tuple(relations), tuple(order)
        )
    if state.binding_kind not in {"source", "hypothetical"}:
        raise ValueError("present schema state requires source or hypothetical binding")

    source_pr = audit.linked_pr_ids[0]
    if state.binding_kind == "source":
        bound_pr = source_pr
        relations = [
            relation
            for relation in relations
            if not _is_relevant_source_relation(relation, audit)
        ]
        if state.relation_present:
            relations.append(
                (pub.SOURCE_RELATION, source_pr, audit.quotation_id)
            )
    else:
        bound_pr = f"{HYPOTHETICAL_PR_PREFIX}{audit.anchor_event_id}"
        if bound_pr not in {obj.object_id for obj in objects}:
            objects.append(fb.SourceObject(bound_pr, pub.PR_TYPE))
        if state.relation_present:
            relations.append(
                (pub.SOURCE_RELATION, bound_pr, audit.quotation_id)
            )

    control_id = f"{HYPOTHETICAL_CONTROL_PREFIX}{audit.anchor_event_id}"
    events.append(
        fb.SourceEvent(
            control_id,
            pub.CONTROL_ACTIVITY,
            None,
            (bound_pr,),
        )
    )
    if audit.anchor_event_id not in order:
        raise ValueError("anchor event is absent from source execution")
    anchor_index = order.index(audit.anchor_event_id)
    insert_at = anchor_index if state.before_anchor else anchor_index + 1
    order.insert(insert_at, control_id)
    return fb.SourceExecution(
        tuple(events), tuple(objects), tuple(relations), tuple(order)
    )


def same_case_view(audit: pub.RObsAudit, execution: fb.SourceExecution) -> bool:
    try:
        view = cvc.flatten_with_constructor(execution, _constructor(audit))
    except ValueError:
        return False
    return _canonical_view(view) == _canonical_view(audit.view)


def _to_internal_execution(
    audit: pub.RObsAudit, execution: fb.SourceExecution
) -> smt.SMTExecution:
    constructor = _constructor(audit)
    assignment = cvc.case_assignment(execution, constructor)
    events = tuple(
        smt.SMTEvent(
            event_id=str(event.event_id),
            activity=str(event.activity),
            actor=event.actor,
            case_ids=tuple(assignment[str(event.event_id)]),
            hidden_objects=tuple(str(object_id) for object_id in event.object_ids),
        )
        for event in execution.events
    )
    relations = tuple(
        sorted(
            (
                pub.INTERNAL_RELATION,
                str(left),
                str(right),
            )
            for qualifier, left, right in execution.relations
            if qualifier == pub.SOURCE_RELATION
        )
    )
    return smt.SMTExecution(events, tuple(execution.order), relations)


def to_internal_execution(
    audit: pub.RObsAudit, execution: fb.SourceExecution
) -> smt.SMTExecution:
    return _to_internal_execution(audit, execution)


def extension_control_is_violation(
    audit: pub.RObsAudit, execution: fb.SourceExecution
) -> bool:
    internal = _to_internal_execution(audit, execution)
    return iwv.evaluate_motif_independent(internal, audit.motif)


def _state_is_protecting(state: SchemaState) -> bool:
    return bool(state.present and state.relation_present and state.before_anchor)


def explicit_safe_extension(audit: pub.RObsAudit) -> dict[str, Any]:
    tested: list[dict[str, Any]] = []
    for state in schema_states():
        if not state.present:
            continue
        execution = extend_source_execution(audit, state)
        same_view = same_case_view(audit, execution)
        state_protects = _state_is_protecting(state)
        motif_safe = not extension_control_is_violation(audit, execution)
        valid_safe_extension = same_view and state_protects and motif_safe
        tested.append(
            {
                "state": state,
                "same_view": same_view,
                "state_protects": state_protects,
                "motif_safe": motif_safe,
                "valid_safe_extension": valid_safe_extension,
            }
        )
        if valid_safe_extension:
            return {"exists": True, "state": state, "tested": tested}
    return {"exists": False, "state": None, "tested": tested}


def first_explicit_safe_state(audit: pub.RObsAudit) -> SchemaState | None:
    return explicit_safe_extension(audit)["state"]


def validate_schema_transition_witness(
    audit: pub.RObsAudit,
    state: SchemaState,
) -> dict[str, Any]:
    """Validate a new R-SCHEMA safe completion against the realized violation.

    This validator is used only when the R-OBS row is sound-violation and the
    schema layer adds the opposite safe verdict. It validates the constructor
    view, the frozen B1 extension budget, opposite motif verdicts, and the
    latent-difference objective without reusing the SMT safe-extension query.
    """
    errors: list[str] = []
    if not _state_is_protecting(state):
        errors.append("state_is_not_a_protecting_extension")

    safe_source = extend_source_execution(audit, state)
    violating_source = audit.source_execution
    if not same_case_view(audit, safe_source):
        errors.append("safe_extension_does_not_reflatten_to_view")
    if not same_case_view(audit, violating_source):
        errors.append("realized_execution_does_not_reflatten_to_view")

    base_event_ids = {str(event.event_id) for event in violating_source.events}
    safe_event_ids = {str(event.event_id) for event in safe_source.events}
    extra_events = safe_event_ids - base_event_ids
    if len(extra_events) != 1:
        errors.append("hidden_event_slack_exceeded")
    else:
        extra_id = next(iter(extra_events))
        extra_event = next(
            event for event in safe_source.events if str(event.event_id) == extra_id
        )
        if str(extra_event.activity) != pub.CONTROL_ACTIVITY:
            errors.append("extra_event_activity_not_allowed")
        if len(tuple(extra_event.object_ids)) != 1:
            errors.append("extra_control_binding_width_not_one")

    base_objects = {str(obj.object_id): str(obj.object_type) for obj in violating_source.objects}
    safe_objects = {str(obj.object_id): str(obj.object_type) for obj in safe_source.objects}
    extra_objects = set(safe_objects) - set(base_objects)
    if len(extra_objects) > 1:
        errors.append("hidden_object_allowance_exceeded")
    for object_id in extra_objects:
        if safe_objects[object_id] != pub.PR_TYPE:
            errors.append("extra_object_type_not_purchase_requisition")
    if any(
        safe_objects[object_id] == pub.QUOTATION_TYPE
        for object_id in extra_objects
    ):
        errors.append("new_quotation_not_allowed")

    safe_internal = _to_internal_execution(audit, safe_source)
    violation_internal = _to_internal_execution(audit, violating_source)
    safe_verdict = iwv.evaluate_motif_independent(safe_internal, audit.motif)
    violation_verdict = iwv.evaluate_motif_independent(
        violation_internal, audit.motif
    )
    if safe_verdict is not False:
        errors.append("safe_completion_is_not_safe")
    if violation_verdict is not True:
        errors.append("realized_completion_is_not_violating")

    objective = iwv.witness_objective_independent(
        audit.view, safe_internal, violation_internal
    )
    return {
        "valid": not errors,
        "errors": errors,
        "safe_verdict": safe_verdict,
        "violating_verdict": violation_verdict,
        "objective": list(objective),
        "state": {
            "present": state.present,
            "binding_kind": state.binding_kind,
            "relation_present": state.relation_present,
            "before_anchor": state.before_anchor,
        },
    }


def smt_safe_extension(audit: pub.RObsAudit) -> dict[str, Any]:
    """Independent Boolean SMT encoding of the frozen B1 safe-extension query."""
    solver = smt.default_solver()
    if solver is None:
        return {"exists": None, "status": "solver_unavailable", "state": None}

    lines = [
        "(set-logic QF_UF)",
        "(declare-const present Bool)",
        "(declare-const bind_hyp Bool)",
        "(declare-const source_rel Bool)",
        "(declare-const hyp_rel Bool)",
        "(declare-const before_anchor Bool)",
        "(assert present)",
        "(assert before_anchor)",
        "(assert (ite bind_hyp hyp_rel source_rel))",
    ]
    if audit.constructor_id == "CV-R1":
        # The source PR-to-quotation relation is required by the frozen R1 view.
        # Any added control connected by the qualifying relation would itself
        # become a one-hop case event, contradicting that the observed view is fixed.
        lines.append("(assert source_rel)")
        lines.append("(assert (not (ite bind_hyp hyp_rel source_rel)))")
    elif audit.constructor_id != "CV-D":
        raise ValueError(audit.constructor_id)

    variables = (
        "present",
        "bind_hyp",
        "source_rel",
        "hyp_rel",
        "before_anchor",
    )
    status, values = solver.solve("\n".join(lines), variables)
    if status != "sat":
        return {"exists": False if status == "unsat" else None, "status": status, "state": None}
    state = SchemaState(
        present=bool(values.get("present", True)),
        binding_kind="hypothetical" if bool(values.get("bind_hyp", False)) else "source",
        relation_present=(
            bool(values.get("hyp_rel", False))
            if bool(values.get("bind_hyp", False))
            else bool(values.get("source_rel", False))
        ),
        before_anchor=bool(values.get("before_anchor", True)),
    )
    return {"exists": True, "status": status, "state": state, "backend": solver.name}


def combine_r_obs_verdicts(
    base_decision: str,
    base_verdicts: list[str] | tuple[str, ...],
    *,
    safe_extension_exists: bool,
) -> tuple[str, list[str]]:
    """Compose R-OBS with an optional control-only schema extension.

    R-SCHEMA contains R-OBS because the new event is optional. The frozen B1
    extension adds only a control event, a purchase-requisition object, a
    qualifying relation, and order freedom. For anchored M2 this extension can
    add a safe completion but cannot create a new violating completion from a
    base completion that was already safe. Unknown R-OBS states stay unknown
    unless separately certified by a stronger proof path.
    """
    order = {"safe": 0, "violation": 1}
    if base_decision == "unknown":
        return "unknown", list(base_verdicts)
    verdicts = set(str(value) for value in base_verdicts)
    if safe_extension_exists:
        verdicts.add("safe")
    ordered = sorted(verdicts, key=lambda value: order.get(value, 99))
    if set(ordered) == {"safe", "violation"}:
        return "unsound", ordered
    if len(ordered) == 1:
        return "sound", ordered
    return "unknown", ordered
