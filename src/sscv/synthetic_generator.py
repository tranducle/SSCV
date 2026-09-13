from __future__ import annotations

from dataclasses import dataclass
import hashlib
import itertools
import json
from typing import Any

from . import case_views as cvc
from . import completion_models as fb
CASE_TYPE = "case"
SUPPORT_TYPE = "support"
CASE_RELATION = "case_membership"
INTERNAL_RELATION = "linked"


@dataclass(frozen=True)
class SemanticProfile:
    process_family: str
    motif_id: str
    first_activity: str
    second_activity: str
    first_object_role: str
    second_object_role: str
    relation_role: str


@dataclass(frozen=True)
class SyntheticPair:
    pair_key: str
    pair_seed: int
    profile: SemanticProfile
    execution: fb.SourceExecution
    source_sha256: str
    first_event_id: str
    second_event_id: str
    first_hidden_object: str
    second_hidden_object: str


@dataclass(frozen=True)
class SyntheticCell:
    cell_id: str
    pair_key: str
    original_cell_seed: int
    pair_seed: int
    process_family: str
    motif_id: str
    mechanism: str
    mixed_recipe: tuple[str, ...]
    tier: str
    replicate: int
    semantic_map_id: str
    structural_parameters: dict[str, int]
    underlying_execution: fb.SourceExecution
    underlying_execution_sha256: str
    constructor: cvc.CaseViewConstructor
    view: cvc.CaseView
    spec: fb.Spec
    motif: Any
    variable_mechanisms: tuple[str, ...]
    motif_event_ids_value: tuple[str, str]
    deleted_motif_event_id_value: str | None
    generation_status: str = "READY"
    infeasible_reason: str | None = None


_PROFILES = {
    ("request_approval_release", "M1"): SemanticProfile("request_approval_release", "M1", "SubmitRequest", "ApproveRequest", "Request", "Approval", "request_to_approval"),
    ("request_approval_release", "M2"): SemanticProfile("request_approval_release", "M2", "ApproveRequest", "Release", "Approval", "ReleaseArtifact", "approval_to_release"),
    ("request_approval_release", "M3"): SemanticProfile("request_approval_release", "M3", "Release", "ApproveRequest", "ReleaseArtifact", "Approval", "approval_to_release"),
    ("procure_to_pay", "M1"): SemanticProfile("procure_to_pay", "M1", "CreatePurchaseRequest", "ApprovePayment", "PurchaseRequest", "Payment", "request_to_payment"),
    ("procure_to_pay", "M2"): SemanticProfile("procure_to_pay", "M2", "ApprovePayment", "ExecutePayment", "PaymentApproval", "Payment", "approval_to_payment"),
    ("procure_to_pay", "M3"): SemanticProfile("procure_to_pay", "M3", "ExecutePayment", "ApprovePayment", "Payment", "PaymentApproval", "approval_to_payment"),
    ("change_approval_deployment", "M1"): SemanticProfile("change_approval_deployment", "M1", "SubmitChange", "ApproveChange", "ChangeRequest", "ChangeApproval", "change_to_approval"),
    ("change_approval_deployment", "M2"): SemanticProfile("change_approval_deployment", "M2", "ApproveChange", "DeployChange", "ChangeApproval", "Deployment", "approval_to_deployment"),
    ("change_approval_deployment", "M3"): SemanticProfile("change_approval_deployment", "M3", "DeployChange", "ApproveChange", "Deployment", "ChangeApproval", "approval_to_deployment"),
}


def semantic_profile(process_family: str, motif_id: str) -> SemanticProfile:
    try:
        return _PROFILES[(process_family, motif_id)]
    except KeyError as exc:
        raise ValueError(f"unsupported synthetic semantic profile: {(process_family, motif_id)}") from exc


def canonical_source_execution(execution: fb.SourceExecution) -> tuple[Any, ...]:
    objects = tuple(sorted((str(obj.object_id), str(obj.object_type)) for obj in execution.objects))
    events = tuple(
        sorted(
            (
                str(event.event_id),
                str(event.activity),
                event.actor,
                tuple(sorted(str(obj) for obj in event.object_ids)),
            )
            for event in execution.events
        )
    )
    relations = tuple(sorted(tuple(str(x) for x in relation) for relation in execution.relations))
    return objects, events, relations, tuple(str(x) for x in execution.order)


def source_execution_sha256(execution: fb.SourceExecution) -> str:
    raw = json.dumps(canonical_source_execution(execution), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _ids(pair_record: dict[str, Any]) -> dict[str, str]:
    token = f"p{int(pair_record['underlying_pair_seed']):08x}"
    return {
        "token": token,
        "case_main": f"{token}:case:main",
        "case_a": f"{token}:case:a",
        "case_b": f"{token}:case:b",
        "case_shared": f"{token}:case:shared",
        "support_a": f"{token}:support:a",
        "support_b": f"{token}:support:b",
        "first_event": f"{token}:event:first",
        "second_event": f"{token}:event:second",
        "first_object": f"{token}:object:first",
        "second_object": f"{token}:object:second",
        "hidden_case_object": f"{token}:object:hidden-case-neutral",
    }


def _is_order_mechanism(pair_record: dict[str, Any]) -> bool:
    mechanism = str(pair_record["mechanism"])
    return mechanism == "order" or (
        mechanism == "mixed" and pair_record["motif"] == "M3"
    )


def _is_deletion_mechanism(pair_record: dict[str, Any]) -> bool:
    mechanism = str(pair_record["mechanism"])
    return mechanism == "deletion" or (
        mechanism == "mixed" and pair_record["motif"] == "M2"
    )


def _visible_motif_event_count(pair_record: dict[str, Any]) -> int:
    return 1 if _is_deletion_mechanism(pair_record) else 2


def _none_order_and_actors(pair_record: dict[str, Any], ids: dict[str, str]) -> tuple[str, str, tuple[str, str]]:
    seed = int(pair_record["underlying_pair_seed"])
    motif = str(pair_record["motif"])
    actor_first = f"{ids['token']}:actor:a"
    actor_second = f"{ids['token']}:actor:b"
    if motif == "M1":
        actor_second = actor_first if seed % 2 == 0 else actor_second
        order = (ids["first_event"], ids["second_event"])
    elif motif == "M2":
        order = (
            (ids["first_event"], ids["second_event"])
            if seed % 2 == 0
            else (ids["second_event"], ids["first_event"])
        )
    else:
        order = (
            (ids["first_event"], ids["second_event"])
            if seed % 2 == 0
            else (ids["second_event"], ids["first_event"])
        )
    return actor_first, actor_second, order


def build_underlying_pair(pair_record: dict[str, Any]) -> SyntheticPair:
    profile = semantic_profile(str(pair_record["process_family"]), str(pair_record["motif"]))
    ids = _ids(pair_record)
    mechanism = str(pair_record["mechanism"])
    parameters = pair_record["parameters"]
    target_visible = int(parameters["visible_events"])
    if target_visible < 2:
        raise ValueError("visible event target must be at least 2")

    objects: list[fb.SourceObject] = []
    relations: list[tuple[str, str, str]] = []
    events: list[fb.SourceEvent] = []

    first_obj = ids["first_object"]
    second_obj = ids["second_object"]
    objects.extend(
        [
            fb.SourceObject(first_obj, profile.first_object_role),
            fb.SourceObject(second_obj, profile.second_object_role),
        ]
    )

    width = int(parameters["hidden_object_width"])
    for index in range(1, width + 1):
        objects.append(fb.SourceObject(f"{ids['token']}:object:alt:{index}", profile.second_object_role))

    relation_free_edges = int(parameters["relation_free_edges"])
    for index in range(1, relation_free_edges):
        objects.append(fb.SourceObject(f"{ids['token']}:relation:left:{index}", "RelationNoiseLeft"))
        objects.append(fb.SourceObject(f"{ids['token']}:relation:right:{index}", "RelationNoiseRight"))

    order_mechanism = _is_order_mechanism(pair_record)
    deletion_mechanism = _is_deletion_mechanism(pair_record)
    if order_mechanism:
        objects.extend(
            [
                fb.SourceObject(ids["case_a"], CASE_TYPE),
                fb.SourceObject(ids["case_b"], CASE_TYPE),
                fb.SourceObject(ids["case_shared"], CASE_TYPE),
                fb.SourceObject(ids["support_a"], SUPPORT_TYPE),
                fb.SourceObject(ids["support_b"], SUPPORT_TYPE),
            ]
        )
        relations.extend(
            [
                (CASE_RELATION, ids["support_a"], ids["case_shared"]),
                (CASE_RELATION, ids["support_b"], ids["case_shared"]),
            ]
        )
        first_case_bindings = (ids["case_a"], ids["support_a"])
        second_case_bindings = (ids["case_b"], ids["support_b"])
    else:
        objects.append(fb.SourceObject(ids["case_main"], CASE_TYPE))
        first_case_bindings = (ids["case_main"],)
        second_case_bindings = (ids["case_main"],)

    actor_first = f"{ids['token']}:actor:a"
    actor_second = f"{ids['token']}:actor:b"
    source_pair_order = (ids["first_event"], ids["second_event"])
    if mechanism == "none":
        actor_first, actor_second, source_pair_order = _none_order_and_actors(pair_record, ids)
    elif profile.motif_id == "M1":
        actor_second = actor_first
    elif profile.motif_id == "M2":
        source_pair_order = (ids["first_event"], ids["second_event"])
    elif profile.motif_id == "M3":
        source_pair_order = (ids["first_event"], ids["second_event"])

    if deletion_mechanism:
        objects.append(fb.SourceObject(ids["hidden_case_object"], "LatentOnly"))
        if profile.motif_id == "M2":
            first_bind = (ids["hidden_case_object"], first_obj)
            second_bind = second_case_bindings + (second_obj,)
        else:
            first_bind = first_case_bindings + (first_obj,)
            second_bind = (ids["hidden_case_object"], second_obj)
    else:
        first_bind = first_case_bindings + (first_obj,)
        second_bind = second_case_bindings + (second_obj,)

    events.extend(
        [
            fb.SourceEvent(ids["first_event"], profile.first_activity, actor_first, tuple(first_bind)),
            fb.SourceEvent(ids["second_event"], profile.second_activity, actor_second, tuple(second_bind)),
        ]
    )

    relations.append((INTERNAL_RELATION, first_obj, second_obj))
    for index in range(1, relation_free_edges):
        relations.append(
            (
                INTERNAL_RELATION,
                f"{ids['token']}:relation:left:{index}",
                f"{ids['token']}:relation:right:{index}",
            )
        )

    visible_motif_count = _visible_motif_event_count(pair_record)
    noise_count = target_visible - visible_motif_count
    if noise_count < 0:
        raise ValueError("visible event target is smaller than visible motif event count")
    noise_ids: list[str] = []
    for index in range(noise_count):
        event_id = f"{ids['token']}:event:noise:{index:02d}"
        noise_ids.append(event_id)
        if order_mechanism:
            case_id = f"{ids['token']}:case:noise:{index:02d}"
            objects.append(fb.SourceObject(case_id, CASE_TYPE))
        else:
            case_id = ids["case_main"]
        events.append(
            fb.SourceEvent(
                event_id,
                f"NoiseActivity{index % 3}",
                f"{ids['token']}:actor:noise:{index % 2}",
                (case_id,),
            )
        )

    pair_order = list(source_pair_order)
    pair_order.extend(noise_ids)
    execution = fb.SourceExecution(
        tuple(events),
        tuple(objects),
        tuple(relations),
        tuple(pair_order),
    )
    return SyntheticPair(
        pair_key=str(pair_record["pair_key"]),
        pair_seed=int(pair_record["underlying_pair_seed"]),
        profile=profile,
        execution=execution,
        source_sha256=source_execution_sha256(execution),
        first_event_id=ids["first_event"],
        second_event_id=ids["second_event"],
        first_hidden_object=first_obj,
        second_hidden_object=second_obj,
    )


def _constructor(case_view: str) -> cvc.CaseViewConstructor:
    if case_view == "CV-D":
        return cvc.CaseViewConstructor.cv_d(CASE_TYPE)
    if case_view == "CV-R1":
        return cvc.CaseViewConstructor.cv_r1(CASE_TYPE, (CASE_RELATION,))
    raise ValueError(case_view)


def _event_case_ids(view: cvc.CaseView) -> dict[str, tuple[str, ...]]:
    result: dict[str, set[str]] = {}
    for row in view.rows:
        result.setdefault(str(row.event_id), set()).add(str(row.case_id))
    return {event_id: tuple(sorted(values)) for event_id, values in result.items()}


def _source_event_map(execution: fb.SourceExecution) -> dict[str, fb.SourceEvent]:
    return {str(event.event_id): event for event in execution.events}


def _object_type_map(execution: fb.SourceExecution) -> dict[str, str]:
    return {str(obj.object_id): str(obj.object_type) for obj in execution.objects}


def _latent_bindings(execution: fb.SourceExecution, event: fb.SourceEvent) -> tuple[str, ...]:
    types = _object_type_map(execution)
    return tuple(
        sorted(
            str(object_id)
            for object_id in event.object_ids
            if types.get(str(object_id)) not in {CASE_TYPE, SUPPORT_TYPE, "LatentOnly"}
        )
    )


def _relation_domain(pair: SyntheticPair, pair_record: dict[str, Any], variable_relation: bool) -> tuple[tuple[tuple[str, str, str], ...], ...]:
    relevant = (INTERNAL_RELATION, pair.first_hidden_object, pair.second_hidden_object)
    if not variable_relation:
        return ((relevant,),)
    free_count = int(pair_record["parameters"]["relation_free_edges"])
    edges: list[tuple[str, str, str]] = [relevant]
    token = _ids(pair_record)["token"]
    for index in range(1, free_count):
        edges.append(
            (
                INTERNAL_RELATION,
                f"{token}:relation:left:{index}",
                f"{token}:relation:right:{index}",
            )
        )
    choices: list[tuple[tuple[str, str, str], ...]] = []
    for mask in range(1 << len(edges)):
        selected = tuple(edges[index] for index in range(len(edges)) if mask & (1 << index))
        choices.append(selected)
    return tuple(choices)


def _motif(pair: SyntheticPair) -> Any:
    profile = pair.profile
    if profile.motif_id == "M1":
        return fb.PairMotif(
            profile.first_activity,
            profile.second_activity,
            actor_relation="same",
            order_relation="before",
            require_shared_hidden_object=False,
            required_hidden_relation=INTERNAL_RELATION,
        )
    if profile.motif_id == "M2":
        return fb.MissingControlMotif(
            sensitive_activity=profile.second_activity,
            control_activity=profile.first_activity,
            require_shared_hidden_object=False,
            control_must_be_before=True,
            required_hidden_relation=INTERNAL_RELATION,
            anchor_event_id=pair.second_event_id,
        )
    if profile.motif_id == "M3":
        return fb.PairMotif(
            profile.first_activity,
            profile.second_activity,
            actor_relation="any",
            order_relation="before",
            require_shared_hidden_object=False,
            required_hidden_relation=INTERNAL_RELATION,
        )
    raise ValueError(profile.motif_id)


def build_cell(pair_record: dict[str, Any], case_view: str) -> SyntheticCell:
    pair = build_underlying_pair(pair_record)
    constructor = _constructor(case_view)
    view = cvc.flatten_with_constructor(pair.execution, constructor)
    visible_ids = {str(row.event_id) for row in view.rows}
    event_map = _source_event_map(pair.execution)

    mechanism = str(pair_record["mechanism"])
    motif_id = str(pair_record["motif"])
    if mechanism == "mixed":
        variable_mechanisms = tuple(str(value) for value in pair_record["mixed_recipe"])
    elif mechanism == "none":
        variable_mechanisms = ()
    else:
        variable_mechanisms = (mechanism,)

    binding_variable = "binding" in variable_mechanisms
    relation_variable = "relation" in variable_mechanisms
    deletion_variable = "deletion" in variable_mechanisms

    domains: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
    token = _ids(pair_record)["token"]
    width = int(pair_record["parameters"]["hidden_object_width"])
    for event_id in sorted(visible_ids):
        event = event_map[event_id]
        actual = _latent_bindings(pair.execution, event)
        if binding_variable and event_id == pair.second_event_id:
            choices: list[tuple[str, ...]] = [(pair.second_hidden_object,)]
            for index in range(1, width + 1):
                choices.append((f"{token}:object:alt:{index}",))
            domains.append((event_id, tuple(choices)))
        else:
            domains.append((event_id, (actual,)))

    optional_deleted: list[fb.DeletedEventTemplate] = []
    deleted_id: str | None = None
    if deletion_variable:
        if motif_id == "M2":
            deleted_id = pair.first_event_id
            before_event_id = pair.second_event_id
            after_event_id = None
        else:
            deleted_id = pair.second_event_id
            before_event_id = None
            after_event_id = pair.first_event_id
        hidden_event = event_map[deleted_id]
        hidden_objects = _latent_bindings(pair.execution, hidden_event)
        optional_deleted.append(
            fb.DeletedEventTemplate(
                fb.Event(
                    event_id=deleted_id,
                    activity=hidden_event.activity,
                    actor=hidden_event.actor,
                    case_ids=(),
                    hidden_objects=hidden_objects,
                ),
                before_event_id=before_event_id,
                after_event_id=after_event_id,
            )
        )

    spec = fb.Spec(
        hidden_binding_domains=tuple(domains),
        hidden_relation_domain=_relation_domain(pair, pair_record, relation_variable),
        optional_deleted_events=tuple(optional_deleted),
    )
    cell_meta = pair_record["cells"][case_view]
    return SyntheticCell(
        cell_id=str(cell_meta["cell_id"]),
        pair_key=str(pair_record["pair_key"]),
        original_cell_seed=int(cell_meta["original_cell_seed"]),
        pair_seed=int(pair_record["underlying_pair_seed"]),
        process_family=str(pair_record["process_family"]),
        motif_id=motif_id,
        mechanism=mechanism,
        mixed_recipe=tuple(str(value) for value in pair_record["mixed_recipe"]),
        tier=str(pair_record["tier"]),
        replicate=int(pair_record["replicate"]),
        semantic_map_id=str(pair_record["semantic_map_id"]),
        structural_parameters={str(k): int(v) for k, v in pair_record["parameters"].items()},
        underlying_execution=pair.execution,
        underlying_execution_sha256=pair.source_sha256,
        constructor=constructor,
        view=view,
        spec=spec,
        motif=_motif(pair),
        variable_mechanisms=variable_mechanisms,
        motif_event_ids_value=(pair.first_event_id, pair.second_event_id),
        deleted_motif_event_id_value=deleted_id,
    )


def motif_event_ids(cell: SyntheticCell) -> tuple[str, str]:
    return cell.motif_event_ids_value


def deleted_motif_event_id(cell: SyntheticCell) -> str:
    if cell.deleted_motif_event_id_value is None:
        raise ValueError("cell has no motif-relevant deleted event")
    return cell.deleted_motif_event_id_value
