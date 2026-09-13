from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CaseViewConstructor:
    constructor_id: str
    case_object_type: str
    relation_qualifiers: tuple[str, ...] = ()

    @classmethod
    def cv_d(cls, case_object_type: str) -> "CaseViewConstructor":
        if not case_object_type:
            raise ValueError("case_object_type is required")
        return cls("CV-D", case_object_type, ())

    @classmethod
    def cv_r1(
        cls,
        case_object_type: str,
        relation_qualifiers: tuple[str, ...],
    ) -> "CaseViewConstructor":
        if not case_object_type:
            raise ValueError("case_object_type is required")
        qualifiers = tuple(sorted(set(relation_qualifiers)))
        if not qualifiers:
            raise ValueError(
                "CV-R1 requires at least one frozen relation qualifier"
            )
        return cls("CV-R1", case_object_type, qualifiers)


@dataclass(frozen=True)
class CaseRow:
    case_id: str
    rank: int
    event_id: str
    activity: str
    actor: str | None


@dataclass(frozen=True)
class CaseView:
    rows: tuple[CaseRow, ...]


def _object_types(execution: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for obj in execution.objects:
        object_id = str(obj.object_id)
        if object_id in result:
            raise ValueError(f"duplicate object id: {object_id}")
        result[object_id] = str(obj.object_type)
    return result


def _event_ids(execution: Any) -> set[str]:
    ids = [str(event.event_id) for event in execution.events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event id")
    return set(ids)


def _relation_neighbors(
    execution: Any, qualifiers: set[str]
) -> dict[str, set[str]]:
    neighbors: dict[str, set[str]] = {}
    for relation_type, left, right in execution.relations:
        if relation_type not in qualifiers:
            continue
        neighbors.setdefault(str(left), set()).add(str(right))
        neighbors.setdefault(str(right), set()).add(str(left))
    return neighbors


def case_assignment(
    execution: Any, constructor: CaseViewConstructor
) -> dict[str, tuple[str, ...]]:
    object_types = _object_types(execution)
    _event_ids(execution)
    case_objects = sorted(
        object_id
        for object_id, object_type in object_types.items()
        if object_type == constructor.case_object_type
    )
    case_set = set(case_objects)
    qualifiers = set(constructor.relation_qualifiers)
    neighbors = (
        _relation_neighbors(execution, qualifiers)
        if constructor.constructor_id == "CV-R1"
        else {}
    )

    result: dict[str, tuple[str, ...]] = {}
    for event in execution.events:
        bound = tuple(str(object_id) for object_id in event.object_ids)
        unknown = [
            object_id for object_id in bound if object_id not in object_types
        ]
        if unknown:
            raise ValueError(
                f"event {event.event_id} binds unknown objects: {unknown}"
            )

        assigned = set(bound).intersection(case_set)
        if constructor.constructor_id == "CV-R1":
            for bound_object in bound:
                for adjacent in neighbors.get(bound_object, set()):
                    if adjacent in case_set:
                        assigned.add(adjacent)
        elif constructor.constructor_id != "CV-D":
            raise ValueError(
                f"unsupported constructor: {constructor.constructor_id}"
            )
        result[str(event.event_id)] = tuple(sorted(assigned))
    return result


def flatten_with_constructor(
    execution: Any, constructor: CaseViewConstructor
) -> CaseView:
    assignment = case_assignment(execution, constructor)
    position = {
        str(event_id): index
        for index, event_id in enumerate(execution.order)
    }
    event_ids = _event_ids(execution)
    if set(position) != event_ids or len(position) != len(event_ids):
        raise ValueError("execution order must contain every event exactly once")

    event_map = {
        str(event.event_id): event for event in execution.events
    }
    rows: list[CaseRow] = []
    all_case_ids = sorted(
        {case_id for ids in assignment.values() for case_id in ids}
    )
    for case_id in all_case_ids:
        events = [
            event_map[event_id]
            for event_id, case_ids in assignment.items()
            if case_id in case_ids
        ]
        events.sort(
            key=lambda event: (
                position[str(event.event_id)],
                str(event.event_id),
            )
        )
        for rank, event in enumerate(events):
            rows.append(
                CaseRow(
                    case_id,
                    rank,
                    str(event.event_id),
                    str(event.activity),
                    event.actor,
                )
            )
    return CaseView(tuple(rows))
