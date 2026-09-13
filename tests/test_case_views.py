from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from sscv import case_views as cvc


@dataclass(frozen=True)
class Event:
    event_id: str
    activity: str
    actor: str | None
    object_ids: tuple[str, ...]


@dataclass(frozen=True)
class Obj:
    object_id: str
    object_type: str


@dataclass(frozen=True)
class Execution:
    events: tuple[Event, ...]
    objects: tuple[Obj, ...]
    relations: tuple[tuple[str, str, str], ...]
    order: tuple[str, ...]


class ConstructorTests(unittest.TestCase):
    def base(self):
        return Execution(
            events=(
                Event("e1", "create", "alice", ("O1", "I1")),
                Event("e2", "approve", "bob", ("I1",)),
                Event("e3", "ship", "carol", ("P1",)),
            ),
            objects=(
                Obj("O1", "order"),
                Obj("I1", "item"),
                Obj("P1", "package"),
            ),
            relations=(
                ("contains", "O1", "I1"),
                ("packs", "I1", "P1"),
            ),
            order=("e1", "e2", "e3"),
        )

    def test_cv_d_assigns_only_events_directly_bound_to_case_type(self):
        execution = self.base()
        assignment = cvc.case_assignment(
            execution, cvc.CaseViewConstructor.cv_d("order")
        )
        self.assertEqual(
            assignment,
            {"e1": ("O1",), "e2": (), "e3": ()},
        )

    def test_cv_r1_assigns_event_to_case_when_bound_object_is_one_hop_related(self):
        execution = self.base()
        assignment = cvc.case_assignment(
            execution,
            cvc.CaseViewConstructor.cv_r1("order", ("contains",)),
        )
        self.assertEqual(
            assignment,
            {"e1": ("O1",), "e2": ("O1",), "e3": ()},
        )

    def test_cv_r1_does_not_traverse_two_hops(self):
        execution = self.base()
        assignment = cvc.case_assignment(
            execution,
            cvc.CaseViewConstructor.cv_r1(
                "order", ("contains", "packs")
            ),
        )
        self.assertEqual(assignment["e3"], ())

    def test_cv_r1_relation_direction_is_undirected_for_membership_only(self):
        execution = self.base()
        reversed_relation = Execution(
            execution.events,
            execution.objects,
            (
                ("contains", "I1", "O1"),
                ("packs", "I1", "P1"),
            ),
            execution.order,
        )
        assignment = cvc.case_assignment(
            reversed_relation,
            cvc.CaseViewConstructor.cv_r1("order", ("contains",)),
        )
        self.assertEqual(assignment["e2"], ("O1",))

    def test_flatten_from_constructor_replicates_shared_event_deterministically(self):
        execution = Execution(
            events=(Event("e1", "touch", "alice", ("I1", "I2")),),
            objects=(
                Obj("O1", "order"),
                Obj("O2", "order"),
                Obj("I1", "item"),
                Obj("I2", "item"),
            ),
            relations=(
                ("contains", "O1", "I1"),
                ("contains", "O2", "I2"),
            ),
            order=("e1",),
        )
        view = cvc.flatten_with_constructor(
            execution,
            cvc.CaseViewConstructor.cv_r1("order", ("contains",)),
        )
        self.assertEqual(
            [(row.case_id, row.event_id, row.rank) for row in view.rows],
            [("O1", "e1", 0), ("O2", "e1", 0)],
        )

    def test_cv_r1_rejects_missing_relation_qualifier_set(self):
        with self.assertRaises(ValueError):
            cvc.CaseViewConstructor.cv_r1("order", ())


if __name__ == "__main__":
    unittest.main()
