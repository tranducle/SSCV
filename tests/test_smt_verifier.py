from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from sscv import smt_verifier as smt


@dataclass(frozen=True)
class Row:
    case_id: str
    rank: int
    event_id: str
    activity: str
    actor: str | None


@dataclass(frozen=True)
class View:
    rows: tuple[Row, ...]


@dataclass(frozen=True)
class Event:
    event_id: str
    activity: str
    actor: str | None
    case_ids: tuple[str, ...] = ()
    hidden_objects: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeletedEventTemplate:
    event: Event
    before_event_id: str | None = None
    after_event_id: str | None = None


@dataclass(frozen=True)
class Spec:
    hidden_binding_domains: tuple[
        tuple[str, tuple[tuple[str, ...], ...]], ...
    ] = ()
    hidden_relation_domain: tuple[
        tuple[tuple[str, str, str], ...], ...
    ] = ((),)
    optional_deleted_events: tuple[DeletedEventTemplate, ...] = ()


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


class SMTVerifierTests(unittest.TestCase):
    def require_solver(self):
        self.assertIsNotNone(
            smt.default_solver(), "a real Z3-compatible backend must be available"
        )

    def test_fixed_hidden_binding_is_sound_violation(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_req", "request", "alice"),
                Row("C2", 0, "e_app", "approve", "alice"),
            )
        )
        spec = Spec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",),)),
            )
        )
        motif = PairMotif("request", "approve", actor_relation="same")
        result = smt.verify_smt(view, spec, motif)
        self.assertEqual(result.decision, "sound")
        self.assertEqual(result.verdicts, (True,))
        self.assertTrue(result.complete)

    def test_hidden_binding_choice_is_unsound_with_valid_witness(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_req", "request", "alice"),
                Row("C2", 0, "e_app", "approve", "alice"),
            )
        )
        spec = Spec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",), ("H2",))),
            )
        )
        motif = PairMotif("request", "approve", actor_relation="same")
        result = smt.verify_smt(view, spec, motif)
        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertIsNotNone(result.witness)
        self.assertTrue(result.witness.valid)
        self.assertFalse(result.witness.minimal)
        self.assertEqual(
            smt.flatten_canonical(result.witness.safe_execution),
            smt.view_canonical(view),
        )
        self.assertEqual(
            smt.flatten_canonical(result.witness.violating_execution),
            smt.view_canonical(view),
        )

    def test_cross_case_order_ambiguity_is_unsound(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_req", "request", "alice"),
                Row("C2", 0, "e_app", "approve", "bob"),
            )
        )
        motif = PairMotif(
            "request",
            "approve",
            order_relation="before",
            require_shared_hidden_object=False,
        )
        result = smt.verify_smt(view, Spec(), motif)
        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)

    def test_hidden_relation_choice_is_unsound(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_req", "request", "alice"),
                Row("C2", 0, "e_app", "approve", "alice"),
            )
        )
        spec = Spec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H2",),)),
            ),
            hidden_relation_domain=((), (("linked", "H1", "H2"),)),
        )
        motif = PairMotif(
            "request",
            "approve",
            actor_relation="same",
            require_shared_hidden_object=False,
            required_hidden_relation="linked",
        )
        result = smt.verify_smt(view, spec, motif)
        self.assertEqual(result.decision, "unsound")
        self.assertTrue(result.witness.valid)

    def test_optional_deleted_control_is_unsound(self):
        self.require_solver()
        view = View((Row("C1", 0, "e_sensitive", "sensitive", "alice"),))
        deleted = DeletedEventTemplate(
            Event("e_control", "control", "bob", (), ("H1",)),
            before_event_id="e_sensitive",
        )
        spec = Spec(
            hidden_binding_domains=(("e_sensitive", (("H1",),)),),
            optional_deleted_events=(deleted,),
        )
        motif = MissingControlMotif("sensitive", "control")
        result = smt.verify_smt(view, spec, motif)
        self.assertEqual(result.decision, "unsound")
        self.assertTrue(result.witness.valid)

    def test_missing_control_relation_choice_is_unsound(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_control", "control", "bob"),
                Row("C1", 1, "e_sensitive", "sensitive", "alice"),
            )
        )
        spec = Spec(
            hidden_binding_domains=(
                ("e_control", (("HC",),)),
                ("e_sensitive", (("HS",),)),
            ),
            hidden_relation_domain=((), (("linked", "HC", "HS"),)),
        )
        motif = MissingControlMotif(
            "sensitive",
            "control",
            require_shared_hidden_object=False,
            control_must_be_before=True,
            required_hidden_relation="linked",
        )
        result = smt.verify_smt(view, spec, motif)
        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)

    def test_one_query_budget_returns_unknown(self):
        self.require_solver()
        view = View(
            (
                Row("C1", 0, "e_req", "request", "alice"),
                Row("C2", 0, "e_app", "approve", "alice"),
            )
        )
        spec = Spec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",), ("H2",))),
            )
        )
        motif = PairMotif("request", "approve", actor_relation="same")
        result = smt.verify_smt(
            view,
            spec,
            motif,
            max_queries=1,
            query_order=("safe", "violation"),
        )
        self.assertEqual(result.decision, "unknown")
        self.assertFalse(result.complete)
        self.assertEqual(
            result.unknown_reason, "operational_query_budget_exhausted"
        )
        self.assertEqual(len(result.solver_statuses), 1)


if __name__ == "__main__":
    unittest.main()
