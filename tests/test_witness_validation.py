from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from sscv import witness_validation as iwv
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


class IndependentWitnessValidatorTests(unittest.TestCase):
    def binding_case(self):
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
        return view, spec, motif, result.witness

    def test_accepts_valid_smt_binding_witness_and_computes_objective(self):
        view, spec, motif, witness = self.binding_case()
        report = iwv.validate_witness(
            view,
            spec,
            motif,
            witness.safe_execution,
            witness.violating_execution,
        )
        self.assertTrue(report.valid, report.errors)
        self.assertFalse(report.safe_verdict)
        self.assertTrue(report.violating_verdict)
        self.assertEqual(report.objective, (2, 0, 2, 0, 0, 1, 2))

    def test_rejects_visible_view_change(self):
        view, spec, motif, witness = self.binding_case()
        bad_events = tuple(
            smt.SMTEvent(
                event.event_id,
                event.activity,
                event.actor,
                ("C9",) if event.event_id == "e_req" else event.case_ids,
                event.hidden_objects,
            )
            for event in witness.safe_execution.events
        )
        bad = smt.SMTExecution(
            bad_events,
            witness.safe_execution.order,
            witness.safe_execution.hidden_relations,
        )
        report = iwv.validate_witness(
            view, spec, motif, bad, witness.violating_execution
        )
        self.assertFalse(report.valid)
        self.assertIn(
            "safe_execution_does_not_reflatten_to_view", report.errors
        )

    def test_rejects_binding_outside_declared_domain(self):
        view, spec, motif, witness = self.binding_case()
        bad_events = tuple(
            smt.SMTEvent(
                event.event_id,
                event.activity,
                event.actor,
                event.case_ids,
                ("OUTSIDE",)
                if event.event_id == "e_app"
                else event.hidden_objects,
            )
            for event in witness.safe_execution.events
        )
        bad = smt.SMTExecution(
            bad_events,
            witness.safe_execution.order,
            witness.safe_execution.hidden_relations,
        )
        report = iwv.validate_witness(
            view, spec, motif, bad, witness.violating_execution
        )
        self.assertFalse(report.valid)
        self.assertIn("safe_execution_not_admissible", report.errors)

    def test_rejects_same_verdict_pair(self):
        view, spec, motif, witness = self.binding_case()
        report = iwv.validate_witness(
            view,
            spec,
            motif,
            witness.violating_execution,
            witness.violating_execution,
        )
        self.assertFalse(report.valid)
        self.assertIn("witness_verdicts_are_not_opposite", report.errors)

    def test_accepts_deleted_control_witness(self):
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
        report = iwv.validate_witness(
            view,
            spec,
            motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        self.assertTrue(report.valid, report.errors)
        self.assertEqual(report.objective, (3, 1, 1, 0, 1, 2, 1))

    def test_accepts_relation_based_missing_control_witness(self):
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
        report = iwv.validate_witness(
            view,
            spec,
            motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        self.assertTrue(report.valid, report.errors)
        self.assertEqual(report.objective[3], 1)


if __name__ == "__main__":
    unittest.main()
