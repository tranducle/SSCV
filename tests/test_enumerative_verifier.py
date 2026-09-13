from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from sscv import enumerative_verifier as sv
except ModuleNotFoundError:
    sv = None


class FlattenSemanticsTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(sv, "sscv_verifier module must exist")

    def test_flatten_deletes_event_without_case_assignment(self):
        self.require_module()
        execution = sv.Execution(
            events=(
                sv.Event("e1", "request", "alice", ("C1",), ()),
                sv.Event("e_hidden", "control", "bob", (), ("H1",)),
            ),
            order=("e1", "e_hidden"),
        )

        view = sv.flatten(execution)

        self.assertEqual([row.event_id for row in view.rows], ["e1"])
        self.assertEqual(view.rows[0].case_id, "C1")

    def test_flatten_replicates_one_event_across_multiple_cases(self):
        self.require_module()
        execution = sv.Execution(
            events=(
                sv.Event("e_shared", "approve", "alice", ("C1", "C2"), ("H1",)),
            ),
            order=("e_shared",),
        )

        view = sv.flatten(execution)

        self.assertEqual(len(view.rows), 2)
        self.assertEqual([row.case_id for row in view.rows], ["C1", "C2"])
        self.assertEqual([row.event_id for row in view.rows], ["e_shared", "e_shared"])


class BoundedVerifierBindingTests(unittest.TestCase):
    def setUp(self):
        for name in ("PairMotif", "CompletionSpec", "verify", "evaluate_motif"):
            self.assertTrue(hasattr(sv, name), f"sscv_verifier must provide {name}")
        self.base = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ()),
                sv.Event("e_app", "approve", "alice", ("C2",), ()),
            ),
            order=("e_req", "e_app"),
        )
        self.view = sv.flatten(self.base)
        self.motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            actor_relation="same",
            order_relation="any",
            require_shared_hidden_object=True,
        )

    def test_fixed_hidden_binding_yields_sound_bounded_verdict(self):
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",),)),
            ),
        )

        result = sv.verify(self.view, spec, self.motif)

        self.assertEqual(result.decision, "sound")
        self.assertEqual(result.verdicts, (True,))
        self.assertTrue(result.complete)
        self.assertIsNone(result.witness)

    def test_hidden_binding_choice_yields_unsound_opposite_verdict_witness(self):
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",), ("H2",))),
            ),
        )

        result = sv.verify(self.view, spec, self.motif)

        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertIsNotNone(result.witness)
        self.assertTrue(result.witness.valid)
        self.assertTrue(result.witness.minimal)
        self.assertEqual(result.witness.objective[0], 2)
        self.assertEqual(
            sv.flatten(result.witness.safe_execution).canonical(),
            self.view.canonical(),
        )
        self.assertEqual(
            sv.flatten(result.witness.violating_execution).canonical(),
            self.view.canonical(),
        )
        self.assertFalse(sv.evaluate_motif(result.witness.safe_execution, self.motif))
        self.assertTrue(sv.evaluate_motif(result.witness.violating_execution, self.motif))


class BoundedVerifierOrderAndUnknownTests(unittest.TestCase):
    def test_cross_case_order_freedom_yields_unsound(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ()),
                sv.Event("e_app", "approve", "bob", ("C2",), ()),
            ),
            order=("e_req", "e_app"),
        )
        view = sv.flatten(execution)
        motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            order_relation="before",
            require_shared_hidden_object=False,
        )

        result = sv.verify(view, sv.CompletionSpec(), motif)

        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)
        self.assertEqual(result.witness.objective, (2, 0, 0, 0, 2, 2, 0))

    def test_same_case_order_is_preserved_and_sound(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ()),
                sv.Event("e_app", "approve", "bob", ("C1",), ()),
            ),
            order=("e_req", "e_app"),
        )
        view = sv.flatten(execution)
        motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            order_relation="before",
            require_shared_hidden_object=False,
        )

        result = sv.verify(view, sv.CompletionSpec(), motif)

        self.assertEqual(result.decision, "sound")
        self.assertEqual(result.verdicts, (True,))
        self.assertTrue(result.complete)

    def test_completion_cap_without_opposite_verdict_returns_unknown(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ()),
                sv.Event("e_app", "approve", "alice", ("C2",), ()),
            ),
            order=("e_req", "e_app"),
        )
        view = sv.flatten(execution)
        motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            actor_relation="same",
            require_shared_hidden_object=True,
        )
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",), ("H2",))),
            ),
            max_completions=1,
        )

        result = sv.verify(view, spec, motif)

        self.assertEqual(result.decision, "unknown")
        self.assertFalse(result.complete)
        self.assertEqual(result.unknown_reason, "completion_cap_reached")
        self.assertEqual(result.explored, 1)


class BoundedVerifierRelationAndDeletionTests(unittest.TestCase):
    def test_hidden_relation_choice_yields_unsound(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ("H1",)),
                sv.Event("e_app", "approve", "alice", ("C2",), ("H2",)),
            ),
            order=("e_req", "e_app"),
        )
        view = sv.flatten(execution)
        motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            actor_relation="same",
            order_relation="any",
            require_shared_hidden_object=False,
            required_hidden_relation="linked",
        )
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H2",),)),
            ),
            hidden_relation_domain=(
                (),
                (("linked", "H1", "H2"),),
            ),
        )

        result = sv.verify(view, spec, motif)

        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)
        self.assertEqual(result.witness.objective, (1, 0, 0, 1, 0, 0, 2))

    def test_optional_deleted_control_yields_missing_control_ambiguity(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_sensitive", "sensitive", "alice", ("C1",), ("H1",)),
            ),
            order=("e_sensitive",),
        )
        view = sv.flatten(execution)
        motif = sv.MissingControlMotif(
            sensitive_activity="sensitive",
            control_activity="control",
            require_shared_hidden_object=True,
            control_must_be_before=True,
        )
        hidden_control = sv.DeletedEventTemplate(
            event=sv.Event("e_control", "control", "bob", (), ("H1",)),
            before_event_id="e_sensitive",
        )
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_sensitive", (("H1",),)),
            ),
            optional_deleted_events=(hidden_control,),
        )

        result = sv.verify(view, spec, motif)

        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)
        self.assertEqual(result.witness.objective, (3, 1, 1, 0, 1, 2, 1))
        self.assertEqual(
            sv.flatten(result.witness.safe_execution).canonical(),
            view.canonical(),
        )
        self.assertEqual(
            sv.flatten(result.witness.violating_execution).canonical(),
            view.canonical(),
        )

    def test_missing_control_relation_choice_yields_ambiguity(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_control", "control", "bob", ("C1",), ("HC",)),
                sv.Event("e_sensitive", "sensitive", "alice", ("C1",), ("HS",)),
            ),
            order=("e_control", "e_sensitive"),
        )
        view = sv.flatten(execution)
        motif = sv.MissingControlMotif(
            sensitive_activity="sensitive",
            control_activity="control",
            require_shared_hidden_object=False,
            control_must_be_before=True,
            required_hidden_relation="linked",
        )
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_control", (("HC",),)),
                ("e_sensitive", (("HS",),)),
            ),
            hidden_relation_domain=((), (("linked", "HC", "HS"),)),
        )

        result = sv.verify(view, spec, motif)

        self.assertEqual(result.decision, "unsound")
        self.assertEqual(result.verdicts, (False, True))
        self.assertTrue(result.witness.valid)
        self.assertEqual(result.witness.objective[3], 1)


class NaiveCaseLocalComparatorTests(unittest.TestCase):
    def test_naive_case_local_monitor_can_report_safe_when_sscv_is_ambiguous(self):
        execution = sv.Execution(
            events=(
                sv.Event("e_req", "request", "alice", ("C1",), ()),
                sv.Event("e_app", "approve", "alice", ("C2",), ()),
            ),
            order=("e_req", "e_app"),
        )
        view = sv.flatten(execution)
        motif = sv.PairMotif(
            first_activity="request",
            second_activity="approve",
            actor_relation="same",
            require_shared_hidden_object=True,
        )
        spec = sv.CompletionSpec(
            hidden_binding_domains=(
                ("e_req", (("H1",),)),
                ("e_app", (("H1",), ("H2",))),
            ),
        )

        naive_violation = sv.naive_case_local_pair_monitor(view, motif)
        result = sv.verify(view, spec, motif)

        self.assertFalse(naive_violation)
        self.assertEqual(result.decision, "unsound")
        self.assertIn(True, result.verdicts)


if __name__ == "__main__":
    unittest.main()
