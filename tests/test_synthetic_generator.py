from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sscv import case_views as cvc
from sscv import synthetic_pairing as pairing

try:
    from sscv import synthetic_generator as gen
except ModuleNotFoundError:
    gen = None


EXPECTED_PROFILES = {
    ("request_approval_release", "M1"): ("SubmitRequest", "ApproveRequest", "Request", "Approval", "request_to_approval"),
    ("request_approval_release", "M2"): ("ApproveRequest", "Release", "Approval", "ReleaseArtifact", "approval_to_release"),
    ("request_approval_release", "M3"): ("Release", "ApproveRequest", "ReleaseArtifact", "Approval", "approval_to_release"),
    ("procure_to_pay", "M1"): ("CreatePurchaseRequest", "ApprovePayment", "PurchaseRequest", "Payment", "request_to_payment"),
    ("procure_to_pay", "M2"): ("ApprovePayment", "ExecutePayment", "PaymentApproval", "Payment", "approval_to_payment"),
    ("procure_to_pay", "M3"): ("ExecutePayment", "ApprovePayment", "Payment", "PaymentApproval", "approval_to_payment"),
    ("change_approval_deployment", "M1"): ("SubmitChange", "ApproveChange", "ChangeRequest", "ChangeApproval", "change_to_approval"),
    ("change_approval_deployment", "M2"): ("ApproveChange", "DeployChange", "ChangeApproval", "Deployment", "approval_to_deployment"),
    ("change_approval_deployment", "M3"): ("DeployChange", "ApproveChange", "Deployment", "ChangeApproval", "approval_to_deployment"),
}


def pair_record(process, motif, mechanism="none", tier="S", replicate=1):
    key = f"{process}|{motif}|{mechanism}|{tier}|r{replicate}"
    manifest = pairing.load_pairing_manifest()
    return next(item for item in manifest["pairs"] if item["pair_key"] == key)


class SyntheticGeneratorTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(gen, "synthetic_generator must exist")

    def test_all_nine_semantic_profiles_use_frozen_activity_and_role_labels(self):
        self.require_module()
        for key, expected in EXPECTED_PROFILES.items():
            profile = gen.semantic_profile(*key)
            actual = (
                profile.first_activity,
                profile.second_activity,
                profile.first_object_role,
                profile.second_object_role,
                profile.relation_role,
            )
            self.assertEqual(actual, expected, key)

    def test_pair_generation_is_deterministic_and_replicates_change_source_hash(self):
        self.require_module()
        p1 = pair_record("request_approval_release", "M1", "none", "S", 1)
        p1_again = pair_record("request_approval_release", "M1", "none", "S", 1)
        p2 = pair_record("request_approval_release", "M1", "none", "S", 2)
        a = gen.build_underlying_pair(p1)
        b = gen.build_underlying_pair(p1_again)
        c = gen.build_underlying_pair(p2)
        self.assertEqual(gen.canonical_source_execution(a.execution), gen.canonical_source_execution(b.execution))
        self.assertEqual(a.source_sha256, b.source_sha256)
        self.assertNotEqual(a.source_sha256, c.source_sha256)

    def test_view_specific_original_cell_seeds_do_not_change_underlying_execution(self):
        self.require_module()
        record = pair_record("procure_to_pay", "M2", "relation", "M", 1)
        direct = gen.build_cell(record, "CV-D")
        expanded = gen.build_cell(record, "CV-R1")
        self.assertNotEqual(direct.original_cell_seed, expanded.original_cell_seed)
        self.assertEqual(direct.underlying_execution_sha256, expanded.underlying_execution_sha256)
        self.assertEqual(
            gen.canonical_source_execution(direct.underlying_execution),
            gen.canonical_source_execution(expanded.underlying_execution),
        )

    def test_none_mechanism_is_fully_fixed(self):
        self.require_module()
        record = pair_record("request_approval_release", "M1", "none", "S", 1)
        for view_id in ("CV-D", "CV-R1"):
            cell = gen.build_cell(record, view_id)
            self.assertEqual(cell.variable_mechanisms, ())
            self.assertTrue(all(len(domain) == 1 for _, domain in cell.spec.hidden_binding_domains))
            self.assertEqual(len(cell.spec.hidden_relation_domain), 1)
            self.assertEqual(len(cell.spec.optional_deleted_events), 0)
            regenerated = cvc.flatten_with_constructor(cell.underlying_execution, cell.constructor)
            self.assertEqual(regenerated, cell.view)

    def test_binding_mechanism_only_varies_binding_domain(self):
        self.require_module()
        record = pair_record("procure_to_pay", "M2", "binding", "S", 1)
        cell = gen.build_cell(record, "CV-D")
        self.assertEqual(cell.variable_mechanisms, ("binding",))
        self.assertTrue(any(len(domain) > 1 for _, domain in cell.spec.hidden_binding_domains))
        self.assertEqual(len(cell.spec.hidden_relation_domain), 1)
        self.assertEqual(len(cell.spec.optional_deleted_events), 0)

    def test_relation_mechanism_only_varies_relation_domain(self):
        self.require_module()
        record = pair_record("change_approval_deployment", "M3", "relation", "M", 1)
        cell = gen.build_cell(record, "CV-D")
        self.assertEqual(cell.variable_mechanisms, ("relation",))
        self.assertTrue(all(len(domain) == 1 for _, domain in cell.spec.hidden_binding_domains))
        self.assertGreater(len(cell.spec.hidden_relation_domain), 1)
        self.assertEqual(len(cell.spec.optional_deleted_events), 0)

    def test_order_mechanism_is_cross_case_in_direct_and_shared_case_in_r1(self):
        self.require_module()
        record = pair_record("request_approval_release", "M3", "order", "M", 1)
        direct = gen.build_cell(record, "CV-D")
        expanded = gen.build_cell(record, "CV-R1")
        event_ids = set(gen.motif_event_ids(direct))
        direct_cases = {
            row.event_id: {r.case_id for r in direct.view.rows if r.event_id == row.event_id}
            for row in direct.view.rows if row.event_id in event_ids
        }
        expanded_cases = {
            event_id: {r.case_id for r in expanded.view.rows if r.event_id == event_id}
            for event_id in event_ids
        }
        e1, e2 = sorted(event_ids)
        self.assertFalse(direct_cases[e1].intersection(direct_cases[e2]))
        self.assertTrue(expanded_cases[e1].intersection(expanded_cases[e2]))
        self.assertEqual(direct.variable_mechanisms, ("order",))
        self.assertEqual(expanded.variable_mechanisms, ("order",))
        self.assertEqual(len(direct.spec.hidden_relation_domain), 1)
        self.assertEqual(len(direct.spec.optional_deleted_events), 0)

    def test_deletion_event_is_hidden_from_both_views_and_optional_in_both_specs(self):
        self.require_module()
        record = pair_record("procure_to_pay", "M2", "deletion", "S", 1)
        direct = gen.build_cell(record, "CV-D")
        expanded = gen.build_cell(record, "CV-R1")
        hidden_id = gen.deleted_motif_event_id(direct)
        self.assertNotIn(hidden_id, {r.event_id for r in direct.view.rows})
        self.assertNotIn(hidden_id, {r.event_id for r in expanded.view.rows})
        self.assertEqual(direct.variable_mechanisms, ("deletion",))
        self.assertEqual(expanded.variable_mechanisms, ("deletion",))
        self.assertIn(hidden_id, {x.event.event_id for x in direct.spec.optional_deleted_events})
        self.assertIn(hidden_id, {x.event.event_id for x in expanded.spec.optional_deleted_events})

    def test_mixed_mechanisms_match_frozen_recipe(self):
        self.require_module()
        expected = {
            "M1": ("binding", "relation"),
            "M2": ("deletion", "relation"),
            "M3": ("order", "relation"),
        }
        for motif, mechanisms in expected.items():
            record = pair_record("request_approval_release", motif, "mixed", "S", 1)
            cell = gen.build_cell(record, "CV-D")
            self.assertEqual(cell.variable_mechanisms, mechanisms)

    def test_visible_event_count_matches_frozen_tier_for_both_views(self):
        self.require_module()
        for mechanism in ("none", "binding", "relation", "order", "deletion", "mixed"):
            for tier, target in (("S", 6), ("M", 12), ("L", 24)):
                record = pair_record("change_approval_deployment", "M2", mechanism, tier, 1)
                for view_id in ("CV-D", "CV-R1"):
                    cell = gen.build_cell(record, view_id)
                    visible_ids = {row.event_id for row in cell.view.rows}
                    self.assertEqual(len(visible_ids), target, (mechanism, tier, view_id))
                    self.assertEqual(cell.structural_parameters["visible_events"], target)


if __name__ == "__main__":
    unittest.main()
