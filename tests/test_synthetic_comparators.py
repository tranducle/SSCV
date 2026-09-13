from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sscv import synthetic_generator as gen
from sscv import synthetic_pairing as pairing

try:
    from sscv import synthetic_comparators as comp
except ModuleNotFoundError:
    comp = None


def pair_record(key: str):
    manifest = pairing.load_pairing_manifest()
    return next(item for item in manifest["pairs"] if item["pair_key"] == key)


class SyntheticComparatorTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(comp, "synthetic_comparators must exist")

    def test_m1_order_direct_closed_world_is_safe_and_open_world_abstains(self):
        self.require_module()
        record = pair_record("request_approval_release|M1|order|S|r1")
        direct = gen.build_cell(record, "CV-D")
        expanded = gen.build_cell(record, "CV-R1")
        self.assertEqual(comp.b0_realized(direct), "violation")
        self.assertEqual(comp.b1_closed_world(direct), "safe")
        self.assertEqual(comp.b2_open_world(direct), "unknown")
        self.assertEqual(comp.b1_closed_world(expanded), "violation")
        self.assertEqual(comp.b2_open_world(expanded), "violation")

    def test_m2_deletion_realized_execution_is_safe_but_case_views_cannot_see_control(self):
        self.require_module()
        record = pair_record("procure_to_pay|M2|deletion|S|r1")
        for view_id in ("CV-D", "CV-R1"):
            cell = gen.build_cell(record, view_id)
            self.assertEqual(comp.b0_realized(cell), "safe")
            self.assertEqual(comp.b1_closed_world(cell), "violation")
            self.assertEqual(comp.b2_open_world(cell), "unknown")

    def test_m2_none_with_control_after_action_is_realized_violation(self):
        self.require_module()
        record = pair_record("procure_to_pay|M2|none|S|r1")
        cell = gen.build_cell(record, "CV-D")
        self.assertEqual(comp.b0_realized(cell), "violation")
        self.assertEqual(comp.b1_closed_world(cell), "violation")
        self.assertEqual(comp.b2_open_world(cell), "violation")

    def test_m3_order_is_unknown_case_locally_in_direct_and_violation_in_r1(self):
        self.require_module()
        record = pair_record("change_approval_deployment|M3|order|S|r1")
        direct = gen.build_cell(record, "CV-D")
        expanded = gen.build_cell(record, "CV-R1")
        self.assertEqual(comp.b0_realized(direct), "violation")
        self.assertEqual(comp.b1_closed_world(direct), "safe")
        self.assertEqual(comp.b2_open_world(direct), "unknown")
        self.assertEqual(comp.b1_closed_world(expanded), "violation")
        self.assertEqual(comp.b2_open_world(expanded), "violation")

    def test_m1_none_safe_actor_separation_is_evaluable(self):
        self.require_module()
        # Choose a frozen pair whose seed parity makes M1 actors different.
        manifest = pairing.load_pairing_manifest()
        record = next(
            item
            for item in manifest["pairs"]
            if item["process_family"] == "request_approval_release"
            and item["motif"] == "M1"
            and item["mechanism"] == "none"
            and int(item["underlying_pair_seed"]) % 2 == 1
        )
        cell = gen.build_cell(record, "CV-D")
        self.assertEqual(comp.b0_realized(cell), "safe")
        self.assertEqual(comp.b1_closed_world(cell), "safe")
        self.assertEqual(comp.b2_open_world(cell), "safe")


if __name__ == "__main__":
    unittest.main()
