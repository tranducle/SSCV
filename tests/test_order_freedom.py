from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from sscv import order_freedom as ofm
except ModuleNotFoundError:
    ofm = None


class OrderFreedomManifestTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(ofm, "order_freedom must exist")

    def test_e7_manifest_has_exact_frozen_population(self):
        self.require_module()
        report = ofm.build_e7_manifest()
        self.assertEqual(report["base_case_count"], 108)
        self.assertEqual(len(report["instances"]), 108)
        self.assertEqual(len({x["base_cell_id"] for x in report["instances"]}), 108)
        for item in report["instances"]:
            self.assertTrue(item["reference_order"])
            self.assertEqual(len(item["reference_order"]), len(set(item["reference_order"])))
            self.assertEqual(item["selected_B0"], item["eligible_pairs"][:3])
            self.assertEqual(item["selected_B_plus_P"], item["eligible_pairs"][:4])

    def test_e11_manifest_has_exact_frozen_population(self):
        self.require_module()
        report = ofm.build_e11_manifest()
        self.assertEqual(report["cell_count"], 216)
        self.assertEqual(len(report["instances"]), 216)
        self.assertEqual(len({x["cell_id"] for x in report["instances"]}), 216)
        for item in report["instances"]:
            self.assertEqual(
                item["selected_pairs"],
                item["eligible_pairs"][: item["order_width"]],
            )

    def test_priority_puts_eligible_motif_pair_first(self):
        self.require_module()
        fixture = ofm.first_e7_order_sensitive_instance()
        if fixture["motif_pair_eligible"]:
            pair = tuple(sorted(fixture["motif_event_ids"]))
            self.assertEqual(tuple(fixture["eligible_pairs"][0]), pair)

    def test_every_selected_pair_is_eligible_and_not_visibly_ordered(self):
        self.require_module()
        for report in (ofm.build_e7_manifest(), ofm.build_e11_manifest()):
            for item in report["instances"]:
                eligible = {tuple(x) for x in item["eligible_pairs"]}
                selected = item.get("selected_B_plus_P", item.get("selected_pairs", []))
                self.assertTrue(all(tuple(x) in eligible for x in selected))
                visible = {tuple(x) for x in item["visible_precedence_closure"]}
                for left, right in selected:
                    self.assertNotIn((left, right), visible)
                    self.assertNotIn((right, left), visible)


if __name__ == "__main__":
    unittest.main()
