from pathlib import Path
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from sscv import synthetic_pairing as pairing
except ModuleNotFoundError:
    pairing = None


class SyntheticPairingContractTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(pairing, "synthetic_pairing must exist")

    def test_frozen_manifest_has_exact_324_pairs_and_648_unique_cells(self):
        self.require_module()
        report = pairing.validate_pairing_manifest()
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["pair_count"], 324)
        self.assertEqual(report["referenced_cell_count"], 648)
        self.assertEqual(report["unique_referenced_cell_count"], 648)
        self.assertEqual(report["missing_cell_count"], 0)
        self.assertEqual(report["extra_cell_count"], 0)

    def test_every_pair_contains_one_direct_and_one_r1_cell(self):
        self.require_module()
        manifest = pairing.load_pairing_manifest()
        for item in manifest["pairs"]:
            self.assertEqual(set(item["cells"]), {"CV-D", "CV-R1"})
            self.assertNotEqual(
                item["cells"]["CV-D"]["cell_id"],
                item["cells"]["CV-R1"]["cell_id"],
            )

    def test_pair_seed_derivation_reproduces_all_frozen_seeds(self):
        self.require_module()
        manifest = pairing.load_pairing_manifest()
        seeds = []
        for item in manifest["pairs"]:
            derived = pairing.derive_pair_seed(
                manifest["source_base_seed"], item["pair_key"]
            )
            self.assertEqual(derived, item["underlying_pair_seed"])
            seeds.append(derived)
        self.assertEqual(len(set(seeds)), 324)

    def test_manifest_canonical_hash_is_exactly_frozen_value(self):
        self.require_module()
        report = pairing.validate_pairing_manifest()
        self.assertEqual(
            report["canonical_sha256"],
            "26a2f76d36f67c581bce529dd4a7896385485c342bca8ffa0a39419f3e555298",
        )
        self.assertTrue(report["canonical_hash_matches"])

    def test_original_cell_seeds_remain_view_specific_metadata(self):
        self.require_module()
        manifest = pairing.load_pairing_manifest()
        differing = 0
        for item in manifest["pairs"]:
            direct = item["cells"]["CV-D"]["original_cell_seed"]
            expanded = item["cells"]["CV-R1"]["original_cell_seed"]
            if direct != expanded:
                differing += 1
        self.assertGreater(differing, 0)


if __name__ == "__main__":
    unittest.main()
