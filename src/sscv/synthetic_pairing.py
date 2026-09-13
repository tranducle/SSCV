from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

PAIRING_DOMAIN = "SSCV-E3E4-PAIR-V1.1"
EXPECTED_MANIFEST_SHA256 = (
    "26a2f76d36f67c581bce529dd4a7896385485c342bca8ffa0a39419f3e555298"
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
PAIRING_PATH = CONFIG_ROOT / "pairing_manifest.json"
DESIGN_PATH = CONFIG_ROOT / "design_matrix.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_sha256_without_embedded_hash(payload: dict[str, Any]) -> str:
    body = dict(payload)
    body.pop("canonical_sha256", None)
    raw = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_pairing_manifest(path: str | Path = PAIRING_PATH) -> dict[str, Any]:
    return _load_json(Path(path))


def load_design_matrix(path: str | Path = DESIGN_PATH) -> dict[str, Any]:
    return _load_json(Path(path))


def derive_pair_seed(base_seed: str, pair_key: str) -> int:
    material = f"{PAIRING_DOMAIN}|{base_seed}|{pair_key}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:4], "big", signed=False)


def validate_pairing_manifest(
    manifest_path: str | Path = PAIRING_PATH,
    design_path: str | Path = DESIGN_PATH,
) -> dict[str, Any]:
    manifest = load_pairing_manifest(manifest_path)
    design = load_design_matrix(design_path)
    errors: list[str] = []
    references: list[str] = []
    derived_seeds: list[int] = []

    if manifest.get("pairing_domain") != PAIRING_DOMAIN:
        errors.append("pairing_domain_mismatch")

    base_seed = str(manifest.get("source_base_seed", ""))
    for item in manifest.get("pairs", ()): 
        cells = item.get("cells", {})
        if set(cells) != {"CV-D", "CV-R1"}:
            errors.append(f"{item.get('pair_key')}:case_view_pair_invalid")
            continue
        references.extend(
            [str(cells["CV-D"]["cell_id"]), str(cells["CV-R1"]["cell_id"])]
        )
        derived = derive_pair_seed(base_seed, str(item["pair_key"]))
        derived_seeds.append(derived)
        if derived != int(item["underlying_pair_seed"]):
            errors.append(f"{item['pair_key']}:pair_seed_mismatch")

    design_ids = {str(cell["cell_id"]) for cell in design.get("cells", ())}
    reference_set = set(references)
    missing = sorted(design_ids - reference_set)
    extra = sorted(reference_set - design_ids)
    if len(references) != len(reference_set):
        errors.append("duplicate_cell_reference")
    if missing:
        errors.append("missing_frozen_cells")
    if extra:
        errors.append("extra_cell_references")
    if len(derived_seeds) != len(set(derived_seeds)):
        errors.append("duplicate_underlying_pair_seed")

    actual_hash = _canonical_sha256_without_embedded_hash(manifest)
    embedded_hash = str(manifest.get("canonical_sha256", ""))
    hash_matches = (
        actual_hash == embedded_hash == EXPECTED_MANIFEST_SHA256
    )
    if not hash_matches:
        errors.append("canonical_hash_mismatch")

    return {
        "valid": not errors,
        "errors": errors,
        "pair_count": len(manifest.get("pairs", ())),
        "referenced_cell_count": len(references),
        "unique_referenced_cell_count": len(reference_set),
        "missing_cell_count": len(missing),
        "extra_cell_count": len(extra),
        "unique_pair_seed_count": len(set(derived_seeds)),
        "canonical_sha256": actual_hash,
        "canonical_hash_matches": hash_matches,
    }
