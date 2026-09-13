from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import time
from typing import Any

from . import completion_models as fb
from . import explicit_oracle as ex
from . import witness_validation as iwv
from . import smt_verifier as smt
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
MANIFEST = CONFIG_ROOT / "witness_manifest.json"
OUT = REPO_ROOT / "results" / "witness"
RESULT = OUT / "results.json"
SUMMARY = OUT / "summary.json"
RUN_MANIFEST = OUT / "run_manifest.json"
INTEGRITY_GATE = OUT / "integrity.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict[str, Any]:
    return _load(MANIFEST)


def _fixture_index() -> dict[str, Any]:
    return {fixture.case_id: fixture for fixture in fb.build_all_complete_fixtures()}


def evaluate_exact_fixture(fixture_id: str) -> dict[str, Any]:
    fixture = _fixture_index()[fixture_id]
    explicit = ex.verify_explicit(fixture.view, fixture.spec, fixture.motif)
    solver = smt.default_solver()
    if solver is None:
        raise RuntimeError("real Z3-compatible backend required")
    t0 = time.perf_counter()
    scalable = smt.verify_smt(fixture.view, fixture.spec, fixture.motif, solver=solver)
    elapsed = time.perf_counter() - t0

    witness_valid = False
    witness_errors: list[str] = []
    smt_objective = None
    if scalable.witness is not None:
        report = iwv.validate_witness(
            fixture.view,
            fixture.spec,
            fixture.motif,
            scalable.witness.safe_execution,
            scalable.witness.violating_execution,
        )
        witness_valid = bool(report.valid)
        witness_errors = list(report.errors)
        smt_objective = list(report.objective) if report.objective is not None else None

    explicit_objective = (
        list(explicit.witness.objective)
        if explicit.witness is not None and explicit.witness.minimal
        else None
    )
    objective_match = (
        smt_objective is not None
        and explicit_objective is not None
        and smt_objective == explicit_objective
    )
    return {
        "fixture_id": fixture.case_id,
        "motif": fixture.motif_id,
        "case_view": fixture.constructor_id,
        "mechanism": fixture.mechanism,
        "semantic_class": fixture.semantic_class,
        "explicit_decision": explicit.decision,
        "explicit_verdicts": ["violation" if x else "safe" for x in explicit.verdicts],
        "explicit_complete": bool(explicit.complete),
        "explicit_explored": int(explicit.explored),
        "explicit_minimal_objective": explicit_objective,
        "smt_decision": scalable.decision,
        "smt_verdicts": ["violation" if x else "safe" for x in scalable.verdicts],
        "smt_complete": bool(scalable.complete),
        "solver_statuses": list(scalable.solver_statuses),
        "smt_witness_returned": scalable.witness is not None,
        "smt_witness_valid": witness_valid,
        "smt_witness_errors": witness_errors,
        "smt_witness_objective": smt_objective,
        "objective_matches_explicit_minimum": bool(objective_match),
        "certified_minimal_on_exact_instance": bool(
            objective_match and explicit.complete and explicit.witness is not None and explicit.witness.minimal
        ),
        "smt_minimality_claimed": bool(
            scalable.witness is not None and scalable.witness.minimal
        ),
        "runtime_seconds": elapsed,
        "backend": scalable.backend,
    }


def run_exact_population() -> list[dict[str, Any]]:
    ids = list(load_manifest()["exact_minimality_population"]["fixture_ids"])
    return [evaluate_exact_fixture(fixture_id) for fixture_id in ids]


def load_e11_overhead_rows() -> list[dict[str, Any]]:
    path = REPO_ROOT / "results" / "scaling" / "baseline" / "witness_overhead.json"
    rows = list(_load(path)["rows"])
    selected = set(load_manifest()["overhead_population"]["cell_ids"])
    return [row for row in rows if str(row["cell_id"]) in selected]


def _validity_source_rows(relative_path: str) -> tuple[int, int, int]:
    data = _load(REPO_ROOT / relative_path)
    rows = list(data.get("rows", []))
    witness_rows: list[dict[str, Any]] = []
    if relative_path.endswith(("paired_evaluation.json", "sensitivity/results.json", "evaluation_results.json")):
        witness_rows = [row for row in rows if bool(row.get("witness_returned"))]
    elif relative_path.endswith("schema_results.json"):
        witness_rows = [row for row in rows if row.get("witness_origin") is not None]
    elif relative_path.endswith("witness_overhead.json"):
        witness_rows = [row for row in rows if row.get("status") == "MEASURED"]
    else:
        raise ValueError(relative_path)
    valid = sum(row.get("witness_valid") is True for row in witness_rows)
    invalid = len(witness_rows) - valid
    return len(witness_rows), valid, invalid


def build_validity_census() -> dict[str, Any]:
    sources = list(load_manifest()["validity_census_sources"])
    by_source: dict[str, Any] = {}
    total = valid = invalid = 0
    for relative_path in sources:
        count, good, bad = _validity_source_rows(relative_path)
        by_source[relative_path] = {
            "witness_bearing_rows": count,
            "validated_rows": good,
            "invalid_rows": bad,
            "source_sha256": _sha(REPO_ROOT / relative_path),
        }
        total += count
        valid += good
        invalid += bad
    return {
        "witness_bearing_row_count": total,
        "validated_witness_row_count": valid,
        "invalid_witness_row_count": invalid,
        "by_source": by_source,
        "interpretation": "Counts are witness-bearing run rows, not deduplicated witness structures.",
    }


def _quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return xs[lo]
    w = pos - lo
    return xs[lo] * (1.0 - w) + xs[hi] * w


def summarize(exact_rows: list[dict[str, Any]], overhead_rows: list[dict[str, Any]], census: dict[str, Any]) -> dict[str, Any]:
    deltas = [float(row["runtime_delta_seconds"]) for row in overhead_rows]
    ratios = [
        float(row["runtime_seconds"]) / float(row["primary_runtime_seconds"])
        for row in overhead_rows
        if float(row["primary_runtime_seconds"]) > 0
    ]
    return {
        "exact_population_count": len(exact_rows),
        "decision_mismatch_count": sum(
            (row["explicit_decision"], row["explicit_verdicts"])
            != (row["smt_decision"], row["smt_verdicts"])
            for row in exact_rows
        ),
        "explicit_incomplete_count": sum(not row["explicit_complete"] for row in exact_rows),
        "invalid_exact_smt_witness_count": sum(not row["smt_witness_valid"] for row in exact_rows),
        "certified_minimal_count": sum(row["certified_minimal_on_exact_instance"] for row in exact_rows),
        "certified_minimal_rate": (
            sum(row["certified_minimal_on_exact_instance"] for row in exact_rows) / len(exact_rows)
            if exact_rows else None
        ),
        "objective_match_by_mechanism": {
            mechanism: {
                "n": sum(row["mechanism"] == mechanism for row in exact_rows),
                "certified_minimal": sum(
                    row["mechanism"] == mechanism and row["certified_minimal_on_exact_instance"]
                    for row in exact_rows
                ),
            }
            for mechanism in sorted({row["mechanism"] for row in exact_rows})
        },
        "overhead_population_count": len(overhead_rows),
        "overhead_valid_count": sum(row.get("witness_valid") is True for row in overhead_rows),
        "witness_materialization_runtime_seconds": {
            "median": statistics.median(float(row["runtime_seconds"]) for row in overhead_rows),
            "p95": _quantile([float(row["runtime_seconds"]) for row in overhead_rows], 0.95),
            "max": max(float(row["runtime_seconds"]) for row in overhead_rows),
        } if overhead_rows else {},
        "runtime_delta_seconds": {
            "median": statistics.median(deltas) if deltas else None,
            "p95": _quantile(deltas, 0.95),
            "max": max(deltas) if deltas else None,
        },
        "runtime_ratio_materialization_to_primary": {
            "median": statistics.median(ratios) if ratios else None,
            "p95": _quantile(ratios, 0.95),
            "max": max(ratios) if ratios else None,
        },
        "validity_census": census,
        "global_witness_optimization_supported": False,
    }


def validate_integrity(exact_rows: list[dict[str, Any]], overhead_rows: list[dict[str, Any]], census: dict[str, Any]) -> dict[str, Any]:
    manifest = load_manifest()
    errors: list[str] = []
    expected_exact = set(manifest["exact_minimality_population"]["fixture_ids"])
    actual_exact = {row["fixture_id"] for row in exact_rows}
    if len(exact_rows) != 30 or actual_exact != expected_exact:
        errors.append("exact_population_mismatch")
    if any(not row["explicit_complete"] for row in exact_rows):
        errors.append("explicit_incomplete")
    if any(row["explicit_decision"] != "unsound" or row["smt_decision"] != "unsound" for row in exact_rows):
        errors.append("exact_decision_mismatch")
    if any(not row["smt_witness_valid"] for row in exact_rows):
        errors.append("invalid_exact_smt_witness")
    expected_overhead = set(manifest["overhead_population"]["cell_ids"])
    if len(overhead_rows) != 36 or {row["cell_id"] for row in overhead_rows} != expected_overhead:
        errors.append("overhead_population_mismatch")
    if any(row.get("status") != "MEASURED" or row.get("witness_valid") is not True for row in overhead_rows):
        errors.append("overhead_invalid_or_missing")
    if census["invalid_witness_row_count"] != 0:
        errors.append("prior_official_invalid_witness_row")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "exact_population_count": len(exact_rows),
        "overhead_population_count": len(overhead_rows),
        "validity_census_row_count": census["witness_bearing_row_count"],
    }


def run_official() -> dict[str, Any]:
    for path in (RESULT, SUMMARY, RUN_MANIFEST, INTEGRITY_GATE):
        if path.exists():
            raise FileExistsError(f"refuse silent overwrite: {path}")
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    exact_rows = run_exact_population()
    overhead_rows = load_e11_overhead_rows()
    census = build_validity_census()
    wall = time.perf_counter() - t0
    summary = summarize(exact_rows, overhead_rows, census)
    result_obj = {
        "version": "E10_RESULTS_V1_1",
        "manifest_canonical_sha256": load_manifest()["canonical_sha256"],
        "exact_rows": exact_rows,
        "overhead_rows": overhead_rows,
        "validity_census": census,
    }
    summary_obj = {
        "version": "E10_SUMMARY_V1_1",
        "summary": summary,
        "claim_boundary": "Witness validity is supported on the tested populations. Minimality is certified only on the exhaustive E2-A subset where the SMT witness objective equals the explicit global minimum. E11 overhead measures witness materialization plus independent validation, not global witness optimization.",
    }
    RESULT.write_text(json.dumps(result_obj, indent=2) + "\n", encoding="utf-8")
    SUMMARY.write_text(json.dumps(summary_obj, indent=2) + "\n", encoding="utf-8")
    run_obj = {
        "run_id": "SSCV_E10_OFFICIAL_V1_1_20260911",
        "experiment": "E10_WITNESS_VALIDITY_AND_TINY_EXACT_MINIMALITY",
        "official": True,
        "wall_seconds": wall,
        "manifest_file_sha256": _sha(MANIFEST),
        "manifest_canonical_sha256": load_manifest()["canonical_sha256"],
        "backend": smt.default_solver().name if smt.default_solver() is not None else None,
        "code_sha256": {
            "runner": _sha(Path(__file__).resolve()),
            "explicit_oracle": _sha(Path(ex.__file__).resolve()),
            "smt_verifier": _sha(Path(smt.__file__).resolve()),
            "witness_validator": _sha(Path(iwv.__file__).resolve()),
            "fixture_builder": _sha(Path(fb.__file__).resolve()),
        },
    }
    RUN_MANIFEST.write_text(json.dumps(run_obj, indent=2) + "\n", encoding="utf-8")
    integrity = validate_integrity(exact_rows, overhead_rows, census)
    warnings = [
        "global_witness_optimization_not_implemented",
        "overhead_is_materialization_plus_validation_not_global_optimization",
    ]
    verdict = "FAIL_REPAIR" if not integrity["valid"] else "PASS_WITH_WARNINGS"
    gate = {
        "gate_id": "E10_WITNESS_VALIDITY_INTEGRITY_V1_1",
        "verdict": verdict,
        "failed_criteria": integrity["errors"],
        "warnings": warnings,
        "integrity": integrity,
        "result_sha256": _sha(RESULT),
        "summary_sha256": _sha(SUMMARY),
        "run_manifest_sha256": _sha(RUN_MANIFEST),
        "summary": summary,
    }
    INTEGRITY_GATE.write_text(json.dumps(gate, indent=2) + "\n", encoding="utf-8")
    return gate


def main() -> int:
    gate = run_official()
    print("VERDICT", gate["verdict"])
    print("FAILED", gate["failed_criteria"])
    print("WARNINGS", gate["warnings"])
    print("SUMMARY", json.dumps(gate["summary"], sort_keys=True))
    return 0 if gate["verdict"] in {"PASS", "PASS_WITH_WARNINGS"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
