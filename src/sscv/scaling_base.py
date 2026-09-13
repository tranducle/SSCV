from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics
import time
from typing import Any

from . import completion_models as fb
from . import witness_validation as iwv
from . import order_freedom as ofm
from . import smt_verifier as smt
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
MATRIX = CONFIG_ROOT / "scaling_matrix.json"
ORDER_MANIFEST = CONFIG_ROOT / "order_freedom_scaling.json"
OUT = REPO_ROOT / "results" / "scaling" / "baseline"
RESULT = OUT / "results.json"
SUMMARY = OUT / "summary.json"
RUN_MANIFEST = OUT / "run_manifest.json"
WARMUP_RESULT = OUT / "warmups.json"
SENTINEL_RESULT = OUT / "timing_sentinels.json"
WITNESS_RESULT = OUT / "witness_overhead.json"
INTEGRITY_GATE = OUT / "integrity.json"

SIZES = (4, 8, 12, 16, 24, 32)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _view_sha(view: Any) -> str:
    rows = sorted((str(r.case_id), int(r.rank), str(r.event_id), str(r.activity), r.actor) for r in view.rows)
    return _canonical_sha(rows)


def load_matrix() -> dict[str, Any]:
    return _load(MATRIX)


def load_matrix_rows() -> list[dict[str, Any]]:
    return list(load_matrix()["cells"])


def warmup_rows() -> list[dict[str, Any]]:
    return [
        row for row in load_matrix_rows()
        if int(row["visible_events"]) == 4
        and str(row["mechanism_condition"]) == "none"
        and int(row["replicate"]) == 1
    ]


def sentinel_rows() -> list[dict[str, Any]]:
    return [
        row for row in load_matrix_rows()
        if int(row["visible_events"]) in {8, 24}
        and str(row["mechanism_condition"]) == "none"
        and int(row["replicate"]) == 1
    ]


def witness_subset_rows() -> list[dict[str, Any]]:
    return [row for row in load_matrix_rows() if bool(row.get("witness_overhead_subset"))]


def resource_budgets_ms() -> dict[str, int]:
    envelope = load_matrix()["resource_envelope"]
    return {
        "primary_timeout_ms": int(envelope["timeout_per_existence_query_seconds"]) * 1000,
        "witness_timeout_ms": int(envelope["witness_optimization_budget_seconds"]) * 1000,
    }


def expected_sentinel_repeat_count(launched_sizes: list[int] | tuple[int, ...]) -> int:
    launched = set(int(size) for size in launched_sizes)
    eligible = [row for row in sentinel_rows() if int(row["visible_events"]) in launched]
    return len(eligible) * 3


def _order_index() -> dict[str, dict[str, Any]]:
    return {str(x["cell_id"]): x for x in _load(ORDER_MANIFEST)["instances"]}


def build_cell(row: dict[str, Any]) -> dict[str, Any]:
    cell = ofm.build_e11_cell(row)
    order = _order_index()[str(row["cell_id"])]
    spec = fb.Spec(
        hidden_binding_domains=cell.spec.hidden_binding_domains,
        hidden_relation_domain=cell.spec.hidden_relation_domain,
        optional_deleted_events=cell.spec.optional_deleted_events,
        max_completions=cell.spec.max_completions,
        reference_order=tuple(str(x) for x in order["reference_order"]),
        order_free_pairs=tuple(tuple(str(y) for y in x) for x in order["selected_pairs"]),
    )
    return {
        "cell": cell,
        "spec": spec,
        "order_manifest_record": order,
        "view_sha256": _view_sha(cell.view),
        "underlying_execution_sha256": cell.underlying_execution_sha256,
        "hidden_event_template_count": len(spec.optional_deleted_events),
        "hidden_event_slack_noop": len(spec.optional_deleted_events) < int(row["hidden_event_slack"]),
    }


def can_advance(completed: int, total: int) -> bool:
    return total == 36 and completed >= 33


def decision_from_statuses(safe_status: str, violation_status: str) -> tuple[str, list[str], bool, str | None]:
    if safe_status in {"unknown", "error"} or violation_status in {"unknown", "error"}:
        bad = safe_status if safe_status in {"unknown", "error"} else violation_status
        return "unknown", [], False, f"solver_{bad}"
    if safe_status == "sat" and violation_status == "sat":
        return "unsound", ["safe", "violation"], True, None
    if safe_status == "sat" and violation_status == "unsat":
        return "sound", ["safe"], True, None
    if safe_status == "unsat" and violation_status == "sat":
        return "sound", ["violation"], True, None
    if safe_status == "unsat" and violation_status == "unsat":
        return "unknown", [], True, "no_admissible_completion"
    return "unknown", [], False, "incomplete_solver_state"


class BudgetSolver:
    def __init__(self, inner: Any, timeout_ms: int):
        if inner is None:
            raise RuntimeError("solver unavailable")
        self.inner = inner
        self.timeout_ms = int(timeout_ms)

    @property
    def name(self) -> str:
        return f"{self.inner.name};timeout_ms={self.timeout_ms};threads=1-sequential"

    @property
    def version(self) -> str:
        return self.inner.version

    def solve(self, smt2: str, variables: Any):
        return self.inner.solve(f"(set-option :timeout {self.timeout_ms})\n" + smt2, variables)

    def status_only(self, smt2: str) -> str:
        status, _ = self.solve(smt2, ())
        return status


def _peak_rss_bytes() -> int | None:
    try:
        import psutil
        info = psutil.Process().memory_info()
        return int(getattr(info, "peak_wset", info.rss))
    except Exception:
        return None


def _resource_ok(peak_rss: int | None, limit_gib: float) -> bool:
    return peak_rss is None or peak_rss <= int(limit_gib * (1024 ** 3))


def run_primary(row: dict[str, Any], solver: BudgetSolver, memory_limit_gib: float) -> dict[str, Any]:
    built = build_cell(row)
    cell = built["cell"]
    encoding = smt.Encoding(cell.view, built["spec"], cell.motif)
    t0 = time.perf_counter()
    statuses = []
    for target in ("safe", "violation"):
        if not encoding.consistent:
            statuses.append("error")
            continue
        statuses.append(solver.status_only(encoding.script_for(target)))
        if statuses[-1] in {"unknown", "error"}:
            break
    elapsed = time.perf_counter() - t0
    while len(statuses) < 2:
        statuses.append("not_run")
    if "not_run" in statuses:
        decision, verdicts, complete, reason = "unknown", [], False, f"solver_{statuses[0]}"
    else:
        decision, verdicts, complete, reason = decision_from_statuses(statuses[0], statuses[1])
    peak = _peak_rss_bytes()
    memory_ok = _resource_ok(peak, memory_limit_gib)
    operational_completed = all(status in {"sat", "unsat"} for status in statuses) and memory_ok
    if not memory_ok:
        decision, verdicts, complete, reason = "unknown", [], False, "memory_envelope_violation"
    return {
        "cell_id": str(row["cell_id"]),
        "visible_events": int(row["visible_events"]),
        "motif": str(row["motif"]),
        "process_family": str(row["process_family"]),
        "case_view": str(row["case_view"]),
        "mechanism_condition": str(row["mechanism_condition"]),
        "mechanism": str(row["mechanism"]),
        "replicate": int(row["replicate"]),
        "seed": int(row["seed"]),
        "witness_overhead_subset": bool(row.get("witness_overhead_subset")),
        "declared_bound": {
            "hidden_event_slack": int(row["hidden_event_slack"]),
            "hidden_object_width": int(row["hidden_object_width"]),
            "relation_free_edges": int(row["relation_free_edges"]),
            "order_width": int(row["order_width"]),
        },
        "view_sha256": built["view_sha256"],
        "underlying_execution_sha256": built["underlying_execution_sha256"],
        "eligible_order_pair_count": int(built["order_manifest_record"]["eligible_pair_count"]),
        "selected_order_pair_count": len(built["order_manifest_record"]["selected_pairs"]),
        "hidden_event_template_count": built["hidden_event_template_count"],
        "hidden_event_slack_noop": built["hidden_event_slack_noop"],
        "decision": decision,
        "verdicts": verdicts,
        "complete": complete,
        "operational_completed": operational_completed,
        "solver_statuses": statuses,
        "unknown_reason": reason,
        "runtime_seconds": elapsed,
        "peak_rss_bytes": peak,
        "memory_envelope_ok": memory_ok,
        "backend": solver.name,
    }


def run_witness_materialization(row: dict[str, Any], solver: BudgetSolver) -> dict[str, Any]:
    built = build_cell(row)
    cell = built["cell"]
    t0 = time.perf_counter()
    result = smt.verify_smt(cell.view, built["spec"], cell.motif, solver=solver)
    elapsed = time.perf_counter() - t0
    valid = None
    errors: list[str] = []
    objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            cell.view,
            built["spec"],
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        valid = bool(report.valid)
        errors = list(report.errors)
        objective = list(report.objective) if report.valid else None
    return {
        "cell_id": str(row["cell_id"]),
        "decision": result.decision,
        "runtime_seconds": elapsed,
        "witness_returned": result.witness is not None,
        "witness_valid": valid,
        "witness_errors": errors,
        "witness_objective": objective,
        "minimality_claimed": bool(result.witness is not None and result.witness.minimal),
        "mode": "witness_materialization_and_independent_validation",
        "protocol_warning": "The current verifier does not implement global witness-objective optimization; no minimality or optimization-overhead claim is made.",
    }


def _quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return xs[lo]
    w = pos - lo
    return xs[lo] * (1.0 - w) + xs[hi] * w


def _runtime_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row["runtime_seconds"]) for row in rows]
    return {
        "n": len(values),
        "median": statistics.median(values) if values else None,
        "q1": _quantile(values, 0.25),
        "q3": _quantile(values, 0.75),
        "p95": _quantile(values, 0.95),
        "max": max(values) if values else None,
        "total": sum(values),
    }


def summarize(primary: list[dict[str, Any]], sentinels: list[dict[str, Any]], witness: list[dict[str, Any]]) -> dict[str, Any]:
    by_size = {}
    for size in sorted({row["visible_events"] for row in primary}):
        rows = [row for row in primary if row["visible_events"] == size]
        completed = sum(bool(row["operational_completed"]) for row in rows)
        by_size[str(size)] = {
            "n": len(rows),
            "operational_completed": completed,
            "advance_allowed": can_advance(completed, len(rows)),
            "decisions": dict(sorted(Counter(row["decision"] for row in rows).items())),
            "unknown_reasons": dict(sorted(Counter(row["unknown_reason"] for row in rows if row["unknown_reason"]).items())),
            "runtime": _runtime_summary(rows),
            "max_peak_rss_bytes": max((row["peak_rss_bytes"] or 0 for row in rows), default=0),
        }
    sentinel_grouped: dict[str, list[float]] = defaultdict(list)
    for row in sentinels:
        sentinel_grouped[row["cell_id"]].append(float(row["runtime_seconds"]))
    sentinel_noise = {
        key: {
            "n": len(values),
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        }
        for key, values in sorted(sentinel_grouped.items())
    }
    witness_times = [float(row["runtime_seconds"]) for row in witness if row.get("status") == "MEASURED"]
    return {
        "primary_row_count": len(primary),
        "launched_sizes": sorted({row["visible_events"] for row in primary}),
        "by_size": by_size,
        "sentinel_noise": sentinel_noise,
        "witness_materialization": {
            "predeclared_subset_count": 36,
            "measured_count": sum(row.get("status") == "MEASURED" for row in witness),
            "not_applicable_count": sum(row.get("status") == "NOT_APPLICABLE" for row in witness),
            "runtime": {
                "median": statistics.median(witness_times) if witness_times else None,
                "p95": _quantile(witness_times, 0.95),
                "max": max(witness_times) if witness_times else None,
            },
            "global_optimization_supported": False,
        },
    }


def validate_integrity(primary: list[dict[str, Any]], warmups: list[dict[str, Any]], sentinels: list[dict[str, Any]], witness: list[dict[str, Any]]) -> dict[str, Any]:
    errors = []
    matrix = load_matrix()
    matrix_ids = {str(row["cell_id"]) for row in matrix["cells"]}
    ids = [str(row["cell_id"]) for row in primary]
    launched_sizes = sorted({row["visible_events"] for row in primary})
    if launched_sizes != list(SIZES[: len(launched_sizes)]):
        errors.append("launched_sizes_not_prefix")
    if len(ids) != len(set(ids)) or not set(ids).issubset(matrix_ids):
        errors.append("primary_cell_id_integrity")
    for size in launched_sizes:
        rows = [row for row in primary if row["visible_events"] == size]
        if len(rows) != 36:
            errors.append(f"size_population:{size}")
        completed = sum(row["operational_completed"] for row in rows)
        idx = SIZES.index(size)
        if idx < len(launched_sizes) - 1 and not can_advance(completed, 36):
            errors.append(f"advanced_after_failed_size:{size}")
    if len(warmups) != 6:
        errors.append("warmup_count")
    if len(sentinels) != expected_sentinel_repeat_count(launched_sizes):
        errors.append("sentinel_repeat_count")
    if len(witness) != sum(row["witness_overhead_subset"] for row in primary):
        errors.append("witness_subset_accounting")
    for row in witness:
        if row.get("status") == "MEASURED" and row.get("witness_valid") is not True:
            errors.append(f"invalid_witness:{row['cell_id']}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "primary_row_count": len(primary),
        "launched_sizes": launched_sizes,
    }


def run_official() -> dict[str, Any]:
    for path in (RESULT, SUMMARY, RUN_MANIFEST, WARMUP_RESULT, SENTINEL_RESULT, WITNESS_RESULT, INTEGRITY_GATE):
        if path.exists():
            raise FileExistsError(f"refuse silent overwrite: {path}")
    OUT.mkdir(parents=True, exist_ok=True)
    matrix = load_matrix()
    env = matrix["resource_envelope"]
    budgets = resource_budgets_ms()
    solver = BudgetSolver(smt.default_solver(), budgets["primary_timeout_ms"])
    witness_solver = BudgetSolver(smt.default_solver(), budgets["witness_timeout_ms"])
    memory_limit = float(env["peak_rss_gib"])

    warmups = []
    for row in warmup_rows():
        result = run_primary(row, solver, memory_limit)
        result["warmup"] = True
        warmups.append(result)
    WARMUP_RESULT.write_text(json.dumps({"version": "E11_WARMUPS_V1_2", "rows": warmups}, indent=2) + "\n", encoding="utf-8")

    primary: list[dict[str, Any]] = []
    stop_reason = None
    start = time.perf_counter()
    for size in SIZES:
        size_rows = [row for row in matrix["cells"] if int(row["visible_events"]) == size]
        current = []
        for row in size_rows:
            current.append(run_primary(row, solver, memory_limit))
        primary.extend(current)
        completed = sum(item["operational_completed"] for item in current)
        print(f"E11_SIZE {size} COMPLETED {completed}/36")
        if not can_advance(completed, 36):
            stop_reason = f"tier_advance_failed_at_size_{size}:{completed}/36"
            break
    wall = time.perf_counter() - start

    launched_ids = {row["cell_id"] for row in primary}
    sentinels = []
    for row in sentinel_rows():
        if str(row["cell_id"]) not in launched_ids:
            continue
        for repeat in range(1, 4):
            result = run_primary(row, solver, memory_limit)
            result["repeat"] = repeat
            sentinels.append(result)
    SENTINEL_RESULT.write_text(json.dumps({"version": "E11_TIMING_SENTINELS_V1_2", "rows": sentinels}, indent=2) + "\n", encoding="utf-8")

    primary_by_id = {row["cell_id"]: row for row in primary}
    witness_rows = []
    matrix_by_id = {str(row["cell_id"]): row for row in matrix["cells"]}
    for selected in witness_subset_rows():
        cell_id = str(selected["cell_id"])
        if cell_id not in launched_ids:
            continue
        primary_row = primary_by_id[cell_id]
        if primary_row["decision"] != "unsound":
            witness_rows.append({"cell_id": cell_id, "status": "NOT_APPLICABLE", "primary_decision": primary_row["decision"]})
            continue
        measured = run_witness_materialization(matrix_by_id[cell_id], witness_solver)
        measured["status"] = "MEASURED"
        measured["primary_runtime_seconds"] = primary_row["runtime_seconds"]
        measured["runtime_delta_seconds"] = measured["runtime_seconds"] - primary_row["runtime_seconds"]
        witness_rows.append(measured)
    WITNESS_RESULT.write_text(json.dumps({"version": "E11_WITNESS_OVERHEAD_V1_2", "rows": witness_rows}, indent=2) + "\n", encoding="utf-8")

    result_obj = {
        "version": "E11_RESULTS_V1_2",
        "matrix_sha256": _sha(MATRIX),
        "order_manifest_canonical_sha256": _load(ORDER_MANIFEST)["canonical_sha256"],
        "stop_reason": stop_reason,
        "rows": primary,
    }
    summary_obj = {
        "version": "E11_SUMMARY_V1_2",
        "summary": summarize(primary, sentinels, witness_rows),
        "claim_boundary": "Scaling characterization only within actually launched sizes and the fixed operational envelope; no asymptotic or deployment-scale claim.",
    }
    RESULT.write_text(json.dumps(result_obj, indent=2) + "\n", encoding="utf-8")
    SUMMARY.write_text(json.dumps(summary_obj, indent=2) + "\n", encoding="utf-8")
    run_obj = {
        "run_id": "SSCV_E11_OFFICIAL_V1_2_20260911",
        "experiment": "E11_BOUNDED_SCALING",
        "official": True,
        "matrix_sha256": _sha(MATRIX),
        "order_manifest_file_sha256": _sha(ORDER_MANIFEST),
        "order_manifest_canonical_sha256": _load(ORDER_MANIFEST)["canonical_sha256"],
        "resource_envelope": env,
        "backend": solver.name,
        "backend_version": solver.version,
        "witness_backend": witness_solver.name,
        "primary_timeout_ms": budgets["primary_timeout_ms"],
        "witness_timeout_ms": budgets["witness_timeout_ms"],
        "wall_seconds_primary": wall,
        "stop_reason": stop_reason,
        "witness_overhead_note": "Measured witness materialization and independent validation. Global witness-objective optimization is not implemented, so no minimality or optimization-overhead claim is licensed.",
        "code_sha256": {
            "runner": _sha(Path(__file__).resolve()),
            "smt_verifier": _sha(Path(smt.__file__).resolve()),
            "witness_validator": _sha(Path(iwv.__file__).resolve()),
            "order_manifest_builder": _sha(Path(ofm.__file__).resolve()),
        },
    }
    RUN_MANIFEST.write_text(json.dumps(run_obj, indent=2) + "\n", encoding="utf-8")

    integrity = validate_integrity(primary, warmups, sentinels, witness_rows)
    warnings = []
    if not summary_obj["summary"]["launched_sizes"] == list(SIZES):
        warnings.append("staircase_stopped_before_size_32")
    warnings.append("global_witness_optimization_not_implemented; witness subset measures materialization_and_validation only")
    verdict = "FAIL_REPAIR" if not integrity["valid"] else ("PASS_WITH_WARNINGS" if warnings else "PASS")
    gate = {
        "gate_id": "E11_BOUNDED_SCALING_INTEGRITY_V1_2",
        "verdict": verdict,
        "failed_criteria": integrity["errors"],
        "warnings": warnings,
        "integrity": integrity,
        "result_sha256": _sha(RESULT),
        "summary_sha256": _sha(SUMMARY),
        "run_manifest_sha256": _sha(RUN_MANIFEST),
        "warmup_sha256": _sha(WARMUP_RESULT),
        "sentinel_sha256": _sha(SENTINEL_RESULT),
        "witness_overhead_sha256": _sha(WITNESS_RESULT),
        "summary": summary_obj["summary"],
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
