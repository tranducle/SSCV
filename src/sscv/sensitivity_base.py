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
from . import smt_verifier as smt
from . import synthetic_generator as generator
from . import synthetic_pairing as pairing
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
MATRIX = CONFIG_ROOT / "bound_sensitivity_matrix.json"
ORDER_MANIFEST = CONFIG_ROOT / "order_freedom_sensitivity.json"
OUT = REPO_ROOT / "results" / "sensitivity" / "baseline"
RESULT = OUT / "results.json"
SUMMARY = OUT / "summary.json"
RUN_MANIFEST = OUT / "run_manifest.json"
INTEGRITY_GATE = OUT / "integrity.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _view_sha(view: Any) -> str:
    rows = sorted(
        (str(r.case_id), int(r.rank), str(r.event_id), str(r.activity), r.actor)
        for r in view.rows
    )
    return _canonical_sha(rows)


def load_matrix_rows() -> list[dict[str, Any]]:
    return list(_load(MATRIX)["cells"])


def _pair_index() -> dict[str, tuple[dict[str, Any], str]]:
    result: dict[str, tuple[dict[str, Any], str]] = {}
    for record in pairing.load_pairing_manifest()["pairs"]:
        for view_id, meta in record["cells"].items():
            result[str(meta["cell_id"])] = (record, str(view_id))
    return result


def _order_index() -> dict[str, dict[str, Any]]:
    return {str(x["base_cell_id"]): x for x in _load(ORDER_MANIFEST)["instances"]}


def _token_from_cell(cell: Any) -> str:
    first = str(cell.motif_event_ids_value[0])
    return first.split(":event:", 1)[0]


def _extend_binding_domains(
    domains: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...],
    token: str,
    target_width: int,
) -> tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]:
    result = []
    for event_id, choices in domains:
        if len(choices) <= 1:
            result.append((event_id, choices))
            continue
        actual = tuple(choices[0])
        expanded = [actual]
        for index in range(1, int(target_width) + 1):
            expanded.append((f"{token}:object:alt:{index}",))
        result.append((event_id, tuple(expanded)))
    return tuple(result)


def _relation_domain(token: str, target_edges: int) -> tuple[tuple[tuple[str, str, str], ...], ...]:
    edges: list[tuple[str, str, str]] = [
        ("linked", f"{token}:object:first", f"{token}:object:second")
    ]
    for index in range(1, int(target_edges)):
        edges.append(
            (
                "linked",
                f"{token}:relation:left:{index}",
                f"{token}:relation:right:{index}",
            )
        )
    choices = []
    for mask in range(1 << len(edges)):
        choices.append(tuple(edges[i] for i in range(len(edges)) if mask & (1 << i)))
    return tuple(choices)


def _spec_signature(spec: fb.Spec) -> str:
    obj = {
        "hidden_binding_domains": spec.hidden_binding_domains,
        "hidden_relation_domain": spec.hidden_relation_domain,
        "optional_deleted_events": [
            {
                "event": {
                    "event_id": t.event.event_id,
                    "activity": t.event.activity,
                    "actor": t.event.actor,
                    "case_ids": t.event.case_ids,
                    "hidden_objects": t.event.hidden_objects,
                },
                "before_event_id": t.before_event_id,
                "after_event_id": t.after_event_id,
            }
            for t in spec.optional_deleted_events
        ],
        "max_completions": spec.max_completions,
        "reference_order": spec.reference_order,
        "order_free_pairs": spec.order_free_pairs,
    }
    return _canonical_sha(obj)


def build_variant(row: dict[str, Any]) -> dict[str, Any]:
    index = _pair_index()
    base_id = str(row["base_cell_id"])
    record, view_id = index[base_id]
    cell = generator.build_cell(record, view_id)
    order = _order_index()[base_id]
    token = _token_from_cell(cell)

    target_object_width = int(row["hidden_object_width"])
    target_relation_edges = int(row["relation_free_edges"])
    binding_domains = _extend_binding_domains(
        cell.spec.hidden_binding_domains, token, target_object_width
    )
    relation_variable = len(cell.spec.hidden_relation_domain) > 1
    relation_domain = (
        _relation_domain(token, target_relation_edges)
        if relation_variable
        else cell.spec.hidden_relation_domain
    )
    selected = (
        order["selected_B_plus_P"]
        if str(row["variant"]) == "B+P"
        else order["selected_B0"]
    )
    spec = fb.Spec(
        hidden_binding_domains=binding_domains,
        hidden_relation_domain=relation_domain,
        optional_deleted_events=cell.spec.optional_deleted_events,
        max_completions=cell.spec.max_completions,
        reference_order=tuple(str(x) for x in order["reference_order"]),
        order_free_pairs=tuple(tuple(str(y) for y in x) for x in selected),
    )
    return {
        "row": row,
        "cell": cell,
        "spec": spec,
        "base_cell_id": base_id,
        "run_id": str(row["run_id"]),
        "variant": str(row["variant"]),
        "view_sha256": _view_sha(cell.view),
        "underlying_execution_sha256": cell.underlying_execution_sha256,
        "reference_order": list(order["reference_order"]),
        "eligible_order_pairs": list(order["eligible_pairs"]),
        "selected_order_pairs": [list(x) for x in selected],
        "eligible_order_pair_count": int(order["eligible_pair_count"]),
        "selected_order_pair_count": len(selected),
        "spec_sha256": _spec_signature(spec),
        "hidden_event_template_count": len(spec.optional_deleted_events),
        "hidden_event_slack": int(row["hidden_event_slack"]),
        "hidden_event_slack_noop": len(spec.optional_deleted_events) < int(row["hidden_event_slack"]),
        "binding_domain_max_choices": max((len(x[1]) for x in spec.hidden_binding_domains), default=0),
        "relation_domain_choice_count": len(spec.hidden_relation_domain),
    }


def _group_rows() -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in load_matrix_rows():
        grouped[str(row["base_cell_id"])].append(row)
    return grouped


def first_group() -> list[dict[str, Any]]:
    grouped = _group_rows()
    return sorted(next(iter(grouped.values())), key=lambda x: x["variant"])


def first_group_with_at_least_four_eligible_pairs() -> list[dict[str, Any]]:
    for group in _group_rows().values():
        b0 = next(row for row in group if row["variant"] == "B0")
        if build_variant(b0)["eligible_order_pair_count"] >= 4:
            return group
    raise RuntimeError("no E7 group has four eligible order pairs")


def first_group_for_mechanism(mechanism: str) -> list[dict[str, Any]]:
    for group in _group_rows().values():
        if str(group[0]["mechanism"]) == mechanism:
            return group
    raise RuntimeError(f"no E7 group for mechanism {mechanism}")


class TimeoutSolver:
    def __init__(self, inner: Any, timeout_ms: int = 30000):
        if inner is None:
            raise RuntimeError("solver unavailable")
        self.inner = inner
        self.timeout_ms = int(timeout_ms)

    @property
    def name(self) -> str:
        return f"{self.inner.name};timeout_ms={self.timeout_ms}"

    @property
    def version(self) -> str:
        return self.inner.version

    def solve(self, smt2: str, variables: Any):
        prefix = f"(set-option :timeout {self.timeout_ms})\n"
        return self.inner.solve(prefix + smt2, variables)


def _peak_rss_bytes() -> int | None:
    try:
        import psutil
        info = psutil.Process().memory_info()
        return int(getattr(info, "peak_wset", info.rss))
    except Exception:
        return None


def run_one(row: dict[str, Any], solver: Any | None = None) -> dict[str, Any]:
    built = build_variant(row)
    cell = built["cell"]
    solver = solver or TimeoutSolver(smt.default_solver(), 30000)
    t0 = time.perf_counter()
    result = smt.verify_smt(cell.view, built["spec"], cell.motif, solver=solver)
    elapsed = time.perf_counter() - t0
    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            cell.view,
            built["spec"],
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(report.valid)
        witness_errors = list(report.errors)
        if report.valid:
            witness_objective = list(report.objective)
    return {
        "run_id": built["run_id"],
        "base_cell_id": built["base_cell_id"],
        "variant": built["variant"],
        "process_family": str(row["process_family"]),
        "motif": str(row["motif"]),
        "case_view": str(row["case_view"]),
        "mechanism": str(row["mechanism"]),
        "seed": int(row["seed"]),
        "declared_bound": {
            "hidden_event_slack": int(row["hidden_event_slack"]),
            "hidden_object_width": int(row["hidden_object_width"]),
            "relation_free_edges": int(row["relation_free_edges"]),
            "order_width": int(row["order_width"]),
        },
        "underlying_execution_sha256": built["underlying_execution_sha256"],
        "view_sha256": built["view_sha256"],
        "spec_sha256": built["spec_sha256"],
        "hidden_event_template_count": built["hidden_event_template_count"],
        "hidden_event_slack_noop": built["hidden_event_slack_noop"],
        "binding_domain_max_choices": built["binding_domain_max_choices"],
        "relation_domain_choice_count": built["relation_domain_choice_count"],
        "eligible_order_pair_count": built["eligible_order_pair_count"],
        "selected_order_pair_count": built["selected_order_pair_count"],
        "selected_order_pairs": built["selected_order_pairs"],
        "decision": result.decision,
        "verdicts": ["violation" if x else "safe" for x in result.verdicts],
        "complete": bool(result.complete),
        "solver_statuses": list(result.solver_statuses),
        "unknown_reason": result.unknown_reason,
        "witness_returned": result.witness is not None,
        "witness_valid": witness_valid,
        "witness_errors": witness_errors,
        "witness_objective": witness_objective,
        "runtime_seconds": elapsed,
        "peak_rss_bytes": _peak_rss_bytes(),
        "backend": result.backend,
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


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_variant = {}
    for variant in ("B0", "B+E", "B+O", "B+R", "B+P"):
        selected = [row for row in rows if row["variant"] == variant]
        times = [float(row["runtime_seconds"]) for row in selected]
        by_variant[variant] = {
            "n": len(selected),
            "decisions": dict(sorted(Counter(row["decision"] for row in selected).items())),
            "unknown_reasons": dict(sorted(Counter(row["unknown_reason"] for row in selected if row["unknown_reason"]).items())),
            "witness_count": sum(bool(row["witness_returned"]) for row in selected),
            "invalid_witness_count": sum(row["witness_returned"] and row["witness_valid"] is not True for row in selected),
            "hidden_event_slack_noop_count": sum(bool(row["hidden_event_slack_noop"]) for row in selected),
            "runtime": {
                "median": statistics.median(times) if times else None,
                "q1": _quantile(times, 0.25),
                "q3": _quantile(times, 0.75),
                "p95": _quantile(times, 0.95),
                "max": max(times) if times else None,
                "total": sum(times),
            },
        }
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        grouped[str(row["base_cell_id"])][str(row["variant"])] = row
    transitions = {}
    for variant in ("B+E", "B+O", "B+R", "B+P"):
        counts = Counter()
        noop = 0
        for variants in grouped.values():
            base = variants["B0"]
            current = variants[variant]
            counts[f"{base['decision']}->{current['decision']}"] += 1
            if base["spec_sha256"] == current["spec_sha256"]:
                noop += 1
        transitions[variant] = {
            "transition_counts": dict(sorted(counts.items())),
            "spec_noop_count": noop,
            "bound_sensitive_sound_to_unsound": counts.get("sound->unsound", 0),
        }
    return {
        "row_count": len(rows),
        "base_case_count": len(grouped),
        "by_variant": by_variant,
        "paired_transitions_vs_B0": transitions,
    }


def validate_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    matrix = load_matrix_rows()
    expected_ids = {str(row["run_id"]) for row in matrix}
    actual_ids = [str(row["run_id"]) for row in rows]
    errors = []
    if len(rows) != 540 or len(set(actual_ids)) != 540 or set(actual_ids) != expected_ids:
        errors.append("run_id_population_mismatch")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["base_cell_id"])].append(row)
        if row["decision"] not in {"sound", "unsound", "unknown"}:
            errors.append(f"invalid_decision:{row['run_id']}")
        if row["witness_returned"] and row["witness_valid"] is not True:
            errors.append(f"invalid_witness:{row['run_id']}")
        if row["decision"] == "unsound" and not (row["witness_returned"] and row["witness_valid"] is True):
            errors.append(f"unsound_without_valid_witness:{row['run_id']}")
    if len(grouped) != 108:
        errors.append("base_group_count_mismatch")
    for base_id, group in grouped.items():
        if {row["variant"] for row in group} != {"B0", "B+E", "B+O", "B+R", "B+P"}:
            errors.append(f"variant_membership:{base_id}")
        if len({row["view_sha256"] for row in group}) != 1:
            errors.append(f"view_changed:{base_id}")
        if len({row["underlying_execution_sha256"] for row in group}) != 1:
            errors.append(f"underlying_execution_changed:{base_id}")
        by = {row["variant"]: row for row in group}
        if not set(tuple(x) for x in by["B0"]["selected_order_pairs"]).issubset(
            set(tuple(x) for x in by["B+P"]["selected_order_pairs"])
        ):
            errors.append(f"order_prefix_not_nested:{base_id}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "row_count": len(rows),
        "base_case_count": len(grouped),
    }


def run_official() -> dict[str, Any]:
    for path in (RESULT, SUMMARY, RUN_MANIFEST, INTEGRITY_GATE):
        if path.exists():
            raise FileExistsError(f"refuse silent overwrite: {path}")
    OUT.mkdir(parents=True, exist_ok=True)
    matrix = _load(MATRIX)
    order_manifest = _load(ORDER_MANIFEST)
    solver = TimeoutSolver(smt.default_solver(), int(matrix["operational_budget"]["timeout_per_existence_query_seconds"]) * 1000)
    start = time.perf_counter()
    rows = []
    for index, row in enumerate(matrix["cells"], start=1):
        rows.append(run_one(row, solver=solver))
        if index % 108 == 0:
            print(f"E7_PROGRESS {index}/540")
    wall = time.perf_counter() - start
    result_obj = {
        "version": "E7_RESULTS_V1_2",
        "matrix_sha256": _sha(MATRIX),
        "order_manifest_canonical_sha256": order_manifest["canonical_sha256"],
        "rows": rows,
    }
    summary_obj = {
        "version": "E7_SUMMARY_V1_2",
        "summary": summarize(rows),
        "claim_boundary": "Controlled synthetic structural-bound sensitivity only; no unbounded robustness or deployment-general claim.",
    }
    run_obj = {
        "run_id": "SSCV_E7_OFFICIAL_V1_2_20260911",
        "experiment": "E7_STRUCTURAL_BOUND_SENSITIVITY",
        "official": True,
        "matrix_sha256": _sha(MATRIX),
        "order_manifest_file_sha256": _sha(ORDER_MANIFEST),
        "order_manifest_canonical_sha256": order_manifest["canonical_sha256"],
        "query_order": matrix["operational_budget"]["query_order"],
        "timeout_per_existence_query_seconds": matrix["operational_budget"]["timeout_per_existence_query_seconds"],
        "solver_threads": matrix["operational_budget"]["solver_threads"],
        "backend": solver.name,
        "backend_version": solver.version,
        "wall_seconds": wall,
        "code_sha256": {
            "runner": _sha(Path(__file__).resolve()),
            "smt_verifier": _sha(Path(smt.__file__).resolve()),
            "witness_validator": _sha(Path(iwv.__file__).resolve()),
            "generator": _sha(Path(generator.__file__).resolve()),
        },
    }
    RESULT.write_text(json.dumps(result_obj, indent=2) + "\n", encoding="utf-8")
    SUMMARY.write_text(json.dumps(summary_obj, indent=2) + "\n", encoding="utf-8")
    RUN_MANIFEST.write_text(json.dumps(run_obj, indent=2) + "\n", encoding="utf-8")
    validation = validate_results(rows)
    gate = {
        "gate_id": "E7_STRUCTURAL_BOUND_SENSITIVITY_INTEGRITY_V1_2",
        "verdict": "PASS" if validation["valid"] else "FAIL_REPAIR",
        "failed_criteria": validation["errors"],
        "validation": validation,
        "result_sha256": _sha(RESULT),
        "summary_sha256": _sha(SUMMARY),
        "run_manifest_sha256": _sha(RUN_MANIFEST),
        "summary": summary_obj["summary"],
    }
    INTEGRITY_GATE.write_text(json.dumps(gate, indent=2) + "\n", encoding="utf-8")
    return gate


def main() -> int:
    gate = run_official()
    print("VERDICT", gate["verdict"])
    print("FAILED", gate["failed_criteria"])
    print("SUMMARY", json.dumps(gate["summary"], sort_keys=True))
    return 0 if gate["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
