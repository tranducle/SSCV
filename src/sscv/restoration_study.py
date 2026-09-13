from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import time
from typing import Any

from . import completion_models as fb
from . import witness_validation as iwv
from . import smt_verifier as smt
from . import synthetic_generator as gen
from . import synthetic_pairing as pairing
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
MANIFEST = CONFIG_ROOT / "restoration_manifest.json"
E3_RESULT = REPO_ROOT / "results" / "synthetic" / "paired_evaluation.json"
OUT = REPO_ROOT / "results" / "restoration"
RESULT = OUT / "results.json"
SUMMARY = OUT / "summary.json"
RUN_MANIFEST = OUT / "run_manifest.json"
INTEGRITY_GATE = OUT / "integrity.json"
PROFILES = ("P-CORE", "P+B", "P+R", "P+O", "P+E")
PROFILE_FAMILY = {
    "P-CORE": None,
    "P+B": "bindings",
    "P+R": "relations",
    "P+O": "order",
    "P+E": "deletion_presence",
}
VARIABLE_TO_PROFILE = {
    "binding": "P+B",
    "relation": "P+R",
    "order": "P+O",
    "deletion": "P+E",
}


def profile_target_variable(profile: str) -> str | None:
    return {
        "P+B": "binding",
        "P+R": "relation",
        "P+O": "order",
        "P+E": "deletion",
    }.get(profile)


def is_declared_noop(cell: Any, profile: str) -> bool:
    target = profile_target_variable(profile)
    return bool(profile != "P-CORE" and target not in cell.variable_mechanisms)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_manifest() -> dict[str, Any]:
    return _load(MANIFEST)


def e3_row_index() -> dict[str, dict[str, Any]]:
    return {str(row["cell_id"]): row for row in _load(E3_RESULT)["rows"]}


def _cell_index() -> dict[str, tuple[dict[str, Any], str]]:
    out: dict[str, tuple[dict[str, Any], str]] = {}
    for record in pairing.load_pairing_manifest()["pairs"]:
        for view_id, cell_meta in record["cells"].items():
            out[str(cell_meta["cell_id"])] = (record, str(view_id))
    return out


def resolve_cell(cell_id: str) -> tuple[dict[str, Any], str]:
    return _cell_index()[str(cell_id)]


def sample_one_cell_per_mechanism() -> dict[str, str]:
    e3 = e3_row_index()
    selected = set(load_manifest()["selected_cell_ids"])
    result: dict[str, str] = {}
    for cell_id in sorted(selected):
        mechanism = str(e3[cell_id]["mechanism"])
        if mechanism in {"binding", "relation", "order", "deletion"} and mechanism not in result:
            result[mechanism] = cell_id
    if set(result) != {"binding", "relation", "order", "deletion"}:
        raise RuntimeError("frozen E5 population lacks a required single-mechanism sample")
    return result


def _view_sha(view: Any) -> str:
    rows = sorted(
        (str(row.case_id), int(row.rank), str(row.event_id), str(row.activity), row.actor)
        for row in view.rows
    )
    return _canonical_sha(rows)


def _source_event_map(cell: Any) -> dict[str, Any]:
    return {str(event.event_id): event for event in cell.underlying_execution.events}


def _realized_bindings(cell: Any) -> tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]:
    events = _source_event_map(cell)
    restored = []
    for event_id, _domain in cell.spec.hidden_binding_domains:
        actual = gen._latent_bindings(cell.underlying_execution, events[str(event_id)])
        restored.append((str(event_id), (tuple(actual),)))
    return tuple(restored)


def _realized_relation_choice(cell: Any) -> tuple[tuple[tuple[str, str, str], ...], ...]:
    universe = {
        tuple(str(x) for x in relation)
        for choice in cell.spec.hidden_relation_domain
        for relation in choice
    }
    realized = tuple(
        sorted(
            tuple(str(x) for x in relation)
            for relation in cell.underlying_execution.relations
            if tuple(str(x) for x in relation) in universe
        )
    )
    return (realized,)


def _realized_reference_order(cell: Any) -> tuple[str, ...]:
    visible_ids = {str(row.event_id) for row in cell.view.rows}
    template_ids = {str(template.event.event_id) for template in cell.spec.optional_deleted_events}
    possible = visible_ids | template_ids
    reference = tuple(str(event_id) for event_id in cell.underlying_execution.order if str(event_id) in possible)
    if set(reference) != possible or len(reference) != len(possible):
        raise ValueError(f"underlying execution does not cover E5 order universe: {cell.cell_id}")
    return reference


def restore_spec(cell: Any, profile: str) -> fb.Spec:
    if profile not in PROFILES:
        raise ValueError(profile)
    base = cell.spec
    bindings = base.hidden_binding_domains
    relations = base.hidden_relation_domain
    reference_order = base.reference_order
    order_free_pairs = base.order_free_pairs
    required_deleted = tuple(getattr(base, "required_deleted_event_ids", ()))

    if profile == "P+B":
        bindings = _realized_bindings(cell)
    elif profile == "P+R":
        relations = _realized_relation_choice(cell)
    elif profile == "P+O":
        reference_order = _realized_reference_order(cell)
        order_free_pairs = ()
    elif profile == "P+E":
        required_deleted = tuple(
            sorted(str(template.event.event_id) for template in base.optional_deleted_events)
        )

    return fb.Spec(
        hidden_binding_domains=tuple(bindings),
        hidden_relation_domain=tuple(relations),
        optional_deleted_events=tuple(base.optional_deleted_events),
        max_completions=base.max_completions,
        reference_order=reference_order,
        order_free_pairs=order_free_pairs,
        required_deleted_event_ids=tuple(required_deleted),
    )


def changed_spec_families(before: fb.Spec, after: fb.Spec) -> tuple[str, ...]:
    changed: list[str] = []
    if before.hidden_binding_domains != after.hidden_binding_domains:
        changed.append("bindings")
    if before.hidden_relation_domain != after.hidden_relation_domain:
        changed.append("relations")
    if (before.reference_order, before.order_free_pairs) != (after.reference_order, after.order_free_pairs):
        changed.append("order")
    if tuple(getattr(before, "required_deleted_event_ids", ())) != tuple(
        getattr(after, "required_deleted_event_ids", ())
    ):
        changed.append("deletion_presence")
    return tuple(changed)


def _labels(values: tuple[bool, ...]) -> list[str]:
    return ["violation" if value else "safe" for value in values]


def run_profile(cell_id: str, profile: str) -> dict[str, Any]:
    record, view_id = resolve_cell(cell_id)
    cell = gen.build_cell(record, view_id)
    spec = restore_spec(cell, profile)
    solver = smt.default_solver()
    if solver is None:
        raise RuntimeError("real Z3-compatible backend required")
    started = time.perf_counter()
    result = smt.verify_smt(cell.view, spec, cell.motif, solver=solver, query_order=("safe", "violation"))
    elapsed = time.perf_counter() - started

    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        validation = iwv.validate_witness(
            cell.view,
            spec,
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(validation.valid)
        witness_errors = list(validation.errors)
        witness_objective = list(validation.objective) if validation.objective is not None else None

    target_variable = profile_target_variable(profile)
    changed = changed_spec_families(cell.spec, spec)
    frozen = e3_row_index()[cell_id]
    return {
        "run_id": f"E5|{cell_id}|{profile}",
        "cell_id": cell_id,
        "profile": profile,
        "profile_family": PROFILE_FAMILY[profile],
        "pair_key": cell.pair_key,
        "case_view": view_id,
        "process_family": cell.process_family,
        "motif": cell.motif_id,
        "mechanism": cell.mechanism,
        "mixed_recipe": list(cell.mixed_recipe),
        "variable_mechanisms": list(cell.variable_mechanisms),
        "target_family_active": bool(target_variable and target_variable in cell.variable_mechanisms),
        "changed_spec_families": list(changed),
        "declared_noop": is_declared_noop(cell, profile),
        "view_sha256": _view_sha(cell.view),
        "underlying_execution_sha256": cell.underlying_execution_sha256,
        "frozen_e3_decision": frozen["sscv_decision"],
        "frozen_e3_verdicts": list(frozen["sscv_verdicts"]),
        "decision": result.decision,
        "verdicts": _labels(result.verdicts),
        "complete": bool(result.complete),
        "solver_statuses": list(result.solver_statuses),
        "unknown_reason": result.unknown_reason,
        "runtime_seconds": elapsed,
        "witness_returned": result.witness is not None,
        "witness_valid": witness_valid,
        "witness_errors": witness_errors,
        "witness_objective": witness_objective,
        "witness_minimal_claimed": bool(result.witness is not None and result.witness.minimal),
        "solver_backend": result.backend or solver.name,
        "solver_version": solver.version,
        "b2_restoration_metric": "NOT_APPLICABLE_COMPARATOR_DOES_NOT_CONSUME_RESTORED_SIDE_INFORMATION",
    }


def _runtime_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row["runtime_seconds"]) for row in rows]
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "total": sum(values),
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    core = {row["cell_id"]: row for row in rows if row["profile"] == "P-CORE"}
    by_profile: dict[str, Any] = {}
    for profile in PROFILES:
        subset = [row for row in rows if row["profile"] == profile]
        transitions = Counter(
            f"{core[row['cell_id']]['decision']}->{row['decision']}" for row in subset
        )
        by_profile[profile] = {
            "n": len(subset),
            "decisions": dict(sorted(Counter(row["decision"] for row in subset).items())),
            "transitions_from_core": dict(sorted(transitions.items())),
            "restored_to_sound_count": sum(
                core[row["cell_id"]]["decision"] == "unsound" and row["decision"] == "sound"
                for row in subset
            ),
            "target_family_active_count": sum(bool(row["target_family_active"]) for row in subset),
            "declared_noop_count": sum(bool(row["declared_noop"]) for row in subset),
            "unknown_reasons": dict(sorted(Counter(row["unknown_reason"] for row in subset if row["unknown_reason"]).items())),
            "invalid_witness_count": sum(
                row["witness_returned"] and row["witness_valid"] is not True for row in subset
            ),
            "runtime": _runtime_summary(subset),
        }
    by_mechanism_profile: dict[str, Any] = {}
    for mechanism in sorted({row["mechanism"] for row in rows}):
        by_mechanism_profile[mechanism] = {}
        for profile in PROFILES:
            subset = [row for row in rows if row["mechanism"] == mechanism and row["profile"] == profile]
            by_mechanism_profile[mechanism][profile] = {
                "n": len(subset),
                "decisions": dict(sorted(Counter(row["decision"] for row in subset).items())),
                "restored_to_sound_count": sum(row["decision"] == "sound" for row in subset),
            }
    return {
        "base_cell_count": len(core),
        "row_count": len(rows),
        "by_profile": by_profile,
        "by_mechanism_profile": by_mechanism_profile,
        "b2_metric_status": "NOT_APPLICABLE_COMPARATOR_DOES_NOT_CONSUME_RESTORED_SIDE_INFORMATION",
    }


def validate_integrity(rows: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = load_manifest()
    selected = set(manifest["selected_cell_ids"])
    errors: list[str] = []
    if len(rows) != 405 or len({row["run_id"] for row in rows}) != 405:
        errors.append("run_population_not_405")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["cell_id"]].append(row)
    if set(grouped) != selected or len(grouped) != 81:
        errors.append("base_cell_set_mismatch")
    for cell_id, group in grouped.items():
        if {row["profile"] for row in group} != set(PROFILES) or len(group) != 5:
            errors.append(f"profile_set:{cell_id}")
            continue
        if len({row["view_sha256"] for row in group}) != 1:
            errors.append(f"view_drift:{cell_id}")
        if len({row["underlying_execution_sha256"] for row in group}) != 1:
            errors.append(f"execution_drift:{cell_id}")
        core = next(row for row in group if row["profile"] == "P-CORE")
        if core["decision"] != core["frozen_e3_decision"] or core["verdicts"] != core["frozen_e3_verdicts"]:
            errors.append(f"core_mismatch:{cell_id}")
        for row in group:
            allowed = {PROFILE_FAMILY[row["profile"]]} if PROFILE_FAMILY[row["profile"]] else set()
            if not set(row["changed_spec_families"]).issubset(allowed):
                errors.append(f"cross_family_change:{row['run_id']}")
            if row["witness_returned"] and row["witness_valid"] is not True:
                errors.append(f"invalid_witness:{row['run_id']}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "row_count": len(rows),
        "base_cell_count": len(grouped),
        "unknown_count": sum(row["decision"] == "unknown" for row in rows),
        "witness_count": sum(bool(row["witness_returned"]) for row in rows),
        "invalid_witness_count": sum(
            row["witness_returned"] and row["witness_valid"] is not True for row in rows
        ),
    }


def run_official() -> dict[str, Any]:
    for path in (RESULT, SUMMARY, RUN_MANIFEST, INTEGRITY_GATE):
        if path.exists():
            raise FileExistsError(f"refuse silent overwrite: {path}")
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    for index, cell_id in enumerate(manifest["selected_cell_ids"], start=1):
        for profile in PROFILES:
            rows.append(run_profile(str(cell_id), profile))
        if index % 27 == 0:
            print(f"E5_PROGRESS {index}/81 BASES {len(rows)}/405 RUNS")
    wall = time.perf_counter() - started
    summary = summarize(rows)
    result_obj = {
        "version": "E5_RESULTS_V1_1",
        "run_id": "SSCV_E5_OFFICIAL_V1_1_20260911",
        "manifest_canonical_sha256": manifest["canonical_sha256"],
        "source_e3_result_sha256": _sha(E3_RESULT),
        "rows": rows,
    }
    summary_obj = {
        "version": "E5_SUMMARY_V1_1",
        "summary": summary,
        "claim_boundary": manifest["claim_boundary"],
    }
    RESULT.write_text(json.dumps(result_obj, indent=2) + "\n", encoding="utf-8")
    SUMMARY.write_text(json.dumps(summary_obj, indent=2) + "\n", encoding="utf-8")
    solver = smt.default_solver()
    run_obj = {
        "run_id": result_obj["run_id"],
        "experiment": "E5_CONTEXT_RESTORATION_ABLATION",
        "official": True,
        "wall_seconds": wall,
        "manifest_file_sha256": _sha(MANIFEST),
        "manifest_canonical_sha256": manifest["canonical_sha256"],
        "source_e3_result_sha256": _sha(E3_RESULT),
        "backend": solver.name if solver else None,
        "backend_version": solver.version if solver else None,
        "code_sha256": {
            "runner": _sha(Path(__file__).resolve()),
            "generator": _sha(Path(gen.__file__).resolve()),
            "smt_verifier": _sha(Path(smt.__file__).resolve()),
            "witness_validator": _sha(Path(iwv.__file__).resolve()),
            "fixture_builder": _sha(Path(fb.__file__).resolve()),
        },
    }
    RUN_MANIFEST.write_text(json.dumps(run_obj, indent=2) + "\n", encoding="utf-8")
    integrity = validate_integrity(rows)
    warnings: list[str] = []
    if integrity["unknown_count"]:
        warnings.append(f"unknown_restoration_outcomes:{integrity['unknown_count']}")
    warnings.append("B2_restoration_metric_not_applicable_under_current_case_local_comparator_contract")
    verdict = "FAIL_REPAIR" if not integrity["valid"] else ("PASS_WITH_WARNINGS" if warnings else "PASS")
    gate = {
        "gate_id": "G4_E5_CONTEXT_RESTORATION_VALIDITY_V1_1",
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
