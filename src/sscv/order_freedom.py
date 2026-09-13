from __future__ import annotations

import hashlib
import json
from itertools import combinations
from pathlib import Path
from typing import Any

from . import synthetic_generator as generator
from . import synthetic_pairing as pairing
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "configs" / "synthetic"
E7_MATRIX = CONFIG_ROOT / "bound_sensitivity_matrix.json"
E11_MATRIX = CONFIG_ROOT / "scaling_matrix.json"
E7_MANIFEST = CONFIG_ROOT / "order_freedom_sensitivity.json"
E11_MANIFEST = CONFIG_ROOT / "order_freedom_scaling.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _visible_precedence(view: Any) -> set[tuple[str, str]]:
    by_case: dict[str, list[Any]] = {}
    for row in view.rows:
        by_case.setdefault(str(row.case_id), []).append(row)
    edges: set[tuple[str, str]] = set()
    for rows in by_case.values():
        ordered = sorted(rows, key=lambda row: (int(row.rank), str(row.event_id)))
        for i, left in enumerate(ordered):
            for right in ordered[i + 1 :]:
                if left.event_id != right.event_id:
                    edges.add((str(left.event_id), str(right.event_id)))
    return edges


def _closure(ids: tuple[str, ...], edges: set[tuple[str, str]]) -> set[tuple[str, str]]:
    reach = {event_id: set() for event_id in ids}
    for left, right in edges:
        if left in reach and right in reach:
            reach[left].add(right)
    changed = True
    while changed:
        changed = False
        for left in ids:
            expanded: set[str] = set()
            for right in tuple(reach[left]):
                expanded.update(reach[right])
            before = len(reach[left])
            reach[left].update(expanded)
            if len(reach[left]) != before:
                changed = True
    return {(left, right) for left in ids for right in reach[left]}


def _mandatory_precedence(cell: Any) -> set[tuple[str, str]]:
    edges = _visible_precedence(cell.view)
    for template in cell.spec.optional_deleted_events:
        event_id = str(template.event.event_id)
        if template.before_event_id is not None:
            edges.add((event_id, str(template.before_event_id)))
        if template.after_event_id is not None:
            edges.add((str(template.after_event_id), event_id))
    return edges


def _contract_record(cell: Any, order_width: int) -> dict[str, Any]:
    visible_ids = {str(row.event_id) for row in cell.view.rows}
    optional_ids = {str(t.event.event_id) for t in cell.spec.optional_deleted_events}
    possible = tuple(sorted(visible_ids | optional_ids))
    reference_order = tuple(
        str(event_id)
        for event_id in cell.underlying_execution.order
        if str(event_id) in set(possible)
    )
    if set(reference_order) != set(possible) or len(reference_order) != len(possible):
        raise ValueError(f"reference order does not cover completion event universe for {cell.cell_id}")
    mandatory = _mandatory_precedence(cell)
    closure = _closure(possible, mandatory)
    motif_ids = tuple(str(x) for x in cell.motif_event_ids_value)
    motif_set = set(motif_ids)

    eligible: list[tuple[str, str]] = []
    for left, right in combinations(sorted(possible), 2):
        if (left, right) in closure or (right, left) in closure:
            continue
        eligible.append((left, right))

    def priority(pair: tuple[str, str]) -> tuple[int, str, str]:
        count = int(pair[0] in motif_set) + int(pair[1] in motif_set)
        category = 0 if count == 2 else 1 if count == 1 else 2
        return category, pair[0], pair[1]

    eligible.sort(key=priority)
    selected = eligible[: max(0, int(order_width))]
    return {
        "reference_order": list(reference_order),
        "reference_order_sha256": _canonical_sha(list(reference_order)),
        "visible_precedence_closure": [list(x) for x in sorted(closure)],
        "motif_event_ids": list(motif_ids),
        "motif_pair_eligible": tuple(sorted(motif_ids)) in eligible,
        "eligible_pair_count": len(eligible),
        "eligible_pairs": [list(x) for x in eligible],
        "order_width": int(order_width),
        "selected_pairs": [list(x) for x in selected],
        "selected_pair_count": len(selected),
    }


def _e7_base_index() -> dict[str, tuple[dict[str, Any], str]]:
    result: dict[str, tuple[dict[str, Any], str]] = {}
    for record in pairing.load_pairing_manifest()["pairs"]:
        for view_id, meta in record["cells"].items():
            result[str(meta["cell_id"])] = (record, str(view_id))
    return result


def build_e7_manifest() -> dict[str, Any]:
    matrix = _load(E7_MATRIX)
    base_ids = sorted({str(row["base_cell_id"]) for row in matrix["cells"]})
    index = _e7_base_index()
    instances = []
    for base_id in base_ids:
        record, view_id = index[base_id]
        cell = generator.build_cell(record, view_id)
        contract = _contract_record(cell, 4)
        instances.append(
            {
                "base_cell_id": base_id,
                "pair_key": str(record["pair_key"]),
                "case_view": view_id,
                "underlying_execution_sha256": cell.underlying_execution_sha256,
                **contract,
                "selected_B0": contract["eligible_pairs"][:3],
                "selected_B_plus_P": contract["eligible_pairs"][:4],
            }
        )
    core = {
        "version": "E7_ORDER_FREEDOM_MANIFEST_V1_2",
        "frozen_date": "2026-09-11",
        "status": "FROZEN_PRE_OUTCOME",
        "source_matrix_sha256": _sha(E7_MATRIX),
        "pairing_manifest_canonical_sha256": pairing.EXPECTED_MANIFEST_SHA256,
        "priority_rule": "motif-motif, motif-noise, noise-noise; deterministic event-id tie break",
        "base_case_count": len(instances),
        "instances": instances,
    }
    core["canonical_sha256"] = _canonical_sha(core)
    return core


def _e11_pair_record(row: dict[str, Any]) -> dict[str, Any]:
    view_id = str(row["case_view"])
    return {
        "pair_key": str(row["cell_id"]),
        "underlying_pair_seed": int(row["seed"]),
        "process_family": str(row["process_family"]),
        "motif": str(row["motif"]),
        "mechanism": str(row["mechanism"]),
        "mixed_recipe": [str(x) for x in row.get("mixed_recipe", [])],
        "tier": f"N{int(row['visible_events'])}",
        "parameters": {
            "visible_events": int(row["visible_events"]),
            "hidden_event_slack": int(row["hidden_event_slack"]),
            "hidden_object_width": int(row["hidden_object_width"]),
            "relation_free_edges": int(row["relation_free_edges"]),
            "order_width": int(row["order_width"]),
        },
        "replicate": int(row["replicate"]),
        "semantic_map_id": f"{row['process_family']}|{row['motif']}",
        "cells": {
            view_id: {
                "cell_id": str(row["cell_id"]),
                "original_cell_seed": int(row["seed"]),
            }
        },
    }


def build_e11_cell(row: dict[str, Any]):
    return generator.build_cell(_e11_pair_record(row), str(row["case_view"]))


def build_e11_manifest() -> dict[str, Any]:
    matrix = _load(E11_MATRIX)
    instances = []
    for row in matrix["cells"]:
        cell = build_e11_cell(row)
        contract = _contract_record(cell, int(row["order_width"]))
        instances.append(
            {
                "cell_id": str(row["cell_id"]),
                "case_view": str(row["case_view"]),
                "visible_events": int(row["visible_events"]),
                "motif": str(row["motif"]),
                "mechanism": str(row["mechanism"]),
                "replicate": int(row["replicate"]),
                "underlying_execution_sha256": cell.underlying_execution_sha256,
                **contract,
            }
        )
    core = {
        "version": "E11_ORDER_FREEDOM_MANIFEST_V1_2",
        "frozen_date": "2026-09-11",
        "status": "FROZEN_PRE_OUTCOME",
        "source_matrix_sha256": _sha(E11_MATRIX),
        "priority_rule": "motif-motif, motif-noise, noise-noise; deterministic event-id tie break",
        "cell_count": len(instances),
        "instances": instances,
    }
    core["canonical_sha256"] = _canonical_sha(core)
    return core


def first_e7_order_sensitive_instance() -> dict[str, Any]:
    manifest = build_e7_manifest()
    for item in manifest["instances"]:
        if item["eligible_pairs"]:
            return item
    raise RuntimeError("no E7 instance has an eligible order-freedom pair")


def freeze_manifests() -> tuple[dict[str, Any], dict[str, Any]]:
    e7 = build_e7_manifest()
    e11 = build_e11_manifest()
    E7_MANIFEST.write_text(json.dumps(e7, indent=2) + "\n", encoding="utf-8")
    E11_MANIFEST.write_text(json.dumps(e11, indent=2) + "\n", encoding="utf-8")
    return e7, e11


def main() -> int:
    e7, e11 = freeze_manifests()
    print("E7", e7["base_case_count"], e7["canonical_sha256"])
    print("E11", e11["cell_count"], e11["canonical_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
