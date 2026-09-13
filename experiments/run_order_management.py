from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sscv import order_management_runner
from sscv import order_management_schema_stress

VIEWS = ("CV-D", "CV-R1")


def _subset(manifest: dict, limit: int | None) -> dict:
    anchors = list(manifest.get("anchors", ()))
    if limit is not None:
        anchors = anchors[:limit]
    return {**manifest, "anchors": anchors, "anchor_count": len(anchors)}


def _summary(rows: list[dict], key: str) -> dict:
    by_view = {}
    for view in VIEWS:
        selected = [row for row in rows if row["case_view"] == view]
        by_view[view] = dict(sorted(Counter(str(row[key]) for row in selected).items()))
    return {
        "row_count": len(rows),
        "anchor_count": len({str(row["stable_anchor_id"]) for row in rows}),
        "by_case_view": by_view,
    }


def replay(limit_evaluation: int | None = None, limit_schema: int | None = None) -> dict:
    index = order_management_runner.load_index()

    evaluation_manifest = _subset(
        order_management_runner.load_manifest("evaluation_sample.json"), limit_evaluation
    )
    evaluation_rows = []
    for anchor in evaluation_manifest["anchors"]:
        for view in VIEWS:
            evaluation_rows.append(order_management_runner.run_anchor_view(index, anchor, view))

    schema_manifest = _subset(
        order_management_runner.load_manifest("schema_stress_sample.json"), limit_schema
    )
    schema_rows = []
    for anchor in schema_manifest["anchors"]:
        for view in VIEWS:
            base = order_management_runner.run_anchor_view(index, anchor, view)
            audit = order_management_runner.build_r_obs_audit(index, anchor, view)
            result = order_management_schema_stress.verify_smt_schema(audit)
            witness_valid = None
            witness_errors: list[str] = []
            if result.witness is not None:
                validation = order_management_schema_stress.validate_schema_witness(audit, result)
                witness_valid = bool(validation.valid)
                witness_errors = list(validation.errors)
            schema_rows.append(
                {
                    "stable_anchor_id": anchor["stable_anchor_id"],
                    "case_view": view,
                    "underlying_execution_sha256": audit.underlying_execution_sha256,
                    "observed_decision": base["sscv_decision"],
                    "schema_decision": result.decision,
                    "transition": f"{base['sscv_decision']}->{result.decision}",
                    "witness_returned": result.witness is not None,
                    "witness_valid": witness_valid,
                    "witness_errors": witness_errors,
                }
            )

    schema_summary = _summary(schema_rows, "schema_decision")
    schema_summary["transitions"] = dict(
        sorted(Counter(row["transition"] for row in schema_rows).items())
    )
    schema_summary["invalid_witness_count"] = sum(
        row["witness_returned"] and row["witness_valid"] is not True
        for row in schema_rows
    )

    return {
        "evaluation": {
            "summary": _summary(evaluation_rows, "sscv_decision"),
            "rows": evaluation_rows,
        },
        "schema_stress": {"summary": schema_summary, "rows": schema_rows},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay the SSCV Order Management public-source study."
    )
    parser.add_argument("--limit-evaluation", type=int)
    parser.add_argument("--limit-schema", type=int)
    parser.add_argument("--out", default="results/order_management/replay.json")
    args = parser.parse_args()
    report = replay(args.limit_evaluation, args.limit_schema)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "evaluation": report["evaluation"]["summary"],
                "schema_stress": report["schema_stress"]["summary"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
