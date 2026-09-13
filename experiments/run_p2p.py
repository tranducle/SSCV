from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sscv import p2p_runner
from sscv import p2p_schema_runner


def _subset(manifest: dict, limit: int | None) -> dict:
    anchors = list(manifest.get("anchors", ()))
    if limit is not None:
        anchors = anchors[:limit]
    return {**manifest, "anchors": anchors, "anchor_count": len(anchors)}


def replay(limit_evaluation: int | None = None, limit_schema: int | None = None) -> dict:
    index = p2p_runner.load_index()

    evaluation_manifest = _subset(
        p2p_runner.load_manifest("evaluation_sample.json"), limit_evaluation
    )
    evaluation_rows = p2p_runner.run_anchor_manifest(index, evaluation_manifest)
    evaluation_summary = p2p_runner.summarize_rows(evaluation_rows)

    schema_manifest = _subset(
        p2p_runner.load_manifest("schema_stress_sample.json"), limit_schema
    )
    schema_base_rows = p2p_runner.run_anchor_manifest(index, schema_manifest)
    schema_base_index = {
        (str(row["stable_anchor_id"]), str(row["case_view"])): row
        for row in schema_base_rows
    }
    schema_rows = p2p_schema_runner.run_e9_manifest(
        index, schema_manifest, schema_base_index
    )
    schema_summary = p2p_schema_runner.summarize_e9_rows(schema_rows)

    return {
        "evaluation": {"summary": evaluation_summary, "rows": evaluation_rows},
        "schema_stress": {"summary": schema_summary, "rows": schema_rows},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay the SSCV P2P public-source study.")
    parser.add_argument("--limit-evaluation", type=int)
    parser.add_argument("--limit-schema", type=int)
    parser.add_argument("--out", default="results/p2p/replay.json")
    args = parser.parse_args()
    report = replay(args.limit_evaluation, args.limit_schema)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    result_dir = ROOT / "results" / "p2p"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "evaluation_results.json").write_text(
        json.dumps({"rows": report["evaluation"]["rows"]}, indent=2) + "\n",
        encoding="utf-8",
    )
    (result_dir / "schema_results.json").write_text(
        json.dumps({"rows": report["schema_stress"]["rows"]}, indent=2) + "\n",
        encoding="utf-8",
    )
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
