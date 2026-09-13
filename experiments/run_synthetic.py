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

from sscv import smt_verifier
from sscv import synthetic_generator
from sscv import synthetic_pairing
from sscv import witness_validation


def replay(limit_pairs: int | None = None) -> dict:
    manifest = synthetic_pairing.load_pairing_manifest()
    pairs = list(manifest["pairs"])
    if limit_pairs is not None:
        pairs = pairs[:limit_pairs]

    rows = []
    for record in pairs:
        for view_id in sorted(record["cells"]):
            cell = synthetic_generator.build_cell(record, view_id)
            result = smt_verifier.verify_smt(cell.view, cell.spec, cell.motif)
            witness_valid = None
            if result.witness is not None:
                validation = witness_validation.validate_witness(
                    cell.view,
                    cell.spec,
                    cell.motif,
                    result.witness.safe_execution,
                    result.witness.violating_execution,
                )
                witness_valid = bool(validation.valid)
            rows.append(
                {
                    "pair_key": cell.pair_key,
                    "view": view_id,
                    "decision": result.decision,
                    "verdicts": list(result.verdicts),
                    "witness_returned": result.witness is not None,
                    "witness_valid": witness_valid,
                }
            )

    decisions = Counter(row["decision"] for row in rows)
    transitions = Counter()
    by_pair: dict[str, dict[str, str]] = {}
    for row in rows:
        by_pair.setdefault(row["pair_key"], {})[row["view"]] = row["decision"]
    for pair in by_pair.values():
        if "CV-D" in pair and "CV-R1" in pair:
            transitions[f"{pair['CV-D']}->{pair['CV-R1']}"] += 1

    return {
        "pair_count": len(pairs),
        "row_count": len(rows),
        "decision_counts": dict(sorted(decisions.items())),
        "paired_transitions": dict(sorted(transitions.items())),
        "invalid_witness_count": sum(
            row["witness_returned"] and row["witness_valid"] is not True for row in rows
        ),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay the controlled paired-view SSCV study.")
    parser.add_argument("--limit-pairs", type=int)
    parser.add_argument("--out", default="results/synthetic/paired_evaluation.json")
    args = parser.parse_args()
    report = replay(args.limit_pairs)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
