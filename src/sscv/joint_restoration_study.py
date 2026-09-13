from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

from . import completion_models as fb
from . import restoration_study as e5
from . import witness_validation as iwv
from . import smt_verifier as smt
from . import synthetic_generator as gen
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / 'configs' / 'synthetic'
MANIFEST = CONFIG_ROOT / 'joint_restoration_manifest.json'


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding='utf-8-sig'))


def build_cell(cell_id: str) -> Any:
    record, view_id = e5.resolve_cell(cell_id)
    return gen.build_cell(record, view_id)


def restore_pair_spec(cell: Any) -> fb.Spec:
    recipe = set(cell.mixed_recipe)
    base = cell.spec
    bindings = base.hidden_binding_domains
    relations = base.hidden_relation_domain
    reference_order = base.reference_order
    order_free_pairs = base.order_free_pairs
    required_deleted = tuple(getattr(base, 'required_deleted_event_ids', ()))

    if 'binding' in recipe:
        bindings = e5._realized_bindings(cell)
    if 'relation' in recipe:
        relations = e5._realized_relation_choice(cell)
    if 'order' in recipe:
        reference_order = e5._realized_reference_order(cell)
        order_free_pairs = ()
    if 'deletion' in recipe:
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


def run_cell(cell_id: str) -> dict[str, Any]:
    cell = build_cell(cell_id)
    spec = restore_pair_spec(cell)
    solver = smt.default_solver()
    if solver is None:
        raise RuntimeError('real Z3-compatible backend required')
    start = time.perf_counter()
    result = smt.verify_smt(
        cell.view,
        spec,
        cell.motif,
        solver=solver,
        query_order=('safe', 'violation'),
    )
    elapsed = time.perf_counter() - start

    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            cell.view,
            spec,
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(report.valid)
        witness_errors = list(report.errors)
        witness_objective = list(report.objective) if report.objective is not None else None

    return {
        'run_id': f'E5B|{cell_id}|P+PAIR',
        'cell_id': cell_id,
        'profile': 'P+PAIR',
        'pair_key': cell.pair_key,
        'case_view': cell.constructor.constructor_id,
        'process_family': cell.process_family,
        'motif': cell.motif_id,
        'mechanism': cell.mechanism,
        'mixed_recipe': list(cell.mixed_recipe),
        'changed_spec_families': list(e5.changed_spec_families(cell.spec, spec)),
        'view_sha256': e5._view_sha(cell.view),
        'underlying_execution_sha256': cell.underlying_execution_sha256,
        'decision': result.decision,
        'verdicts': e5._labels(result.verdicts),
        'complete': bool(result.complete),
        'solver_statuses': list(result.solver_statuses),
        'unknown_reason': result.unknown_reason,
        'runtime_seconds': elapsed,
        'witness_returned': result.witness is not None,
        'witness_valid': witness_valid,
        'witness_errors': witness_errors,
        'witness_objective': witness_objective,
        'witness_minimal_claimed': bool(result.witness is not None and result.witness.minimal),
        'solver_backend': result.backend or solver.name,
        'solver_version': solver.version,
    }
