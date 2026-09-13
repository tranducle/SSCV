from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from . import completion_models as fb
from . import scaling_base as legacy
from . import hidden_event_bounds as slack
from . import witness_validation as iwv
from . import order_freedom as ofm
from . import smt_verifier as smt
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / 'configs' / 'synthetic'
MATRIX = CONFIG_ROOT / 'scaling_matrix.json'
AMENDMENT = CONFIG_ROOT / 'hidden_event_bound_amendment.md'
OUT = REPO_ROOT / 'results' / 'scaling'
RESULT = OUT / 'results.json'
SUMMARY = OUT / 'summary.json'
RUN_MANIFEST = OUT / 'run_manifest.json'
WARMUP_RESULT = OUT / 'warmups.json'
SENTINEL_RESULT = OUT / 'timing_sentinels.json'
WITNESS_RESULT = OUT / 'witness_overhead.json'
QUALIFICATION = OUT / 'structural_qualification.json'
INTEGRITY_GATE = OUT / 'integrity.json'
SIZES = legacy.SIZES


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8-sig'))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _view_sha(view: Any) -> str:
    rows = sorted((str(r.case_id), int(r.rank), str(r.event_id), str(r.activity), r.actor) for r in view.rows)
    return _canonical_sha(rows)


def load_matrix() -> dict[str, Any]:
    return _load(MATRIX)


def load_matrix_rows() -> list[dict[str, Any]]:
    return list(load_matrix()['cells'])


def warmup_rows() -> list[dict[str, Any]]:
    return [
        row for row in load_matrix_rows()
        if int(row['visible_events']) == 4
        and str(row['mechanism_condition']) == 'none'
        and int(row['replicate']) == 1
    ]


def sentinel_rows() -> list[dict[str, Any]]:
    return [
        row for row in load_matrix_rows()
        if int(row['visible_events']) in {8, 24}
        and str(row['mechanism_condition']) == 'none'
        and int(row['replicate']) == 1
    ]


def witness_subset_rows() -> list[dict[str, Any]]:
    return [row for row in load_matrix_rows() if bool(row.get('witness_overhead_subset'))]


def resource_budgets_ms() -> dict[str, int]:
    envelope = load_matrix()['resource_envelope']
    return {
        'primary_timeout_ms': int(envelope['timeout_per_existence_query_seconds']) * 1000,
        'witness_timeout_ms': int(envelope['witness_optimization_budget_seconds']) * 1000,
    }


def expected_sentinel_repeat_count(launched_sizes: list[int] | tuple[int, ...]) -> int:
    launched = set(int(size) for size in launched_sizes)
    return len([row for row in sentinel_rows() if int(row['visible_events']) in launched]) * 3


def build_cell(row: dict[str, Any]) -> dict[str, Any]:
    cell = ofm.build_e11_cell(row)
    target_slack = int(row['hidden_event_slack'])
    templates = slack.materialize_hidden_event_templates(cell, target_slack)
    contract = slack.build_order_contract(cell, templates, int(row['order_width']))
    spec = fb.Spec(
        hidden_binding_domains=tuple(cell.spec.hidden_binding_domains),
        hidden_relation_domain=tuple(cell.spec.hidden_relation_domain),
        optional_deleted_events=tuple(templates),
        max_completions=cell.spec.max_completions,
        reference_order=tuple(str(value) for value in contract['reference_order']),
        order_free_pairs=tuple(tuple(str(item) for item in pair) for pair in contract['selected_pairs']),
        required_deleted_event_ids=tuple(getattr(cell.spec, 'required_deleted_event_ids', ())),
    )
    return {
        'cell': cell,
        'spec': spec,
        'contract': contract,
        'view_sha256': _view_sha(cell.view),
        'underlying_execution_sha256': cell.underlying_execution_sha256,
        'hidden_event_candidate_count': len(templates),
        'hidden_event_slack_noop': len(templates) != target_slack,
        'filler_event_ids': list(slack.slack_filler_ids(templates)),
        'selected_order_pairs': [list(pair) for pair in contract['selected_pairs']],
        'spec_sha256': _canonical_sha({
            'hidden_binding_domains': spec.hidden_binding_domains,
            'hidden_relation_domain': spec.hidden_relation_domain,
            'optional_deleted_event_ids': [t.event.event_id for t in spec.optional_deleted_events],
            'reference_order': spec.reference_order,
            'order_free_pairs': spec.order_free_pairs,
        }),
    }


def structural_qualification() -> dict[str, Any]:
    rows = load_matrix_rows()
    errors: list[str] = []
    slack_counts = Counter()
    size_counts = Counter()
    for row in rows:
        built = build_cell(row)
        target = int(row['hidden_event_slack'])
        slack_counts[target] += 1
        size_counts[int(row['visible_events'])] += 1
        if built['hidden_event_candidate_count'] != target or built['hidden_event_slack_noop']:
            errors.append(f'slack_materialization:{row["cell_id"]}')
        fillers = set(built['filler_event_ids'])
        for left, right in built['selected_order_pairs']:
            if left in fillers or right in fillers:
                errors.append(f'filler_order_pair:{row["cell_id"]}')
        visible_count = len({str(item.event_id) for item in built['cell'].view.rows})
        if visible_count != int(row['visible_events']):
            errors.append(f'visible_count:{row["cell_id"]}:{visible_count}')
    criteria = {
        'exact_216_cells': len(rows) == 216,
        'exact_36_per_size': all(size_counts[size] == 36 for size in SIZES),
        'slack_distribution_72_each': slack_counts == Counter({1: 72, 2: 72, 3: 72}),
        'warmup_count_6': len(warmup_rows()) == 6,
        'sentinel_base_count_12': len(sentinel_rows()) == 12,
        'witness_subset_count_36': len(witness_subset_rows()) == 36,
        'zero_structural_errors': not errors,
        'amendment_exists': AMENDMENT.exists(),
    }
    failed = [name for name, ok in criteria.items() if not ok]
    return {
        'gate_id': 'E11_STRUCTURAL_QUALIFICATION_V1_3',
        'date': '2026-09-11',
        'verdict': 'PASS' if not failed else 'FAIL_REPAIR',
        'cell_count': len(rows),
        'size_counts': {str(key): value for key, value in sorted(size_counts.items())},
        'slack_counts': {str(key): value for key, value in sorted(slack_counts.items())},
        'criteria': criteria,
        'failed_criteria': failed,
        'structural_errors': errors,
        'matrix_sha256': _sha(MATRIX),
        'amendment_sha256': _sha(AMENDMENT) if AMENDMENT.exists() else None,
        'claim_boundary': 'Corrective scaling materializes the declared hidden-event candidate count. Neutral fillers preserve mechanism isolation and do not model arbitrary security-relevant hidden activities.',
    }


class BudgetSolver:
    def __init__(self, inner: Any, timeout_ms: int):
        if inner is None:
            raise RuntimeError('solver unavailable')
        self.inner = inner
        self.timeout_ms = int(timeout_ms)

    @property
    def name(self) -> str:
        return f'{self.inner.name};timeout_ms={self.timeout_ms};threads=1-sequential'

    @property
    def version(self) -> str:
        return self.inner.version

    def solve(self, smt2: str, variables: Any):
        return self.inner.solve(f'(set-option :timeout {self.timeout_ms})\n' + smt2, variables)

    def status_only(self, smt2: str) -> str:
        status, _ = self.solve(smt2, ())
        return status


def _peak_rss_bytes() -> int | None:
    return legacy._peak_rss_bytes()


def _resource_ok(peak_rss: int | None, limit_gib: float) -> bool:
    return legacy._resource_ok(peak_rss, limit_gib)


def can_advance(completed: int, total: int) -> bool:
    return legacy.can_advance(completed, total)


def decision_from_statuses(safe_status: str, violation_status: str) -> tuple[str, list[str], bool, str | None]:
    return legacy.decision_from_statuses(safe_status, violation_status)


def run_primary(row: dict[str, Any], solver: BudgetSolver, memory_limit_gib: float) -> dict[str, Any]:
    built = build_cell(row)
    cell = built['cell']
    encoding = smt.Encoding(cell.view, built['spec'], cell.motif)
    start = time.perf_counter()
    statuses: list[str] = []
    for target in ('safe', 'violation'):
        if not encoding.consistent:
            statuses.append('error')
            continue
        statuses.append(solver.status_only(encoding.script_for(target)))
        if statuses[-1] in {'unknown', 'error'}:
            break
    elapsed = time.perf_counter() - start
    while len(statuses) < 2:
        statuses.append('not_run')
    if 'not_run' in statuses:
        decision, verdicts, complete, reason = 'unknown', [], False, f'solver_{statuses[0]}'
    else:
        decision, verdicts, complete, reason = decision_from_statuses(statuses[0], statuses[1])
    peak = _peak_rss_bytes()
    memory_ok = _resource_ok(peak, memory_limit_gib)
    operational_completed = all(status in {'sat', 'unsat'} for status in statuses) and memory_ok
    if not memory_ok:
        decision, verdicts, complete, reason = 'unknown', [], False, 'memory_envelope_violation'
    return {
        'cell_id': str(row['cell_id']),
        'visible_events': int(row['visible_events']),
        'motif': str(row['motif']),
        'process_family': str(row['process_family']),
        'case_view': str(row['case_view']),
        'mechanism_condition': str(row['mechanism_condition']),
        'mechanism': str(row['mechanism']),
        'replicate': int(row['replicate']),
        'seed': int(row['seed']),
        'witness_overhead_subset': bool(row.get('witness_overhead_subset')),
        'declared_bound': {
            'hidden_event_slack': int(row['hidden_event_slack']),
            'hidden_object_width': int(row['hidden_object_width']),
            'relation_free_edges': int(row['relation_free_edges']),
            'order_width': int(row['order_width']),
        },
        'view_sha256': built['view_sha256'],
        'underlying_execution_sha256': built['underlying_execution_sha256'],
        'spec_sha256': built['spec_sha256'],
        'eligible_order_pair_count': int(built['contract']['eligible_pair_count']),
        'selected_order_pair_count': int(built['contract']['selected_pair_count']),
        'selected_order_pairs': built['selected_order_pairs'],
        'hidden_event_template_count': built['hidden_event_candidate_count'],
        'hidden_event_slack_noop': built['hidden_event_slack_noop'],
        'hidden_event_filler_count': len(built['filler_event_ids']),
        'decision': decision,
        'verdicts': verdicts,
        'complete': complete,
        'operational_completed': operational_completed,
        'solver_statuses': statuses,
        'unknown_reason': reason,
        'runtime_seconds': elapsed,
        'peak_rss_bytes': peak,
        'memory_envelope_ok': memory_ok,
        'backend': solver.name,
    }


def run_witness_materialization(row: dict[str, Any], solver: BudgetSolver) -> dict[str, Any]:
    built = build_cell(row)
    cell = built['cell']
    start = time.perf_counter()
    result = smt.verify_smt(cell.view, built['spec'], cell.motif, solver=solver, query_order=('safe', 'violation'))
    elapsed = time.perf_counter() - start
    valid = None
    errors: list[str] = []
    objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            cell.view,
            built['spec'],
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        valid = bool(report.valid)
        errors = list(report.errors)
        objective = list(report.objective) if report.valid and report.objective is not None else None
    return {
        'cell_id': str(row['cell_id']),
        'decision': result.decision,
        'runtime_seconds': elapsed,
        'witness_returned': result.witness is not None,
        'witness_valid': valid,
        'witness_errors': errors,
        'witness_objective': objective,
        'minimality_claimed': bool(result.witness is not None and result.witness.minimal),
        'mode': 'witness_materialization_and_independent_validation',
        'protocol_warning': 'No global witness-objective optimization is implemented; no minimality or optimization-overhead claim is made.',
    }


def summarize(primary: list[dict[str, Any]], sentinels: list[dict[str, Any]], witness: list[dict[str, Any]]) -> dict[str, Any]:
    base = legacy.summarize(primary, sentinels, witness)
    for size, record in base['by_size'].items():
        selected = [row for row in primary if int(row['visible_events']) == int(size)]
        record['hidden_event_candidate_counts'] = dict(sorted(Counter(row['hidden_event_template_count'] for row in selected).items()))
        record['process_peak_rss_note'] = 'Windows peak_wset is a process-lifetime high-water mark; use only for envelope compliance, not per-cell memory scaling.'
    return base


def validate_integrity(primary: list[dict[str, Any]], warmups: list[dict[str, Any]], sentinels: list[dict[str, Any]], witness: list[dict[str, Any]], qualification: dict[str, Any]) -> dict[str, Any]:
    base = legacy.validate_integrity(primary, warmups, sentinels, witness)
    errors = list(base['errors'])
    if qualification['verdict'] != 'PASS':
        errors.append('structural_qualification_not_pass')
    matrix_by_id = {str(row['cell_id']): row for row in load_matrix_rows()}
    for row in primary:
        expected = int(matrix_by_id[row['cell_id']]['hidden_event_slack'])
        if int(row['hidden_event_template_count']) != expected or bool(row['hidden_event_slack_noop']):
            errors.append(f'hidden_event_slack:{row["cell_id"]}')
    return {
        'valid': not errors,
        'errors': sorted(set(errors)),
        'primary_row_count': len(primary),
        'launched_sizes': base['launched_sizes'],
    }


def run_official() -> dict[str, Any]:
    paths = (RESULT, SUMMARY, RUN_MANIFEST, WARMUP_RESULT, SENTINEL_RESULT, WITNESS_RESULT, QUALIFICATION, INTEGRITY_GATE)
    for path in paths:
        if path.exists():
            raise FileExistsError(f'refuse silent overwrite: {path}')
    OUT.mkdir(parents=True, exist_ok=True)
    qualification = structural_qualification()
    QUALIFICATION.write_text(json.dumps(qualification, indent=2) + '\n', encoding='utf-8')
    if qualification['verdict'] != 'PASS':
        raise RuntimeError(f'E11 V1.3 structural qualification failed: {qualification["failed_criteria"]}')

    matrix = load_matrix()
    envelope = matrix['resource_envelope']
    budgets = resource_budgets_ms()
    solver = BudgetSolver(smt.default_solver(), budgets['primary_timeout_ms'])
    witness_solver = BudgetSolver(smt.default_solver(), budgets['witness_timeout_ms'])
    memory_limit = float(envelope['peak_rss_gib'])

    warmups: list[dict[str, Any]] = []
    for row in warmup_rows():
        result = run_primary(row, solver, memory_limit)
        result['warmup'] = True
        warmups.append(result)
    WARMUP_RESULT.write_text(json.dumps({'version': 'E11_WARMUPS_V1_3', 'rows': warmups}, indent=2) + '\n', encoding='utf-8')

    primary: list[dict[str, Any]] = []
    stop_reason = None
    start = time.perf_counter()
    for size in SIZES:
        size_rows = [row for row in matrix['cells'] if int(row['visible_events']) == size]
        current = [run_primary(row, solver, memory_limit) for row in size_rows]
        primary.extend(current)
        completed = sum(bool(item['operational_completed']) for item in current)
        print(f'E11_V13_SIZE {size} COMPLETED {completed}/36', flush=True)
        if not can_advance(completed, 36):
            stop_reason = f'tier_advance_failed_at_size_{size}:{completed}/36'
            break
    wall = time.perf_counter() - start

    launched_ids = {row['cell_id'] for row in primary}
    sentinels: list[dict[str, Any]] = []
    for row in sentinel_rows():
        if str(row['cell_id']) not in launched_ids:
            continue
        for repeat in range(1, 4):
            result = run_primary(row, solver, memory_limit)
            result['repeat'] = repeat
            sentinels.append(result)
    SENTINEL_RESULT.write_text(json.dumps({'version': 'E11_TIMING_SENTINELS_V1_3', 'rows': sentinels}, indent=2) + '\n', encoding='utf-8')

    primary_by_id = {row['cell_id']: row for row in primary}
    matrix_by_id = {str(row['cell_id']): row for row in matrix['cells']}
    witness_rows: list[dict[str, Any]] = []
    for selected in witness_subset_rows():
        cell_id = str(selected['cell_id'])
        if cell_id not in launched_ids:
            continue
        primary_row = primary_by_id[cell_id]
        if primary_row['decision'] != 'unsound':
            witness_rows.append({'cell_id': cell_id, 'status': 'NOT_APPLICABLE', 'primary_decision': primary_row['decision']})
            continue
        measured = run_witness_materialization(matrix_by_id[cell_id], witness_solver)
        measured['status'] = 'MEASURED'
        measured['primary_runtime_seconds'] = primary_row['runtime_seconds']
        measured['runtime_delta_seconds'] = measured['runtime_seconds'] - primary_row['runtime_seconds']
        witness_rows.append(measured)
    WITNESS_RESULT.write_text(json.dumps({'version': 'E11_WITNESS_OVERHEAD_V1_3', 'rows': witness_rows}, indent=2) + '\n', encoding='utf-8')

    result_obj = {
        'version': 'E11_RESULTS_V1_3',
        'matrix_sha256': _sha(MATRIX),
        'amendment_sha256': _sha(AMENDMENT),
        'stop_reason': stop_reason,
        'rows': primary,
    }
    summary_obj = {
        'version': 'E11_SUMMARY_V1_3',
        'summary': summarize(primary, sentinels, witness_rows),
        'claim_boundary': 'Scaling characterization only within actually launched sizes and the fixed operational envelope. Hidden-event candidate counts now match the frozen matrix. No asymptotic, deployment-scale, per-cell memory-scaling, or global witness-optimization claim.',
    }
    RESULT.write_text(json.dumps(result_obj, indent=2) + '\n', encoding='utf-8')
    SUMMARY.write_text(json.dumps(summary_obj, indent=2) + '\n', encoding='utf-8')

    run_obj = {
        'run_id': 'SSCV_E11_CORRECTIVE_V1_3_20260911',
        'experiment': 'E11_BOUNDED_SCALING_CORRECTIVE',
        'official_corrective': True,
        'trigger': 'pre-G7 independent review found declared hidden_event_slack was not materialized in V1.2',
        'matrix_sha256': _sha(MATRIX),
        'amendment_sha256': _sha(AMENDMENT),
        'resource_envelope': envelope,
        'backend': solver.name,
        'backend_version': solver.version,
        'witness_backend': witness_solver.name,
        'primary_timeout_ms': budgets['primary_timeout_ms'],
        'witness_timeout_ms': budgets['witness_timeout_ms'],
        'wall_seconds_primary': wall,
        'stop_reason': stop_reason,
        'historical_e11_v1_2_preserved': True,
        'memory_measurement_boundary': 'peak_wset is process-lifetime high-water mark on Windows; used only for 16 GiB envelope compliance, not per-cell scaling.',
        'code_sha256': {
            'runner': _sha(Path(__file__).resolve()),
            'slack_helper': _sha(Path(slack.__file__).resolve()),
            'smt_verifier': _sha(Path(smt.__file__).resolve()),
            'witness_validator': _sha(Path(iwv.__file__).resolve()),
        },
    }
    RUN_MANIFEST.write_text(json.dumps(run_obj, indent=2) + '\n', encoding='utf-8')

    integrity = validate_integrity(primary, warmups, sentinels, witness_rows, qualification)
    warnings = ['global_witness_optimization_not_implemented; witness subset measures materialization_and_validation only', 'Windows peak_wset is process-lifetime high-water mark; no per-cell memory-scaling claim']
    if summary_obj['summary']['launched_sizes'] != list(SIZES):
        warnings.append('staircase_stopped_before_size_32')
    verdict = 'FAIL_REPAIR' if not integrity['valid'] else 'PASS_WITH_WARNINGS'
    gate = {
        'gate_id': 'E11_BOUNDED_SCALING_INTEGRITY_V1_3',
        'verdict': verdict,
        'failed_criteria': integrity['errors'],
        'warnings': warnings,
        'integrity': integrity,
        'result_sha256': _sha(RESULT),
        'summary_sha256': _sha(SUMMARY),
        'run_manifest_sha256': _sha(RUN_MANIFEST),
        'warmup_sha256': _sha(WARMUP_RESULT),
        'sentinel_sha256': _sha(SENTINEL_RESULT),
        'witness_overhead_sha256': _sha(WITNESS_RESULT),
        'qualification_sha256': _sha(QUALIFICATION),
        'summary': summary_obj['summary'],
    }
    INTEGRITY_GATE.write_text(json.dumps(gate, indent=2) + '\n', encoding='utf-8')
    print('VERDICT', gate['verdict'])
    print('FAILED', gate['failed_criteria'])
    print('WARNINGS', gate['warnings'])
    print('SUMMARY', json.dumps(gate['summary'], sort_keys=True))
    return gate


if __name__ == '__main__':
    gate = run_official()
    raise SystemExit(0 if gate['verdict'] in {'PASS', 'PASS_WITH_WARNINGS'} else 2)
