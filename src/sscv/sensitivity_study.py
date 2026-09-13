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
from . import sensitivity_base as legacy
from . import hidden_event_bounds as slack
from . import witness_validation as iwv
from . import smt_verifier as smt
from . import synthetic_generator as generator
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / 'configs' / 'synthetic'
MATRIX = CONFIG_ROOT / 'bound_sensitivity_matrix.json'
AMENDMENT = CONFIG_ROOT / 'hidden_event_bound_amendment.md'
OUT = REPO_ROOT / 'results' / 'sensitivity'
RESULT = OUT / 'results.json'
SUMMARY = OUT / 'summary.json'
RUN_MANIFEST = OUT / 'run_manifest.json'
QUALIFICATION = OUT / 'structural_qualification.json'
INTEGRITY_GATE = OUT / 'integrity.json'


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8-sig'))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _view_sha(view: Any) -> str:
    rows = sorted(
        (str(row.case_id), int(row.rank), str(row.event_id), str(row.activity), row.actor)
        for row in view.rows
    )
    return _canonical_sha(rows)


def load_matrix_rows() -> list[dict[str, Any]]:
    return list(_load(MATRIX)['cells'])


def group_matrix_rows() -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in load_matrix_rows():
        grouped[str(row['base_cell_id'])].append(row)
    return grouped


def _binding_signature(domains: Any) -> str:
    return _canonical_sha(domains)


def _relation_signature(domain: Any) -> str:
    return _canonical_sha(domain)


def _spec_signature(spec: fb.Spec) -> str:
    payload = {
        'hidden_binding_domains': spec.hidden_binding_domains,
        'hidden_relation_domain': spec.hidden_relation_domain,
        'optional_deleted_events': [
            {
                'event_id': template.event.event_id,
                'activity': template.event.activity,
                'actor': template.event.actor,
                'case_ids': template.event.case_ids,
                'hidden_objects': template.event.hidden_objects,
                'before_event_id': template.before_event_id,
                'after_event_id': template.after_event_id,
            }
            for template in spec.optional_deleted_events
        ],
        'reference_order': spec.reference_order,
        'order_free_pairs': spec.order_free_pairs,
        'required_deleted_event_ids': spec.required_deleted_event_ids,
    }
    return _canonical_sha(payload)


def build_variant(row: dict[str, Any]) -> dict[str, Any]:
    base_id = str(row['base_cell_id'])
    pair_record, view_id = legacy._pair_index()[base_id]
    cell = generator.build_cell(pair_record, view_id)
    token = legacy._token_from_cell(cell)

    target_width = int(row['hidden_object_width'])
    binding_domains = legacy._extend_binding_domains(cell.spec.hidden_binding_domains, token, target_width)
    relation_variable = len(cell.spec.hidden_relation_domain) > 1
    relation_domain = (
        legacy._relation_domain(token, int(row['relation_free_edges']))
        if relation_variable
        else cell.spec.hidden_relation_domain
    )

    templates = slack.materialize_hidden_event_templates(cell, int(row['hidden_event_slack']))
    contract = slack.build_order_contract(cell, templates, int(row['order_width']))
    spec = fb.Spec(
        hidden_binding_domains=tuple(binding_domains),
        hidden_relation_domain=tuple(relation_domain),
        optional_deleted_events=tuple(templates),
        max_completions=cell.spec.max_completions,
        reference_order=tuple(str(value) for value in contract['reference_order']),
        order_free_pairs=tuple(tuple(str(item) for item in pair) for pair in contract['selected_pairs']),
        required_deleted_event_ids=tuple(getattr(cell.spec, 'required_deleted_event_ids', ())),
    )
    candidate_ids = [str(template.event.event_id) for template in templates]
    return {
        'row': row,
        'cell': cell,
        'spec': spec,
        'base_cell_id': base_id,
        'run_id': str(row['run_id']),
        'variant': str(row['variant']),
        'view_sha256': _view_sha(cell.view),
        'underlying_execution_sha256': cell.underlying_execution_sha256,
        'binding_domain_signature': _binding_signature(spec.hidden_binding_domains),
        'relation_domain_signature': _relation_signature(spec.hidden_relation_domain),
        'spec_sha256': _spec_signature(spec),
        'hidden_event_candidate_ids': candidate_ids,
        'hidden_event_candidate_count': len(candidate_ids),
        'hidden_event_filler_count': len(slack.slack_filler_ids(templates)),
        'reference_order': list(contract['reference_order']),
        'eligible_order_pair_count': int(contract['eligible_pair_count']),
        'selected_order_pairs': [list(pair) for pair in contract['selected_pairs']],
        'selected_order_pair_count': int(contract['selected_pair_count']),
        'binding_domain_max_choices': max((len(item[1]) for item in spec.hidden_binding_domains), default=0),
        'relation_domain_choice_count': len(spec.hidden_relation_domain),
    }


def structural_qualification() -> dict[str, Any]:
    groups = group_matrix_rows()
    errors: list[str] = []
    active = 0
    for base_id, rows in groups.items():
        if {str(row['variant']) for row in rows} != {'B0', 'B+E', 'B+O', 'B+R', 'B+P'}:
            errors.append(f'variant_set:{base_id}')
            continue
        built = {str(row['variant']): build_variant(row) for row in rows}
        base = built['B0']
        event = built['B+E']
        expected_counts = {'B0': 2, 'B+E': 3, 'B+O': 2, 'B+R': 2, 'B+P': 2}
        for variant, expected in expected_counts.items():
            if built[variant]['hidden_event_candidate_count'] != expected:
                errors.append(f'event_count:{base_id}:{variant}')
        if (
            event['hidden_event_candidate_ids'][:2] == base['hidden_event_candidate_ids']
            and len(event['hidden_event_candidate_ids']) == len(base['hidden_event_candidate_ids']) + 1
            and event['spec_sha256'] != base['spec_sha256']
        ):
            active += 1
        else:
            errors.append(f'b_plus_e_not_active:{base_id}')
        for field in (
            'view_sha256',
            'underlying_execution_sha256',
            'binding_domain_signature',
            'relation_domain_signature',
            'selected_order_pairs',
        ):
            if event[field] != base[field]:
                errors.append(f'b_plus_e_changed_{field}:{base_id}')
        for variant in ('B+O', 'B+R', 'B+P'):
            if built[variant]['hidden_event_candidate_ids'] != base['hidden_event_candidate_ids']:
                errors.append(f'non_event_variant_changed_events:{base_id}:{variant}')
    criteria = {
        'exact_108_base_cases': len(groups) == 108,
        'exact_540_runs': sum(len(rows) for rows in groups.values()) == 540,
        'b_plus_e_active_108_of_108': active == 108,
        'zero_structural_errors': not errors,
        'amendment_exists': AMENDMENT.exists(),
    }
    failed = [name for name, ok in criteria.items() if not ok]
    return {
        'gate_id': 'E7_STRUCTURAL_QUALIFICATION_V1_3',
        'date': '2026-09-11',
        'verdict': 'PASS' if not failed else 'FAIL_REPAIR',
        'base_case_count': len(groups),
        'run_count': sum(len(rows) for rows in groups.values()),
        'b_plus_e_active_count': active,
        'criteria': criteria,
        'failed_criteria': failed,
        'structural_errors': errors,
        'source_matrix_sha256': _sha(MATRIX),
        'amendment_sha256': _sha(AMENDMENT) if AMENDMENT.exists() else None,
        'claim_boundary': 'V1.3 repairs hidden-event candidate capacity with motif-neutral fillers. It does not model arbitrary hidden security-relevant activity schemas.',
    }


class TimeoutSolver:
    def __init__(self, inner: Any, timeout_ms: int = 30000):
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


def _peak_rss_bytes() -> int | None:
    try:
        import psutil
        info = psutil.Process().memory_info()
        return int(getattr(info, 'peak_wset', info.rss))
    except Exception:
        return None


def run_one(row: dict[str, Any], solver: Any | None = None) -> dict[str, Any]:
    built = build_variant(row)
    cell = built['cell']
    solver = solver or TimeoutSolver(smt.default_solver(), 30000)
    start = time.perf_counter()
    result = smt.verify_smt(cell.view, built['spec'], cell.motif, solver=solver, query_order=('safe', 'violation'))
    elapsed = time.perf_counter() - start
    witness_valid = None
    witness_errors: list[str] = []
    witness_objective = None
    if result.witness is not None:
        report = iwv.validate_witness(
            cell.view,
            built['spec'],
            cell.motif,
            result.witness.safe_execution,
            result.witness.violating_execution,
        )
        witness_valid = bool(report.valid)
        witness_errors = list(report.errors)
        witness_objective = list(report.objective) if report.valid and report.objective is not None else None
    return {
        'run_id': built['run_id'],
        'base_cell_id': built['base_cell_id'],
        'variant': built['variant'],
        'process_family': str(row['process_family']),
        'motif': str(row['motif']),
        'case_view': str(row['case_view']),
        'mechanism': str(row['mechanism']),
        'seed': int(row['seed']),
        'declared_bound': {
            'hidden_event_slack': int(row['hidden_event_slack']),
            'hidden_object_width': int(row['hidden_object_width']),
            'relation_free_edges': int(row['relation_free_edges']),
            'order_width': int(row['order_width']),
        },
        'underlying_execution_sha256': built['underlying_execution_sha256'],
        'view_sha256': built['view_sha256'],
        'spec_sha256': built['spec_sha256'],
        'hidden_event_candidate_count': built['hidden_event_candidate_count'],
        'hidden_event_filler_count': built['hidden_event_filler_count'],
        'hidden_event_candidate_ids': built['hidden_event_candidate_ids'],
        'binding_domain_max_choices': built['binding_domain_max_choices'],
        'relation_domain_choice_count': built['relation_domain_choice_count'],
        'eligible_order_pair_count': built['eligible_order_pair_count'],
        'selected_order_pair_count': built['selected_order_pair_count'],
        'selected_order_pairs': built['selected_order_pairs'],
        'decision': result.decision,
        'verdicts': ['violation' if value else 'safe' for value in result.verdicts],
        'complete': bool(result.complete),
        'solver_statuses': list(result.solver_statuses),
        'unknown_reason': result.unknown_reason,
        'witness_returned': result.witness is not None,
        'witness_valid': witness_valid,
        'witness_errors': witness_errors,
        'witness_objective': witness_objective,
        'runtime_seconds': elapsed,
        'peak_rss_bytes': _peak_rss_bytes(),
        'backend': result.backend or solver.name,
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
    weight = pos - lo
    return xs[lo] * (1.0 - weight) + xs[hi] * weight


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        grouped[str(row['base_cell_id'])][str(row['variant'])] = row
    transitions: dict[str, Any] = {}
    for variant in ('B+E', 'B+O', 'B+R', 'B+P'):
        counter = Counter()
        spec_noop = 0
        for variants in grouped.values():
            base = variants['B0']
            current = variants[variant]
            counter[f"{base['decision']}->{current['decision']}"] += 1
            spec_noop += int(base['spec_sha256'] == current['spec_sha256'])
        transitions[variant] = {
            'transition_counts': dict(sorted(counter.items())),
            'spec_noop_count': spec_noop,
            'sound_to_unsound': counter.get('sound->unsound', 0),
        }
    by_variant = {}
    for variant in ('B0', 'B+E', 'B+O', 'B+R', 'B+P'):
        selected = [row for row in rows if row['variant'] == variant]
        times = [float(row['runtime_seconds']) for row in selected]
        by_variant[variant] = {
            'n': len(selected),
            'decisions': dict(sorted(Counter(row['decision'] for row in selected).items())),
            'unknown_count': sum(row['decision'] == 'unknown' for row in selected),
            'invalid_witness_count': sum(row['witness_returned'] and row['witness_valid'] is not True for row in selected),
            'hidden_event_candidate_counts': dict(sorted(Counter(row['hidden_event_candidate_count'] for row in selected).items())),
            'runtime': {
                'median': statistics.median(times) if times else None,
                'q1': _quantile(times, 0.25),
                'q3': _quantile(times, 0.75),
                'p95': _quantile(times, 0.95),
                'max': max(times) if times else None,
            },
        }
    return {
        'row_count': len(rows),
        'base_case_count': len(grouped),
        'decision_counts': dict(sorted(Counter(row['decision'] for row in rows).items())),
        'by_variant': by_variant,
        'paired_transitions': transitions,
    }


def validate_integrity(rows: list[dict[str, Any]], qualification: dict[str, Any]) -> dict[str, Any]:
    matrix_ids = {str(row['run_id']) for row in load_matrix_rows()}
    run_ids = [str(row['run_id']) for row in rows]
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        grouped[str(row['base_cell_id'])][str(row['variant'])] = row
    errors: list[str] = []
    if len(rows) != 540 or len(run_ids) != len(set(run_ids)) or set(run_ids) != matrix_ids:
        errors.append('frozen_denominator_or_run_id_mismatch')
    if qualification['verdict'] != 'PASS':
        errors.append('structural_qualification_not_pass')
    for base_id, variants in grouped.items():
        if set(variants) != {'B0', 'B+E', 'B+O', 'B+R', 'B+P'}:
            errors.append(f'pairing:{base_id}')
            continue
        base = variants['B0']
        event = variants['B+E']
        if event['hidden_event_candidate_count'] != base['hidden_event_candidate_count'] + 1:
            errors.append(f'b_plus_e_capacity:{base_id}')
        if event['hidden_event_candidate_ids'][:2] != base['hidden_event_candidate_ids']:
            errors.append(f'b_plus_e_nested:{base_id}')
        if base['underlying_execution_sha256'] != event['underlying_execution_sha256'] or base['view_sha256'] != event['view_sha256']:
            errors.append(f'b_plus_e_pair_identity:{base_id}')
    for row in rows:
        if row['decision'] == 'unsound' and not (row['witness_returned'] and row['witness_valid'] is True):
            errors.append(f'invalid_unsound_witness:{row["run_id"]}')
    return {'valid': not errors, 'errors': sorted(set(errors)), 'row_count': len(rows), 'base_case_count': len(grouped)}


def run_official() -> dict[str, Any]:
    for path in (RESULT, SUMMARY, RUN_MANIFEST, QUALIFICATION, INTEGRITY_GATE):
        if path.exists():
            raise FileExistsError(f'refuse silent overwrite: {path}')
    OUT.mkdir(parents=True, exist_ok=True)
    qualification = structural_qualification()
    QUALIFICATION.write_text(json.dumps(qualification, indent=2) + '\n', encoding='utf-8')
    if qualification['verdict'] != 'PASS':
        raise RuntimeError(f'E7 V1.3 structural qualification failed: {qualification["failed_criteria"]}')

    manifest = {
        'run_id': 'E7_CORRECTIVE_V1_3_20260911',
        'official_corrective': True,
        'trigger': 'pre-G7 independent review found hidden_event_slack was not materialized in V1.2',
        'source_matrix_sha256': _sha(MATRIX),
        'amendment_sha256': _sha(AMENDMENT),
        'runner_sha256': _sha(Path(__file__).resolve()),
        'slack_helper_sha256': _sha(Path(slack.__file__).resolve()),
        'historical_e7_v1_2_preserved': True,
        'declared_run_count': 540,
        'resource_policy': {'threads': 1, 'timeout_per_query_seconds': 30, 'query_order': ['safe', 'violation']},
        'claim_boundary': qualification['claim_boundary'],
    }
    RUN_MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')

    solver = TimeoutSolver(smt.default_solver(), 30000)
    rows: list[dict[str, Any]] = []
    start = time.perf_counter()
    for index, row in enumerate(load_matrix_rows(), 1):
        rows.append(run_one(row, solver=solver))
        if index % 108 == 0:
            print(f'E7_V13_PROGRESS {index}/540', flush=True)
    wall = time.perf_counter() - start
    result = {'version': 'E7_RESULTS_V1_3', 'run_id': manifest['run_id'], 'rows': rows}
    RESULT.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    summary = summarize(rows)
    SUMMARY.write_text(json.dumps({'version': 'E7_SUMMARY_V1_3', 'summary': summary, 'wall_seconds': wall}, indent=2) + '\n', encoding='utf-8')
    integrity = validate_integrity(rows, qualification)
    gate = {
        'gate_id': 'E7_CORRECTIVE_INTEGRITY_V1_3',
        'verdict': 'PASS' if integrity['valid'] else 'FAIL_REPAIR',
        'failed_criteria': integrity['errors'],
        'integrity': integrity,
        'summary': summary,
        'result_sha256': _sha(RESULT),
        'summary_sha256': _sha(SUMMARY),
        'run_manifest_sha256': _sha(RUN_MANIFEST),
        'qualification_sha256': _sha(QUALIFICATION),
        'warnings': ['V1.3 neutral slack fillers repair candidate capacity while preserving mechanism isolation; they do not enumerate arbitrary hidden security-relevant activities.'],
    }
    INTEGRITY_GATE.write_text(json.dumps(gate, indent=2) + '\n', encoding='utf-8')
    print('VERDICT', gate['verdict'])
    print('FAILED', gate['failed_criteria'])
    print('SUMMARY', json.dumps(summary, sort_keys=True))
    print('WALL', wall)
    if not integrity['valid']:
        raise RuntimeError(integrity['errors'])
    return gate


if __name__ == '__main__':
    run_official()
