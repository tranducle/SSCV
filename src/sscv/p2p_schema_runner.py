from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import time
from typing import Any

from . import p2p_runner as pub
from . import p2p_schema_stress as rs
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_E8_RESULT = REPO_ROOT / 'results' / 'p2p' / 'evaluation_results.json'


def load_e8_rows(path: str | Path = DEFAULT_E8_RESULT) -> dict[tuple[str, str], dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding='utf-8'))
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in payload['rows']:
        key = (str(row['stable_anchor_id']), str(row['case_view']))
        if key in rows:
            raise ValueError(f'duplicate E8 row: {key}')
        rows[key] = row
    return rows


def _state_dict(state: rs.SchemaState | None) -> dict[str, Any] | None:
    if state is None:
        return None
    return {
        'present': state.present,
        'binding_kind': state.binding_kind,
        'relation_present': state.relation_present,
        'before_anchor': state.before_anchor,
    }


def run_e9_anchor_view(
    index: pub.P2PIndex,
    anchor: dict[str, Any],
    constructor_id: str,
    e8_rows: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    stable_anchor_id = str(anchor['stable_anchor_id'])
    base_key = (stable_anchor_id, constructor_id)
    if base_key not in e8_rows:
        raise ValueError(f'missing paired E8 row for {base_key}')
    base = e8_rows[base_key]
    audit = pub.build_r_obs_audit(index, anchor, constructor_id)

    t0 = time.perf_counter()
    explicit = rs.explicit_safe_extension(audit)
    scalable = rs.smt_safe_extension(audit)
    elapsed = time.perf_counter() - t0
    crosscheck = (
        scalable.get('exists') is not None
        and bool(explicit['exists']) == bool(scalable['exists'])
    )

    if not crosscheck:
        schema_decision = 'unknown'
        schema_verdicts = list(base.get('sscv_verdicts', ()))
        unknown_reason = 'schema_extension_crosscheck_mismatch'
    else:
        schema_decision, schema_verdicts = rs.combine_r_obs_verdicts(
            str(base['sscv_decision']),
            list(base.get('sscv_verdicts', ())),
            safe_extension_exists=bool(explicit['exists']),
        )
        unknown_reason = (
            'r_obs_unknown_preserved'
            if schema_decision == 'unknown'
            else None
        )

    witness_origin = None
    witness_valid = None
    witness_objective = None
    witness_errors: list[str] = []
    if schema_decision == 'unsound':
        if base['sscv_decision'] == 'unsound':
            witness_origin = 'R_OBS_E8'
            witness_valid = base.get('witness_valid') is True
            witness_objective = base.get('witness_objective')
            if not witness_valid:
                witness_errors.append('paired_e8_witness_not_valid')
        elif (
            base['sscv_decision'] == 'sound'
            and list(base.get('sscv_verdicts', ())) == ['violation']
            and explicit['exists']
            and explicit['state'] is not None
        ):
            witness_origin = 'R_SCHEMA_EXTENSION'
            report = rs.validate_schema_transition_witness(
                audit, explicit['state']
            )
            witness_valid = bool(report['valid'])
            witness_objective = report['objective']
            witness_errors = list(report['errors'])
        else:
            witness_origin = 'UNRESOLVED'
            witness_valid = False
            witness_errors.append('unsound_without_certified_opposite_witness')

    return {
        'stable_anchor_id': stable_anchor_id,
        'anchor_event_id': str(anchor['event_id']),
        'quotation_id': str(anchor['quotation_id']),
        'case_view': constructor_id,
        'r_obs_decision': str(base['sscv_decision']),
        'r_obs_verdicts': list(base.get('sscv_verdicts', ())),
        'r_schema_decision': schema_decision,
        'r_schema_verdicts': schema_verdicts,
        'transition': f"{base['sscv_decision']}->{schema_decision}",
        'schema_safe_extension_exists': bool(explicit['exists']) if crosscheck else None,
        'schema_safe_extension_state': _state_dict(explicit.get('state')),
        'explicit_extension_exists': bool(explicit['exists']),
        'smt_extension_exists': scalable.get('exists'),
        'smt_extension_status': scalable.get('status'),
        'extension_crosscheck_match': crosscheck,
        'runtime_seconds': elapsed,
        'witness_origin': witness_origin,
        'witness_valid': witness_valid,
        'witness_objective': witness_objective,
        'witness_errors': witness_errors,
        'witness_minimal_claimed': False,
        'base_b0': base.get('b0'),
        'base_b1': base.get('b1'),
        'base_b2': base.get('b2'),
    }


def run_e9_manifest(
    index: pub.P2PIndex,
    manifest: dict[str, Any],
    e8_rows: dict[tuple[str, str], dict[str, Any]],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    anchors = list(manifest.get('anchors', ()))
    if limit is not None:
        anchors = anchors[:limit]
    rows: list[dict[str, Any]] = []
    for anchor in anchors:
        for constructor_id in ('CV-D', 'CV-R1'):
            rows.append(
                run_e9_anchor_view(index, anchor, constructor_id, e8_rows)
            )
    return rows


def _counts(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        value = str(row[key])
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def summarize_e9_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    anchors = {str(row['stable_anchor_id']) for row in rows}
    by_view: dict[str, Any] = {}
    for view_id in ('CV-D', 'CV-R1'):
        current = [row for row in rows if row['case_view'] == view_id]
        by_view[view_id] = {
            'row_count': len(current),
            'r_obs_decision_counts': _counts(current, 'r_obs_decision'),
            'r_schema_decision_counts': _counts(current, 'r_schema_decision'),
            'transition_counts': _counts(current, 'transition'),
            'schema_safe_extension_count': sum(
                row['schema_safe_extension_exists'] is True for row in current
            ),
            'new_unsound_count': sum(
                row['r_obs_decision'] == 'sound'
                and row['r_schema_decision'] == 'unsound'
                for row in current
            ),
            'witness_count': sum(row['witness_valid'] is not None for row in current),
            'invalid_witness_count': sum(row['witness_valid'] is False for row in current),
            'extension_crosscheck_failures': sum(
                not row['extension_crosscheck_match'] for row in current
            ),
            'runtime_seconds_total': sum(float(row['runtime_seconds']) for row in current),
        }
    return {
        'row_count': len(rows),
        'anchor_count': len(anchors),
        'case_view_count': len({row['case_view'] for row in rows}),
        'r_obs_decision_counts': _counts(rows, 'r_obs_decision'),
        'r_schema_decision_counts': _counts(rows, 'r_schema_decision'),
        'transition_counts': _counts(rows, 'transition'),
        'schema_safe_extension_count': sum(
            row['schema_safe_extension_exists'] is True for row in rows
        ),
        'new_unsound_count': sum(
            row['r_obs_decision'] == 'sound'
            and row['r_schema_decision'] == 'unsound'
            for row in rows
        ),
        'witness_count': sum(row['witness_valid'] is not None for row in rows),
        'invalid_witness_count': sum(row['witness_valid'] is False for row in rows),
        'extension_crosscheck_failures': sum(
            not row['extension_crosscheck_match'] for row in rows
        ),
        'by_case_view': by_view,
    }
