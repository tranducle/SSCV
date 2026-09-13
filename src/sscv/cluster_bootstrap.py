from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import random
import statistics
from typing import Any

from . import p2p_runner as public
REPO_ROOT = Path(__file__).resolve().parents[2]
E8_RESULT = REPO_ROOT / 'results' / 'p2p' / 'evaluation_results.json'
SOURCE_ROOT = REPO_ROOT / 'configs' / 'p2p'
E8_SAMPLE = SOURCE_ROOT / 'evaluation_sample.json'
FREEZE_HASHES = SOURCE_ROOT / 'sample_checksums.json'
OUT = REPO_ROOT / 'results' / 'p2p' / 'cluster_bootstrap.json'

METRICS = (
    'delta_sound',
    'delta_unsound',
    'delta_unknown',
    'delta_b1_false_assurance',
    'delta_b2_abstention',
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8-sig'))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _quantile(values: list[float], q: float) -> float:
    xs = sorted(float(x) for x in values)
    if not xs:
        raise ValueError('quantile requires at least one value')
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * float(q)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return xs[lo]
    weight = pos - lo
    return xs[lo] * (1.0 - weight) + xs[hi] * weight


def _neighborhood_tokens(index: Any, anchor: dict[str, Any]) -> frozenset[str]:
    audit = public.build_r_obs_audit(index, anchor, 'CV-D')
    event_tokens = {f'e:{event.event_id}' for event in audit.source_execution.events}
    object_tokens = {f'o:{obj.object_id}' for obj in audit.source_execution.objects}
    return frozenset(event_tokens | object_tokens)


def build_overlap_clusters() -> list[tuple[str, ...]]:
    index = public.load_index()
    anchors = public.load_manifest('P2P_M2_E8_SAMPLE_V1_2.json')['anchors']
    ordered = sorted(anchors, key=lambda row: str(row['stable_anchor_id']))
    parent = {str(row['stable_anchor_id']): str(row['stable_anchor_id']) for row in ordered}
    rank = {key: 0 for key in parent}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(left: str, right: str) -> None:
        a = find(left)
        b = find(right)
        if a == b:
            return
        if rank[a] < rank[b]:
            a, b = b, a
        parent[b] = a
        if rank[a] == rank[b]:
            rank[a] += 1

    first_owner: dict[str, str] = {}
    for row in ordered:
        anchor_id = str(row['stable_anchor_id'])
        for token in sorted(_neighborhood_tokens(index, row)):
            previous = first_owner.get(token)
            if previous is None:
                first_owner[token] = anchor_id
            else:
                union(anchor_id, previous)

    grouped: dict[str, list[str]] = {}
    for anchor_id in sorted(parent):
        grouped.setdefault(find(anchor_id), []).append(anchor_id)
    clusters = [tuple(sorted(members)) for members in grouped.values()]
    clusters.sort(key=lambda members: members[0])
    return clusters


def paired_anchor_metrics() -> dict[str, dict[str, float]]:
    rows = _load(E8_RESULT)['rows']
    paired: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        paired.setdefault(str(row['stable_anchor_id']), {})[str(row['case_view'])] = row

    result: dict[str, dict[str, float]] = {}
    for anchor_id, views in sorted(paired.items()):
        if set(views) != {'CV-D', 'CV-R1'}:
            raise ValueError(f'incomplete paired views for {anchor_id}')
        direct = views['CV-D']
        relation = views['CV-R1']

        def indicator(row: dict[str, Any], decision: str) -> float:
            return 1.0 if row['sscv_decision'] == decision else 0.0

        def false_assurance(row: dict[str, Any]) -> float:
            return 1.0 if (
                row['b1'] == 'safe'
                and row['sscv_decision'] == 'unsound'
                and row['witness_returned']
                and row['witness_valid'] is True
            ) else 0.0

        result[anchor_id] = {
            'delta_sound': indicator(relation, 'sound') - indicator(direct, 'sound'),
            'delta_unsound': indicator(relation, 'unsound') - indicator(direct, 'unsound'),
            'delta_unknown': indicator(relation, 'unknown') - indicator(direct, 'unknown'),
            'delta_b1_false_assurance': false_assurance(relation) - false_assurance(direct),
            'delta_b2_abstention': (1.0 if relation['b2'] == 'unknown' else 0.0) - (1.0 if direct['b2'] == 'unknown' else 0.0),
            'runtime_delta_seconds': float(relation['runtime_seconds']) - float(direct['runtime_seconds']),
        }
    return result


def point_estimates(metrics: dict[str, dict[str, float]]) -> dict[str, float]:
    if not metrics:
        raise ValueError('empty metric population')
    return {
        name: statistics.fmean(row[name] for row in metrics.values())
        for name in METRICS
    }


def run_bootstrap(*, replicates: int = 2000, seed: int = 20260911) -> dict[str, Any]:
    if int(replicates) != 2000:
        raise ValueError('the frozen analysis plan requires exactly 2000 replicates')
    if int(seed) != 20260911:
        raise ValueError('the frozen analysis plan requires seed 20260911')

    clusters = build_overlap_clusters()
    metrics = paired_anchor_metrics()
    covered = {anchor_id for cluster in clusters for anchor_id in cluster}
    if covered != set(metrics):
        raise ValueError('cluster population does not exactly match paired E8 anchors')

    rng = random.Random(seed)
    samples = {name: [] for name in METRICS}
    for _ in range(replicates):
        sampled_clusters = [clusters[rng.randrange(len(clusters))] for _ in range(len(clusters))]
        sampled_ids = [anchor_id for cluster in sampled_clusters for anchor_id in cluster]
        if not sampled_ids:
            raise RuntimeError('empty bootstrap replicate')
        for name in METRICS:
            samples[name].append(statistics.fmean(metrics[anchor_id][name] for anchor_id in sampled_ids))

    point = point_estimates(metrics)
    intervals = {
        name: [_quantile(values, 0.025), _quantile(values, 0.975)]
        for name, values in samples.items()
    }
    runtime_deltas = [row['runtime_delta_seconds'] for row in metrics.values()]
    return {
        'analysis_id': 'P2P_M2_E8_CLUSTER_BOOTSTRAP_V1_1',
        'replicates': replicates,
        'seed': seed,
        'anchor_count': len(metrics),
        'cluster_count': len(clusters),
        'cluster_size_distribution': {
            str(size): sum(len(cluster) == size for cluster in clusters)
            for size in sorted({len(cluster) for cluster in clusters})
        },
        'max_cluster_size': max(len(cluster) for cluster in clusters),
        'point_estimates': point,
        'percentile_95_ci': intervals,
        'paired_runtime_delta_seconds': {
            'median': statistics.median(runtime_deltas),
            'mean': statistics.fmean(runtime_deltas),
            'min': min(runtime_deltas),
            'max': max(runtime_deltas),
        },
    }


def build_artifact() -> dict[str, Any]:
    freeze = _load(FREEZE_HASHES)
    sample = _load(E8_SAMPLE)
    expected_canonical = freeze['canonical_json_sha256']['e8']
    actual_canonical = _canonical_sha256(sample)
    if actual_canonical != expected_canonical:
        raise RuntimeError('frozen P2P E8 sample canonical hash mismatch')
    report = run_bootstrap(replicates=2000, seed=20260911)
    report.update({
        'date': '2026-09-11',
        'status': 'POST_OUTCOME_EXECUTION_OF_PRE_OUTCOME_FROZEN_ANALYSIS_PLAN',
        'source_e8_result_sha256': _sha256(E8_RESULT),
        'source_e8_sample_canonical_sha256': actual_canonical,
        'eligibility_rule': 'compute only when anchor_count >= 50 and overlap_cluster_count >= 30',
        'eligible': report['anchor_count'] >= 50 and report['cluster_count'] >= 30,
        'resampling_unit': 'connected components of the frozen anchor overlap graph; clusters sampled with replacement',
        'interval_method': '2.5th and 97.5th percentile of exactly 2000 cluster-bootstrap replicates',
        'claim_boundary': 'Source-conditioned paired uncertainty for the frozen simulated P2P source only. It is not a prevalence or deployment-general interval.',
    })
    if not report['eligible']:
        raise RuntimeError('P2P population unexpectedly fails frozen bootstrap eligibility')
    return report


def main() -> int:
    if OUT.exists():
        raise FileExistsError(f'refuse overwrite: {OUT}')
    report = build_artifact()
    OUT.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
