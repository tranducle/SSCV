# Reproducibility

## Environment

Python 3.12.x is recommended. Create an isolated environment and install the pinned runtime dependencies:

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m pip install -e .
```

Run the included regression suite:

```bash
python -m unittest discover -s tests -p "test_*.py" -q
```

Expected result for this release: 58 tests pass.

## Prepare public data

```bash
python scripts/download_p2p.py
python scripts/normalize_p2p.py
python scripts/download_order_management.py
python scripts/normalize_order_management.py
```

The downloaders verify pinned source hashes. Raw and normalized data remain under `data/` and are excluded from Git.

## Study families

The reusable implementation is in `src/sscv/`. Public experiment entry points are in `experiments/`:

- `run_synthetic.py`: controlled paired-view synthetic evaluation.
- `run_restoration.py`: context-restoration study.
- `run_sensitivity.py`: bounded sensitivity study.
- `run_witness_study.py`: witness-validity and witness-objective study.
- `run_scaling.py`: bounded scaling study.
- `run_p2p.py`: P2P source-conditioned evaluation and schema stress test.
- `run_order_management.py`: Order Management source-conditioned evaluation and schema stress test.

Frozen study definitions are stored in `configs/` using release-facing filenames. Internal provenance/version fields inside the JSON payloads are preserved because they identify the frozen scientific design; they are not filesystem dependencies.

## Replication criteria

Use `docs/reference_outcomes.md` to compare reruns with the frozen reference outcomes. Exact runtime equality is not required because runtime depends on the host. The primary checks are denominators, decisions, paired transitions, witness validity, and declared integrity conditions.

## Output policy

Generated outputs belong under `results/` and are excluded from Git. Do not overwrite the frozen configuration files in `configs/` after inspecting outcomes.
