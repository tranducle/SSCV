# Security-Sound Case Views (SSCV)

Reproducibility code for **Assessing Case-Centric Views for Security Analysis in Enterprise Information Systems**.

SSCV checks whether all admissible object-centric completions consistent with a visible case view yield the same declared security verdict. The repository includes the case-view construction logic, enumerative and SMT verification backends, independent witness validation, controlled synthetic studies, and replay code for two simulated OCEL 2.0 sources.

## Repository structure

- `src/sscv/`: reusable SSCV implementation and study logic.
- `experiments/`: command-line entry points for the reported study families.
- `configs/`: frozen release-facing manifests, mappings, and sampling specifications.
- `tests/`: deterministic semantic and configuration regression tests.
- `scripts/`: public-data download and normalization utilities.
- `docs/`: replication notes and reference outcomes.
- `DATA.md`: public data sources and integrity information.
- `REPRODUCIBILITY.md`: environment setup and replay workflow.

## Quick start

Python 3.12 is recommended.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install -r requirements.txt
python -m pip install -e .
python -m unittest discover -s tests -p "test_*.py" -q
```

The release regression suite contains 58 deterministic tests.

## Public data

The public-source studies use two simulated OCEL 2.0 datasets:

- Procure-to-Payment (P2P), Zenodo record 8412920, DOI `10.5281/zenodo.8412920`.
- Order Management, Zenodo record 8428112, DOI `10.5281/zenodo.8428112`.

Raw data are not redistributed. Downloaders verify the pinned file sizes and cryptographic hashes before use. See `DATA.md`.

## Reproducibility scope

The repository preserves the bounded completion semantics, frozen samples, mappings, and deterministic experiment specifications used for the reported study. Runtime measurements are hardware-dependent; semantic decisions, frozen denominators, transition counts, and witness-validity checks are the primary replication targets.

Generated result files and publication figures are not stored in Git. They are regenerated locally under `results/` when the experiment entry points are run.

## Citation

A formal publication citation will be added after publication. Until then, cite the manuscript title and the tagged repository release used for replication.
