# Data

The SSCV public-source evaluation uses two simulated OCEL 2.0 business-process datasets. No proprietary enterprise logs or real insider-incident records are required.

## Procure-to-Payment

- Zenodo record: `8412920`
- DOI: `10.5281/zenodo.8412920`
- Expected files: `ocel2-p2p.json`, `ocel2-p2p.sqlite`
- Downloader: `scripts/download_p2p.py`
- Local raw-data directory: `data/raw/p2p/`
- Normalizer: `scripts/normalize_p2p.py`
- Normalized directory: `data/normalized/p2p/`

The downloader contains the pinned byte counts, MD5 values, and SHA-256 values used to verify the source files.

## Order Management

- Zenodo record: `8428112`
- DOI: `10.5281/zenodo.8428112`
- Expected file: `order-management.sqlite`
- Downloader: `scripts/download_order_management.py`
- Local raw-data directory: `data/raw/order_management/`
- Normalizer: `scripts/normalize_order_management.py`
- Normalized directory: `data/normalized/order_management/`

The downloader verifies the pinned file size, MD5, and SHA-256 values before the source is used.

## Interpretation boundary

Both sources are simulated business-process event data. They are not real insider-threat incidents, malicious-employee ground truth, or population-representative enterprise samples.

Raw and normalized dataset files are excluded from Git by `.gitignore`.
