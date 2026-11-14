# PhishGuard — URL-based Phishing Detection

PhishGuard is an educational URL-analysis project with a static frontend and a FastAPI backend. The live scanner uses explainable URL heuristics. Its experimental machine-learning model is kept behind an external-validation release gate.

## Project structure

- index.html, styles.css, app.js: static frontend.
- api-config.js: public API base URL configuration.
- server.py: FastAPI API, explainable heuristics, and gated ML inference.
- url_features.py: deterministic URL-only structural feature extraction used by model v4.
- train_model.py: training, grouped data partitioning, model comparison, calibration, and validation-threshold selection.
- evaluate_external.py: evaluation against a separately sourced labelled CSV, including development-domain overlap checks.
- models/: generated model artifact and training metrics (created during deployment).
- requirements.txt: Python dependencies.

## Deploy the frontend on GitHub Pages or Netlify

Deploy the repository root as a static site. The public backend address is configured in api-config.js:

~~~js
window.PHISHING_API_BASE = "https://YOUR-BACKEND.onrender.com";
~~~

## Deploy the API on Render

1. Create a Web Service connected to this repository; use the repository root as Root Directory.
2. Runtime: Python.
3. Build command:
   ~~~bash
   pip install -r requirements.txt && python train_model.py
   ~~~
4. Start command:
   ~~~bash
   gunicorn server:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
   ~~~
5. Optional environment variable: ALLOWED_ORIGINS=https://abhinavcse-er.github.io.

The default `python train_model.py` entry point now delegates to the V5 multi-source trainer. It samples up to 10,000 benign and 10,000 phishing URLs from each of three pinned development sources (60,000 total before domain partitioning). Set `ML_V5_MAX_PER_SOURCE_CLASS` to change the per-source cap. The validation target is 1% global false-positive rate and 2% maximum false-positive rate within each source; no-positive fallback is used when no useful threshold satisfies both constraints. The archived V4 trainer is retained as `train_model_v4.py`.

## Model v4 design

The v4 pipeline compares three URL-only model candidates:

| Candidate | Representation |
|---|---|
| Character baseline | Character TF-IDF n-grams + Logistic Regression |
| Hybrid candidate | Character TF-IDF + word TF-IDF + 36 URL structure features + Logistic Regression |
| Structured baseline | URL structure features + HistGradientBoosting |

The structural features are extracted offline from the submitted URL string. They include URL/host/path lengths, subdomain and digit counts, query structure, URL entropy, punycode/IP/port indicators, suspicious-word counts, redirect-parameter indicators, and other lexical properties. The feature extractor does not resolve DNS, query WHOIS, visit websites, or fetch page content.

### Training and evaluation protocol

The trainer creates four registrable-domain-disjoint partitions using the offline Public Suffix List snapshot:

- Training set: fits candidate models.
- Calibration set: fits sigmoid (Platt) calibration.
- Validation set: selects the candidate and a decision threshold.
- Final test set: reports performance once; it is not used for model or threshold selection.

Model selection maximizes validation Matthews correlation coefficient (MCC) while requiring the validation false-positive rate to stay at or below ML_MAX_VALIDATION_FPR. The final test report includes false-positive rate, false-negative rate, precision, recall, F1, MCC, ROC-AUC, average precision, and a confusion matrix.

The source data is a balanced sample from the public [Phishing URL Dataset by Raja Muhammad Awais](https://github.com/RajaMuhammadAwais/phishing-url-dataset). It uses source labels 1=legitimate, 0=phishing; the trainer maps them to 0=legitimate, 1=phishing.

**Important:** a domain-held-out split from the same source is not independent external validation. Calibration on a balanced sample does not make a score a real-world probability. No headline accuracy number should be treated as a production guarantee.

## V5 multi-source design

The current V5 trainer uses three pinned development corpora from [aI-area/PhishDetecting](https://github.com/aI-area/PhishDetecting), all with `url` and `phishing` columns (`0=benign`, `1=phishing`):

| Source | Published rows | Development role |
|---|---:|---|
| PhishFusion | 105,752 | Training / calibration / validation / grouped test |
| Ebbu2017 | 73,575 | Training / calibration / validation / grouped test |
| PhishStorm | 95,911 | Training / calibration / validation / grouped test |

The corpora are pinned to upstream commit `aedc3dd65fd92a187f5c174cd8a93a89588a98f6` and their Git blob hashes are checked before training. V5 removes invalid URLs, normalized URL duplicates, and conflicting normalized URL labels. It samples the same number of benign and phishing URLs from each source so a larger corpus cannot dominate the fit.

V5 compares the same three URL-only model families as V4. Its nested splits use a local Public Suffix List snapshot including private suffixes, and are stratified by source and label. Training, calibration, validation, and final test domains do not overlap. Candidate thresholds must meet both the overall validation FPR ceiling and a per-source FPR ceiling; a zero-recall threshold is not considered useful. The final grouped test is report-only and is never used for selection.

**External holdouts are not training data:** PhishTank and PhreshPhish are held aside for independent evaluation. The V5 workflow evaluates both after excluding normalized URL overlap, private-suffix-aware registered-domain overlap with all three development corpora, and every development domain recorded in the model artifact.

Run V5 locally with:

~~~bash
python train_model_v5.py
~~~

Or use the default entry point:

~~~bash
python train_model.py
~~~

Run the reproducible multi-source workflow through [V5 GitHub Actions](https://github.com/abhinavcse-er/Url-based-phishing-detection-system/actions/workflows/v5-multisource-validation.yml). It produces separate PhreshPhish and PhishTank JSON reports. A failed external gate is a valid evaluation outcome; it must not be bypassed by tuning on either external cohort.

## Independent external validation

Before enabling model inference, obtain a separately sourced and independently labelled CSV with both benign and phishing examples. Keep source provenance, collection dates, label definitions, and redistribution terms.

### Recommended public GitHub evaluation CSV: PhreshPhish

A pinned URL-only export is available in the public GitHub repository [aI-area/PhishDetecting](https://github.com/aI-area/PhishDetecting):

- [Download the compressed CSV from GitHub](https://github.com/aI-area/PhishDetecting/blob/main/dataset/PhreshPhish/test_url_metadata.csv.gz)
- [Direct raw download](https://raw.githubusercontent.com/aI-area/PhishDetecting/main/dataset/PhreshPhish/test_url_metadata.csv.gz)
- [Dataset README, source counts, and label meaning](https://github.com/aI-area/PhishDetecting/blob/main/dataset/PhreshPhish/README.md)
- [Pinned metadata and SHA-256 checksums](https://github.com/aI-area/PhishDetecting/blob/main/dataset/PhreshPhish/metadata.json)

The documented released test split contains 91,260 benign and 76,800 phishing URLs (168,060 total). Its eligible URL-disjoint cohort has 166,227 rows, and its stricter source-domain-disjoint subset has 141,623 rows (67,421 benign and 74,202 phishing). The exported file uses the `url` and `source_label` columns, with `benign` and `phish` labels; it is gzip-compressed CSV, which pandas can read directly by the `.csv.gz` extension. Upstream terms are CC BY 4.0 for anti-phishing research; retain attribution to the PhreshPhish authors.

The source project documents this as separate from its PhishTank and PhishFusion cohorts and says its PhreshPhish export excludes exact/normalized PhishFusion URL overlap; its stricter subset also excludes PhishFusion registered-domain overlap. The v4 evaluator additionally checks overlap against the domains actually used by the PhishGuard v4 development sample. Do not infer independence from a filename alone: retain the generated overlap report and inspect the result counts.

Download the two pinned source files, then verify their checksums:

~~~bash
curl -L "https://raw.githubusercontent.com/aI-area/PhishDetecting/aedc3dd65fd92a187f5c174cd8a93a89588a98f6/dataset/PhreshPhish/test_url_metadata.csv.gz" -o phreshphish_test_url_metadata.csv.gz
curl -L "https://raw.githubusercontent.com/aI-area/PhishDetecting/aedc3dd65fd92a187f5c174cd8a93a89588a98f6/dataset/PhishFusion.csv" -o PhishFusion.csv
echo "ecc1efc3a8207f91b3953546011da5f35bc17907e7ae96ada6beb6635efa6dd7  phreshphish_test_url_metadata.csv.gz" | sha256sum --check --strict
test "$(git hash-object PhishFusion.csv)" = "b698ebad3a81bf81c3868f60b1d1fefb4f1e2361"
~~~

Run the external evaluation:

~~~bash
python evaluate_external.py \
  --dataset phreshphish_test_url_metadata.csv.gz \
  --url-column url \
  --label-column source_label \
  --phishing-label phish \
  --benign-label benign \
  --source-training-csv PhishFusion.csv \
  --minimum-per-class 500 \
  --max-fpr 0.01 \
  --min-recall 0.80 \
  --output phreshphish_external_validation_report.json
~~~

The evaluator never opens submitted URLs. It verifies the uploaded row hashes when present, removes invalid URLs, conflicting normalized labels, later normalized duplicates, and source-corpus exact/normalized URL overlaps. It reports the URL-disjoint cohort, then a stricter cohort without PhishFusion registered-domain overlap (using a Public Suffix List snapshot with private suffixes), and finally excludes any PhishGuard v4 development-site overlap. The original URL string is still passed to the model. Review cohort counts, source provenance, collection dates, labels, and false-positive examples before treating the report as a release decision.

Example for a CSV with URL and Label columns where 0=phishing and 1=legitimate:

~~~bash
python evaluate_external.py \
  --dataset independent_urls.csv \
  --url-column URL \
  --label-column Label \
  --phishing-label 0 \
  --benign-label 1 \
  --minimum-per-class 500 \
  --max-fpr 0.01 \
  --min-recall 0.80 \
  --output external_validation_report.json
~~~

For other datasets, set the column names and positive/negative label values explicitly. The evaluator never visits URLs. It reports results for the full external sample and for registrable sites that do not overlap any development partition. It also writes a dataset SHA-256 digest. It does not automatically edit the model artifact or enable inference.

## Latest independent external evaluation — 14 November 2026

The V4 candidate was trained on a balanced 50,000-URL sample from the documented development source. It selected the hybrid text-plus-URL-feature model. The untouched development-source holdout scored 99.6% accuracy, but this is not independent validation.

The pinned PhreshPhish external test completed with a **failed release gate**. On the strict cohort (PhishFusion URL and registered-domain overlaps removed, then all V4 development domains excluded), 108,928 URLs remained:

| Metric | Result |
|---|---:|
| Accuracy | 40.76% |
| False-positive rate | **93.06%** |
| False-negative rate | 10.36% |
| Phishing recall | 89.64% |
| ROC-AUC | 0.506 |
| MCC | -0.061 |

The permitted false-positive rate was 1%. The observed rate is far above that limit, and the ROC-AUC is close to random ranking. The candidate therefore **must not be enabled**. Its strong internal holdout score did not transfer to this independent source.

- [Full machine-readable external evaluation report](./phreshphish-external-validation-report.json)
- [Original reproducible GitHub Actions run](https://github.com/abhinavcse-er/Url-based-phishing-detection-system/actions/runs/43577785231)

Do not tune a decision threshold on this completed PhreshPhish test cohort and then report the same cohort as independent validation. A revised candidate needs development on training data and a fresh, untouched external evaluation. Live scans continue to use explainable URL heuristics only.

### Production inference release gate

Live ML inference requires all three approval conditions:

- ENABLE_ML_INFERENCE=true
- ML_EXTERNAL_VALIDATION_APPROVED=true
- The loaded model artifact must contain release_gate.status=approved and release_gate.passed=true.

Leave the switches unset or false while external validation is pending. The second environment variable is an explicit operator approval and must only be enabled after reviewing the independent evaluation report, source and label quality, site overlap, error examples, collection dates, false-positive rate, false-negative rate, and recall. The artifact-level approval is a separate safeguard: even if both environment variables are accidentally set, an artifact marked pending_external_validation cannot run inference.

The trainer always writes release_gate.status=pending_external_validation and release_gate.passed=false. A fresh training build therefore re-locks inference; any subsequent approval must be deliberate and tied to that exact model artifact and evaluation report. Production scans continue to use explainable URL heuristics until all three conditions are met.

## API

- GET /: service status and model version.
- GET /health: model status, selected candidate, held-out evaluation metrics, threshold diagnostics, and release-gate status.
- POST /api/scan: analyze one URL.
- POST /api/batch_scan: analyze up to 20 URLs.

A successful current model build can report model version 4 (archived) or 5 (multi-source). V5 training always writes a pending release gate, so `ml_inference_status` remains `disabled_pending_external_validation` until independent metrics are reviewed, the artifact is explicitly approved, and both runtime switches are deliberately set. If the model artifact is missing or fails to load, heuristic scanning remains available.

## Local development and tests

~~~bash
pip install -r requirements.txt
python train_model.py
uvicorn server:app --reload --port 5500
~~~

Run the lightweight regression suite without downloading the training dataset:

~~~bash
python -m compileall -q server.py train_model.py train_model_v4.py train_model_v5.py url_features.py evaluate_external.py evaluate_external_v5.py
python -m unittest discover -s tests -v
~~~

The GitHub Actions workflow named ML model V5 multi-source checks runs the compile and regression suite. The separate V5 external workflow trains on the three development corpora and evaluates only on the PhishTank and PhreshPhish holdouts.

## Dataset and limitations

V5 training uses the pinned PhishFusion, Ebbu2017, and PhishStorm development corpora described above. PhishTank and PhreshPhish are not used for V5 fitting, calibration, feature selection, or threshold selection. Source labels and collection conditions can be noisy or stale, and the balanced sampling design does not represent phishing prevalence in ordinary browsing.

The model uses URL text only. It cannot determine whether a page is actually malicious, whether a legitimate site has been compromised, or whether a live threat-intelligence source has reported a URL. The live heuristic score is an advisory URL-pattern score, not a guarantee of safety. Do not enter credentials based only on a low-risk result.

## Research inspiration

The implementation was informed by ideas and evaluation practices from these public projects; their source code was not copied into this repository:

- [phishing-unseen-site-evaluation](https://github.com/SaraArif6198/phishing-unseen-site-evaluation) — registrable-site-disjoint evaluation and careful comparison of URL feature and character-text model families.
- [PhishDriftBench](https://github.com/rajeswari-30/phishdriftbench) — source-shift evaluation, URL-only feature modelling, false-positive/false-negative analysis, and selective release controls.
- [PhishDetecting / LitePhish](https://github.com/aI-area/PhishDetecting) — URL-intrinsic feature engineering and external-dataset evaluation practices.

These repositories are research references, not evidence that PhishGuard has achieved the performance reported by those projects.

## Author

Abhinav Kumar Mishra
