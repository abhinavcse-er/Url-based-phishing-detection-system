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

The default training sample is up to 50,000 URLs (balanced by class). Set ML_TRAIN_MAX_SAMPLES to change this. The dataset download URL and local cache path can be overridden with PHISHING_DATASET_URL and PHISHING_DATASET_PATH. ML_MAX_VALIDATION_FPR controls the validation false-positive ceiling; its default is 0.01 (1%).

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

Download the raw file, then run:

~~~bash
curl -L "https://raw.githubusercontent.com/aI-area/PhishDetecting/main/dataset/PhreshPhish/test_url_metadata.csv.gz" -o phreshphish_test_url_metadata.csv.gz
~~~

Verify the compressed file using the SHA-256 value published in the upstream [metadata.json](https://github.com/aI-area/PhishDetecting/blob/main/dataset/PhreshPhish/metadata.json), then run:

~~~bash
python evaluate_external.py \
  --dataset phreshphish_test_url_metadata.csv.gz \
  --url-column url \
  --label-column source_label \
  --phishing-label phish \
  --benign-label benign \
  --minimum-per-class 500 \
  --max-fpr 0.01 \
  --min-recall 0.80 \
  --output phreshphish_external_validation_report.json
~~~

This evaluation command never opens the submitted URLs. It checks and reports the subset of sites not present in the v4 development-site manifest. Review the dataset paper, license, dates, label provenance, overlap counts, and false-positive examples before treating the result as a release decision.

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

### Production inference release gate

Live ML inference requires **both** environment variables:

- ENABLE_ML_INFERENCE=true
- ML_EXTERNAL_VALIDATION_APPROVED=true

Leave both unset or false while external validation is pending. The second variable is an explicit operator approval and must only be enabled after reviewing the independent evaluation report, source and label quality, site overlap, error examples, collection dates, false-positive rate, false-negative rate, and recall. Setting only ENABLE_ML_INFERENCE=true will not enable ML.

The current training artifact deliberately records release_gate.status=pending_external_validation. Production scans continue to use explainable URL heuristics until an independent evaluation has been reviewed and approved.

## API

- GET /: service status and model version.
- GET /health: model status, selected candidate, held-out evaluation metrics, threshold diagnostics, and release-gate status.
- POST /api/scan: analyze one URL.
- POST /api/batch_scan: analyze up to 20 URLs.

A successful current model build reports ml_model_version: 4 and ml_inference_status: disabled_pending_external_validation until the two-variable release gate is approved. If the model artifact is missing or fails to load, heuristic scanning remains available.

## Local development and tests

~~~bash
pip install -r requirements.txt
python train_model.py
uvicorn server:app --reload --port 5500
~~~

Run the lightweight regression suite without downloading the training dataset:

~~~bash
python -m compileall -q server.py train_model.py url_features.py evaluate_external.py
python -m unittest discover -s tests -v
~~~

The GitHub Actions workflow named ML model v4 checks runs the same compile and unit-test checks on pushes and pull requests.

## Dataset and limitations

The trainer currently uses the public [Phishing URL Dataset by Raja Muhammad Awais](https://github.com/RajaMuhammadAwais/phishing-url-dataset), which describes 200,000 labelled URLs compiled from UCI PhiUSIIL and Phishing.Database sources. Dataset labels and collection conditions can be noisy or stale. The balanced sampling design is useful for controlled comparisons but does not represent the prevalence of phishing in ordinary browsing.

The model uses URL text only. It cannot determine whether a page is actually malicious, whether a legitimate site has been compromised, or whether a live threat-intelligence source has reported a URL. The live heuristic score is an advisory URL-pattern score, not a guarantee of safety. Do not enter credentials based only on a low-risk result.

## Research inspiration

The implementation was informed by ideas and evaluation practices from these public projects; their source code was not copied into this repository:

- [phishing-unseen-site-evaluation](https://github.com/SaraArif6198/phishing-unseen-site-evaluation) — registrable-site-disjoint evaluation and careful comparison of URL feature and character-text model families.
- [PhishDriftBench](https://github.com/rajeswari-30/phishdriftbench) — source-shift evaluation, URL-only feature modelling, false-positive/false-negative analysis, and selective release controls.
- [PhishDetecting / LitePhish](https://github.com/aI-area/PhishDetecting) — URL-intrinsic feature engineering and external-dataset evaluation practices.

These repositories are research references, not evidence that PhishGuard has achieved the performance reported by those projects.

## Author

Abhinav Kumar Mishra
