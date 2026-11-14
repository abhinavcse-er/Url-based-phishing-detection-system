# PhishGuard — URL-based Phishing Detection

A responsive static frontend and FastAPI backend that combines explainable URL heuristics with a trained machine-learning URL classifier.

## Project structure

- `index.html`, `styles.css`, `app.js`: Netlify static frontend.
- `api-config.js`: public API base URL configuration.
- `server.py`: FastAPI API, heuristic checks, and ML inference.
- `train_model.py`: reproducible model training, probability calibration, and registered-domain-held-out evaluation.
- `models/`: generated model artifact and evaluation metrics (created during deployment).
- `requirements.txt`: Python dependencies.

## Deploy the frontend on Netlify

Deploy the repository root as a static site. Set `window.PHISHING_API_BASE` in `api-config.js` to your Render API URL:
```js
window.PHISHING_API_BASE = "https://YOUR-BACKEND.onrender.com";
```

## Deploy the API on Render

1. Create a **Web Service** connected to this repository; use the repository root as Root Directory.
2. Runtime: Python.
3. **Build command:**
   ```bash
   pip install -r requirements.txt && python train_model.py
   ```
   This downloads the labelled URL corpus, trains a character n-gram TF-IDF + Logistic Regression model, calibrates it on a separate set of hostnames, and reports metrics on a final hostname-held-out test set.
4. **Start command:**
   ```bash
   gunicorn server:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
   ```
5. Optional environment variable: `ALLOWED_ORIGINS=https://detectphishing.netlify.app`.
6. Deploy, then open `https://YOUR-BACKEND.onrender.com/health`. A successful current model deployment reports `"ml_model": "loaded"` and `"ml_evaluation_status": "available"`.

The default training sample is 50,000 URLs (up to 25,000 per class). Set `ML_TRAIN_MAX_SAMPLES` to change this. The dataset download URL can be overridden with `PHISHING_DATASET_URL`.

## Model evaluation and release gate

The training pipeline creates three registrable-domain-disjoint partitions using the bundled Public Suffix List snapshot:

- Training set: fits the URL classifier.
- Calibration set: applies sigmoid (Platt) calibration to the trained classifier.
- Test set: remains untouched until final evaluation.

URLs sharing the same registrable domain (eTLD+1) are kept in the same partition. This is stricter than separating only exact hostnames, because subdomains of the same site cannot be split across training and test.

**ML inference is disabled by default.** A browser-level external test found that the model labelled Microsoft, GitHub, Amazon, and example.org as phishing-like. Until the false-positive behaviour is resolved with independent verified datasets, the model is retained only for training/evaluation diagnostics and does not influence live scan verdicts. Do not set `ENABLE_ML_INFERENCE=true` for production until the release gate is passed.

The live scanner uses explainable URL heuristics. These checks are indicators, not definitive safety verdicts. In particular, HTTPS alone does not mean a site is safe, and phishing can occur on legitimate hosting platforms.

The build logs and `/health` endpoint expose held-out test metrics and calibration diagnostics. These are benchmark measurements only. Because the public source dataset is constructed from a balanced sample of legitimate URLs and active phishing URLs, neither calibration nor test accuracy establishes real-world phishing probabilities or accuracy.

**Release gate before re-enabling ML:** test against a separately sourced, independently labelled set with verified benign and active phishing URLs; report false-positive rate and false-negative rate; ensure legitimate popular domains and shared-hosting platforms are not systematically flagged; document dataset dates and overlap checks; and keep a final time-based test set untouched until model selection is complete.

## Local development

```bash
pip install -r requirements.txt
python train_model.py
uvicorn server:app --reload --port 5500
```

## Dataset and limitations

The classifier is trained on the public [Phishing URL Dataset by Raja Muhammad Awais](https://github.com/RajaMuhammadAwais/phishing-url-dataset), which describes 200,000 labelled URLs (label 1 = legitimate, label 0 = phishing) compiled from UCI PhiUSIIL and Phishing.Database sources. The training script reverses the source labels into the API convention (0 = legitimate, 1 = phishing).

The model uses URL text only; it does not open submitted websites. ML inference is currently disabled because the external false-positive test failed. The live heuristic score is an advisory URL-pattern score, not a guarantee of safety. Dataset bias, stale labels, unseen domains, and changing attacker behavior can affect predictions. Do not enter credentials based solely on a low-risk result.

If the model artifact is missing or fails to load, the API deliberately keeps heuristic scanning available and reports ML as unavailable rather than inventing a prediction.

## Author

Abhinav Kumar Mishra
