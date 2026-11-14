# PhishGuard — URL-based Phishing Detection

A responsive static frontend and FastAPI backend that combines explainable URL heuristics with a trained machine-learning URL classifier.

## Project structure

- `index.html`, `styles.css`, `app.js`: Netlify static frontend.
- `api-config.js`: public API base URL configuration.
- `server.py`: FastAPI API, heuristic checks, and ML inference.
- `train_model.py`: reproducible model training, probability calibration, and held-out evaluation.
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

## Model evaluation and calibration

The training pipeline creates three hostname-disjoint partitions:

- Training set: fits the URL classifier.
- Calibration set: applies sigmoid (Platt) calibration to the trained classifier.
- Test set: remains untouched until final evaluation.

URLs sharing the same normalized hostname are kept in the same partition to reduce hostname leakage between training and evaluation. The build logs and `/health` endpoint expose held-out test metrics: accuracy, balanced accuracy, phishing precision/recall/F1, ROC-AUC, and calibration diagnostics.

Calibration diagnostics compare the uncalibrated and calibrated model using Brier score, log loss, and expected calibration error (ECE). For these metrics, lower values generally indicate better probability calibration. Check the actual Render build output and `/health` response after deployment rather than assuming the model passed; the metrics are generated from the dataset used in that build.

**Important probability limitation:** the public dataset is sampled to create a balanced benchmark. Its phishing prevalence does not represent the prevalence of phishing among real users' submitted URLs. Calibration metrics therefore describe performance on that benchmark only; they do not establish real-world phishing probabilities. For this reason, the scanner intentionally shows the ML class prediction only and does not display a probability percentage.

## Local development

```bash
pip install -r requirements.txt
python train_model.py
uvicorn server:app --reload --port 5500
```

## Dataset and limitations

The classifier is trained on the public [Phishing URL Dataset by Raja Muhammad Awais](https://github.com/RajaMuhammadAwais/phishing-url-dataset), which describes 200,000 labelled URLs (label 1 = legitimate, label 0 = phishing) compiled from UCI PhiUSIIL and Phishing.Database sources. The training script reverses the source labels into the API convention (0 = legitimate, 1 = phishing).

The model uses URL text only; it does not open submitted websites. The heuristic score and ML classification are separate signals and neither is a definitive safety verdict. Dataset bias, stale labels, unseen domains, and changing attacker behavior can affect predictions. Do not enter credentials based solely on a low-risk result.

If the model artifact is missing or fails to load, the API deliberately keeps heuristic scanning available and reports ML as unavailable rather than inventing a prediction.

## Author

Abhinav Kumar Mishra
