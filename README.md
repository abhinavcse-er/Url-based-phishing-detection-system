# PhishGuard — URL-based Phishing Detection

A responsive static frontend and FastAPI backend that combines explainable URL heuristics with a trained machine-learning URL classifier.

## Project structure

- `index.html`, `styles.css`, `app.js`: Netlify static frontend.
- `api-config.js`: public API base URL configuration.
- `server.py`: FastAPI API, heuristic checks, and ML inference.
- `train_model.py`: reproducible training and held-out evaluation.
- `models/`: generated model artifact and training metrics (created during deployment).
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
   This downloads the labelled URL corpus, trains a character n-gram TF-IDF + Logistic Regression pipeline, evaluates it on a held-out stratified test split, then saves the model into `models/`.
4. **Start command:**
   ```bash
   gunicorn server:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
   ```
5. Optional environment variable: `ALLOWED_ORIGINS=https://detectphishing.netlify.app`.
6. Deploy, then open `https://YOUR-BACKEND.onrender.com/health`. A successful ML deployment reports `"ml_model": "loaded"` and includes training metrics.

The default training sample is 50,000 URLs (25,000 per class) to keep free-tier build resource use manageable. Set `ML_TRAIN_MAX_SAMPLES` to change this. The dataset download URL can be overridden with `PHISHING_DATASET_URL`.

## Local development

```bash
pip install -r requirements.txt
python train_model.py
uvicorn server:app --reload --port 5500
```

## Model and dataset notes

The classifier is trained on the public [Phishing URL Dataset by Raja Muhammad Awais](https://github.com/RajaMuhammadAwais/phishing-url-dataset), which describes 200,000 labelled URLs (label 1 = legitimate, label 0 = phishing) compiled from UCI PhiUSIIL and Phishing.Database sources. The training script reverses the source labels into the API convention (0 = legitimate, 1 = phishing).

The model uses URL text only; it does not open submitted websites. The API returns the model's estimated phishing probability alongside the existing heuristic risk score. This is a model estimate, not a calibrated guarantee of safety. Dataset bias, stale labels, unseen domains, and changing attacker behavior can affect predictions. Do not enter credentials based solely on a low-risk result.

If the model artifact is missing or fails to load, the API deliberately keeps heuristic scanning available and reports ML as unavailable rather than inventing a prediction.

## Author

Abhinav Kumar Mishra
