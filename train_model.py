"""
Train a URL-text phishing classifier from a public, labelled URL corpus.
Dataset labels in the source: 1=legitimate, 0=phishing.
Our model labels: 0=legitimate, 1=phishing.
"""
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DATA_URL = os.getenv(
    "PHISHING_DATASET_URL",
    "https://raw.githubusercontent.com/RajaMuhammadAwais/phishing-url-dataset/master/phishing_url_dataset.csv",
)
DATA_PATH = Path(os.getenv("PHISHING_DATASET_PATH", "/tmp/phishing_url_dataset.csv"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "models"))
MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"
MAX_SAMPLES = int(os.getenv("ML_TRAIN_MAX_SAMPLES", "50000"))
RANDOM_STATE = 42


def download_dataset():
    if DATA_PATH.exists() and DATA_PATH.stat().st_size > 1000:
        return
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    request = Request(DATA_URL, headers={"User-Agent": "PhishGuard-ML-Trainer/1.0"})
    with urlopen(request, timeout=90) as response, DATA_PATH.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
    if DATA_PATH.stat().st_size < 1000:
        raise RuntimeError("Downloaded phishing dataset is unexpectedly small.")


def main():
    download_dataset()
    frame = pd.read_csv(DATA_PATH, usecols=["URL", "Label"])
    frame["URL"] = frame["URL"].astype(str).str.strip()
    frame["Label"] = pd.to_numeric(frame["Label"], errors="coerce")
    frame = frame.dropna(subset=["URL", "Label"])
    frame = frame[frame["URL"].str.len().between(4, 2048)]
    frame = frame[frame["Label"].isin([0, 1])].drop_duplicates(subset=["URL"])
    if frame["Label"].nunique() != 2:
        raise RuntimeError("Dataset must contain both legitimate and phishing labels.")

    # Source: 1=legitimate, 0=phishing. Model: 0=legitimate, 1=phishing.
    frame["target"] = (frame["Label"] == 0).astype(int)
    per_class = max(1, MAX_SAMPLES // 2)
    sampled = (
        frame.groupby("target", group_keys=False)
        .apply(lambda group: group.sample(n=min(len(group), per_class), random_state=RANDOM_STATE))
        .reset_index(drop=True)
    )
    if sampled["target"].nunique() != 2 or len(sampled) < 1000:
        raise RuntimeError("Not enough balanced labelled URLs to train a useful model.")

    x_train, x_test, y_train, y_test = train_test_split(
        sampled["URL"], sampled["target"], test_size=0.2,
        random_state=RANDOM_STATE, stratify=sampled["target"],
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5), min_df=2,
            max_features=40000, sublinear_tf=True, dtype=float,
        )),
        ("classifier", LogisticRegression(
            C=4.0, max_iter=1000, class_weight="balanced",
            solver="liblinear", random_state=RANDOM_STATE,
        )),
    ])
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    metrics = {
        "dataset_source": DATA_URL,
        "dataset_rows_after_cleaning": int(len(frame)),
        "training_sample_rows": int(len(sampled)),
        "test_rows": int(len(x_test)),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "f1_phishing": round(float(f1_score(y_test, predictions, pos_label=1)), 4),
        "classification_report": classification_report(
            y_test, predictions, target_names=["legitimate", "phishing"], output_dict=True,
            zero_division=0,
        ),
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "random_state": RANDOM_STATE,
    }

    # Refit on the full sampled corpus after measuring held-out performance.
    pipeline.fit(sampled["URL"], sampled["target"])
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "metadata": metrics}, MODEL_PATH, compress=3)
    (MODEL_DIR / "training_metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print("ML model trained and saved:", MODEL_PATH)
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))


if __name__ == "__main__":
    main()
