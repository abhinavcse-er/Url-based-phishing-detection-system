"""
Train and evaluate a URL-text phishing classifier.

Source labels: 1=legitimate, 0=phishing.
Internal labels: 0=legitimate, 1=phishing.

The dataset is sampled to a balanced benchmark, so even calibrated scores must
NOT be interpreted as real-world phishing probabilities. The user-facing API
therefore returns a class prediction only, not a probability percentage.
"""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

DATA_URL = os.getenv(
    "PHISHING_DATASET_URL",
    "https://raw.githubusercontent.com/RajaMuhammadAwais/phishing-url-dataset/master/phishing_url_dataset.csv",
)
DATA_PATH = Path(os.getenv("PHISHING_DATASET_PATH", "/tmp/phishing_url_dataset.csv"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "models"))
MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"
METRICS_PATH = MODEL_DIR / "training_metrics.json"
MAX_SAMPLES = max(1000, int(os.getenv("ML_TRAIN_MAX_SAMPLES", "50000")))
RANDOM_STATE = 42
MODEL_VERSION = 2


def download_dataset():
    if DATA_PATH.exists() and DATA_PATH.stat().st_size > 1000:
        return
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    request = Request(DATA_URL, headers={"User-Agent": "PhishGuard-ML-Trainer/2.0"})
    with urlopen(request, timeout=90) as response, DATA_PATH.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
    if DATA_PATH.stat().st_size < 1000:
        raise RuntimeError("Downloaded phishing dataset is unexpectedly small.")


def hostname_group(url: str) -> str:
    """Return a normalized hostname so URLs from one host stay in one split."""
    candidate = url if "://" in url else "http://" + url
    try:
        hostname = urlsplit(candidate).hostname
    except ValueError:
        hostname = None
    return (hostname or url).lower().rstrip(".")


def split_by_hostname(urls, targets, groups, n_splits, random_state):
    splitter = StratifiedGroupKFold(
        n_splits=n_splits, shuffle=True, random_state=random_state
    )
    return next(splitter.split(urls, targets, groups=groups))


def calibration_summary(y_true, probabilities, n_bins=10):
    """Calculate calibration metrics using equal-count probability bins."""
    y_array = np.asarray(y_true, dtype=int)
    probability_array = np.asarray(probabilities, dtype=float)
    order = np.argsort(probability_array)
    bins = np.array_split(order, min(n_bins, len(order)))
    ece = 0.0
    bin_rows = []

    for indexes in bins:
        if len(indexes) == 0:
            continue
        mean_predicted = float(np.mean(probability_array[indexes]))
        observed_fraction = float(np.mean(y_array[indexes]))
        weight = len(indexes) / len(order)
        ece += weight * abs(observed_fraction - mean_predicted)
        bin_rows.append({
            "count": int(len(indexes)),
            "mean_predicted_phishing": round(mean_predicted, 6),
            "observed_phishing_fraction": round(observed_fraction, 6),
        })

    return {
        "brier_score": round(float(np.mean((probability_array - y_array) ** 2)), 6),
        "log_loss": round(float(log_loss(y_array, probability_array, labels=[0, 1])), 6),
        "expected_calibration_error": round(float(ece), 6),
        "bins": bin_rows,
    }


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

    # Source: 1=legitimate, 0=phishing. Internal convention: 0=legitimate, 1=phishing.
    frame["target"] = (frame["Label"] == 0).astype(int)
    per_class = max(1, MAX_SAMPLES // 2)
    class_sizes = frame["target"].value_counts()
    per_class = min(per_class, int(class_sizes.min()))
    sampled = frame.groupby("target", group_keys=False).sample(
        n=per_class, random_state=RANDOM_STATE
    ).reset_index(drop=True)
    if sampled["target"].nunique() != 2 or len(sampled) < 1000:
        raise RuntimeError("Not enough balanced labelled URLs to train a useful model.")

    urls = sampled["URL"].reset_index(drop=True)
    targets = sampled["target"].reset_index(drop=True)
    groups = urls.map(hostname_group)

    # First reserve unseen hostnames for the final test set (about 20%).
    train_cal_idx, test_idx = split_by_hostname(
        urls, targets, groups, n_splits=5, random_state=RANDOM_STATE
    )
    train_cal_urls = urls.iloc[train_cal_idx].reset_index(drop=True)
    train_cal_targets = targets.iloc[train_cal_idx].reset_index(drop=True)
    train_cal_groups = groups.iloc[train_cal_idx].reset_index(drop=True)
    test_urls = urls.iloc[test_idx].reset_index(drop=True)
    test_targets = targets.iloc[test_idx].reset_index(drop=True)

    # Reserve a separate hostname-disjoint calibration set from the remaining data.
    train_idx, calibration_idx = split_by_hostname(
        train_cal_urls,
        train_cal_targets,
        train_cal_groups,
        n_splits=5,
        random_state=RANDOM_STATE + 1,
    )
    x_train = train_cal_urls.iloc[train_idx].reset_index(drop=True)
    y_train = train_cal_targets.iloc[train_idx].reset_index(drop=True)
    x_calibration = train_cal_urls.iloc[calibration_idx].reset_index(drop=True)
    y_calibration = train_cal_targets.iloc[calibration_idx].reset_index(drop=True)
    x_test = test_urls
    y_test = test_targets

    for split_name, split_targets in (
        ("training", y_train),
        ("calibration", y_calibration),
        ("test", y_test),
    ):
        if split_targets.nunique() != 2:
            raise RuntimeError(
                f"The hostname-held-out {split_name} split does not contain both classes. "
                "Increase ML_TRAIN_MAX_SAMPLES or use a more diverse labelled dataset."
            )

    base_model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=40000,
            sublinear_tf=True,
            dtype=float,
        )),
        ("classifier", LogisticRegression(
            C=4.0,
            max_iter=1000,
            class_weight="balanced",
            solver="liblinear",
            random_state=RANDOM_STATE,
        )),
    ])
    base_model.fit(x_train, y_train)

    # Calibrate only on the dedicated calibration hosts; the test hosts remain untouched.
    calibrated_model = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method="sigmoid",
    )
    calibrated_model.fit(x_calibration, y_calibration)

    # Compare uncalibrated vs calibrated probabilities on the same unseen-host test set.
    raw_test_probabilities = base_model.predict_proba(x_test)[:, 1]
    calibrated_test_probabilities = calibrated_model.predict_proba(x_test)[
        :, list(calibrated_model.classes_).index(1)
    ]
    predictions = calibrated_model.predict(x_test)

    test_metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, predictions)), 4),
        "precision_phishing": round(float(precision_score(y_test, predictions, pos_label=1, zero_division=0)), 4),
        "recall_phishing": round(float(recall_score(y_test, predictions, pos_label=1, zero_division=0)), 4),
        "f1_phishing": round(float(f1_score(y_test, predictions, pos_label=1, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, calibrated_test_probabilities)), 4),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
    }
    calibration_metrics = {
        "method": "sigmoid (Platt scaling)",
        "raw_model": calibration_summary(y_test, raw_test_probabilities),
        "calibrated_model": calibration_summary(y_test, calibrated_test_probabilities),
        "interpretation": (
            "Calibration scores are benchmark diagnostics on a balanced, hostname-held-out "
            "dataset. They are not real-world phishing probabilities because the dataset "
            "sampling does not represent the prevalence of phishing among users' submitted URLs."
        ),
    }

    train_hosts = set(groups.iloc[train_cal_idx].iloc[train_idx])
    calibration_hosts = set(groups.iloc[train_cal_idx].iloc[calibration_idx])
    test_hosts = set(groups.iloc[test_idx])
    if (train_hosts & calibration_hosts) or (train_hosts & test_hosts) or (calibration_hosts & test_hosts):
        raise RuntimeError("Hostname leakage detected between training, calibration, and test splits.")

    metadata = {
        "model_version": MODEL_VERSION,
        "dataset_source": DATA_URL,
        "dataset_rows_after_cleaning": int(len(frame)),
        "training_sample_rows": int(len(sampled)),
        "training_rows": int(len(x_train)),
        "calibration_rows": int(len(x_calibration)),
        "test_rows": int(len(x_test)),
        "training_unique_hosts": int(len(train_hosts)),
        "calibration_unique_hosts": int(len(calibration_hosts)),
        "test_unique_hosts": int(len(test_hosts)),
        "split_strategy": "StratifiedGroupKFold by normalized hostname; no hostname overlap between splits",
        "test_metrics": test_metrics,
        "calibration_metrics": calibration_metrics,
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "random_state": RANDOM_STATE,
        "probabilities_are_real_world_prevalence_estimates": False,
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": calibrated_model, "metadata": metadata}, MODEL_PATH, compress=3)
    METRICS_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Calibrated ML model trained and saved:", MODEL_PATH)
    print("Held-out test metrics:")
    print(json.dumps(test_metrics, indent=2))
    print("Calibration comparison (lower Brier score / ECE / log loss is better):")
    print(json.dumps(calibration_metrics, indent=2))
    print("Split sizes:", json.dumps({
        "training": len(x_train),
        "calibration": len(x_calibration),
        "test": len(x_test),
    }))


if __name__ == "__main__":
    main()
