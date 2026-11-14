"""
Train PhishGuard's v4 URL-only phishing classifier.

The v4 trainer compares three representations on registrable-domain-disjoint
partitions: character TF-IDF, hybrid character/word TF-IDF plus structural URL
features, and a structured-feature gradient-boosting baseline.

Source labels: 1=legitimate, 0=phishing.
Internal labels: 0=legitimate, 1=phishing.

The decision threshold is selected on a dedicated validation partition subject
to a configurable false-positive-rate ceiling. A final grouped test partition is
used once for reporting and never for model or threshold selection.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from url_features import (
    FEATURE_NAMES,
    extract_url_features_dense,
    extract_url_features_sparse,
)


DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

DATA_URL = os.getenv(
    "PHISHING_DATASET_URL",
    "https://raw.githubusercontent.com/RajaMuhammadAwais/phishing-url-dataset/master/phishing_url_dataset.csv",
)
DATA_PATH = Path(os.getenv("PHISHING_DATASET_PATH", "/tmp/phishing_url_dataset.csv"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "models"))
MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"
METRICS_PATH = MODEL_DIR / "training_metrics.json"
MAX_SAMPLES = max(1000, int(os.getenv("ML_TRAIN_MAX_SAMPLES", "50000")))
MAX_VALIDATION_FPR = float(os.getenv("ML_MAX_VALIDATION_FPR", "0.01"))
RANDOM_STATE = 42
MODEL_VERSION = 4


def download_dataset() -> None:
    if DATA_PATH.exists() and DATA_PATH.stat().st_size > 1000:
        return

    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    request = Request(DATA_URL, headers={"User-Agent": "PhishGuard-ML-Trainer/4.0"})
    with urlopen(request, timeout=90) as response, DATA_PATH.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)

    if DATA_PATH.stat().st_size < 1000:
        raise RuntimeError("Downloaded phishing dataset is unexpectedly small.")


def hostname_group(url: str) -> str:
    """Return an offline eTLD+1 grouping key to prevent subdomain leakage."""
    candidate = url if "://" in url else "https://" + url
    try:
        hostname = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        hostname = ""
    if not hostname:
        return str(url).lower().strip()

    extracted = DOMAIN_EXTRACTOR(hostname)
    return (extracted.top_domain_under_public_suffix or hostname).lower()


def hash_site(site: str) -> str:
    """Hash site keys before storing them in the private model artifact."""
    return hashlib.sha256(site.encode("utf-8")).hexdigest()


def split_by_hostname(urls, targets, groups, n_splits: int, random_state: int):
    from sklearn.model_selection import StratifiedGroupKFold

    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )
    return next(
        splitter.split(
            np.zeros(len(urls)),
            np.asarray(targets, dtype=int),
            groups=np.asarray(groups),
        )
    )


def make_grouped_splits(urls, targets, groups) -> dict[str, np.ndarray]:
    """Create train/calibration/validation/test groups with no eTLD+1 overlap."""
    train_validation_idx, test_idx = split_by_hostname(
        urls, targets, groups, n_splits=5, random_state=RANDOM_STATE
    )

    remaining_urls = urls.iloc[train_validation_idx].reset_index(drop=True)
    remaining_targets = targets.iloc[train_validation_idx].reset_index(drop=True)
    remaining_groups = groups.iloc[train_validation_idx].reset_index(drop=True)

    train_calibration_local, validation_local = split_by_hostname(
        remaining_urls,
        remaining_targets,
        remaining_groups,
        n_splits=5,
        random_state=RANDOM_STATE + 1,
    )
    train_calibration_idx = train_validation_idx[train_calibration_local]
    validation_idx = train_validation_idx[validation_local]

    train_calibration_urls = urls.iloc[train_calibration_idx].reset_index(drop=True)
    train_calibration_targets = targets.iloc[train_calibration_idx].reset_index(drop=True)
    train_calibration_groups = groups.iloc[train_calibration_idx].reset_index(drop=True)

    training_local, calibration_local = split_by_hostname(
        train_calibration_urls,
        train_calibration_targets,
        train_calibration_groups,
        n_splits=4,
        random_state=RANDOM_STATE + 2,
    )

    return {
        "training": train_calibration_idx[training_local],
        "calibration": train_calibration_idx[calibration_local],
        "validation": validation_idx,
        "test": test_idx,
    }


def build_model_candidates() -> dict[str, Pipeline]:
    """Build comparable URL-only baselines and the proposed hybrid candidate."""
    char_model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=50000,
            sublinear_tf=True,
            dtype=np.float32,
        )),
        ("classifier", LogisticRegression(
            C=2.0,
            max_iter=1400,
            solver="liblinear",
            random_state=RANDOM_STATE,
        )),
    ])

    hybrid_features = FeatureUnion([
        ("character_ngrams", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=50000,
            sublinear_tf=True,
            dtype=np.float32,
        )),
        ("word_ngrams", TfidfVectorizer(
            analyzer="word",
            token_pattern=r"(?u)[a-zA-Z0-9]+",
            ngram_range=(1, 2),
            min_df=2,
            max_features=20000,
            sublinear_tf=True,
            dtype=np.float32,
        )),
        ("url_structure", Pipeline([
            ("extract", FunctionTransformer(
                extract_url_features_sparse,
                validate=False,
            )),
            ("scale", StandardScaler(with_mean=False)),
        ])),
    ])
    hybrid_model = Pipeline([
        ("features", hybrid_features),
        ("classifier", LogisticRegression(
            C=2.0,
            max_iter=1600,
            solver="liblinear",
            random_state=RANDOM_STATE,
        )),
    ])

    structured_model = Pipeline([
        ("features", FunctionTransformer(
            extract_url_features_dense,
            validate=False,
        )),
        ("classifier", HistGradientBoostingClassifier(
            learning_rate=0.07,
            max_iter=180,
            max_leaf_nodes=15,
            l2_regularization=1.0,
            early_stopping=True,
            random_state=RANDOM_STATE,
        )),
    ])

    return {
        "character_tfidf_logistic_regression": char_model,
        "hybrid_text_and_url_features": hybrid_model,
        "structured_url_features_hist_gradient_boosting": structured_model,
    }


def calibration_summary(y_true, probabilities, n_bins: int = 10) -> dict:
    """Summarize benchmark calibration; these are not real-world probabilities."""
    y_array = np.asarray(y_true, dtype=int)
    probability_array = np.asarray(probabilities, dtype=float)
    order = np.argsort(probability_array)
    bins = np.array_split(order, min(n_bins, len(order)))
    expected_calibration_error = 0.0
    bin_rows = []

    for indexes in bins:
        if len(indexes) == 0:
            continue
        mean_predicted = float(np.mean(probability_array[indexes]))
        observed_fraction = float(np.mean(y_array[indexes]))
        weight = len(indexes) / len(order)
        expected_calibration_error += weight * abs(observed_fraction - mean_predicted)
        bin_rows.append({
            "count": int(len(indexes)),
            "mean_model_score": round(mean_predicted, 6),
            "observed_phishing_fraction": round(observed_fraction, 6),
        })

    return {
        "brier_score": round(
            float(np.mean((probability_array - y_array) ** 2)), 6
        ),
        "expected_calibration_error": round(
            float(expected_calibration_error), 6
        ),
        "bins": bin_rows,
    }


def classification_metrics(y_true, probabilities, threshold: float) -> dict:
    y_array = np.asarray(y_true, dtype=int)
    probability_array = np.asarray(probabilities, dtype=float)
    predictions = (probability_array >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_array, predictions, labels=[0, 1]
    ).ravel()

    return {
        "threshold": round(float(threshold), 8),
        "accuracy": round(float(accuracy_score(y_array, predictions)), 6),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_array, predictions)), 6),
        "precision_phishing": round(float(precision_score(
            y_array, predictions, pos_label=1, zero_division=0
        )), 6),
        "recall_phishing": round(float(recall_score(
            y_array, predictions, pos_label=1, zero_division=0
        )), 6),
        "f1_phishing": round(float(f1_score(
            y_array, predictions, pos_label=1, zero_division=0
        )), 6),
        "mcc": round(float(matthews_corrcoef(y_array, predictions)), 6),
        "roc_auc": round(float(roc_auc_score(y_array, probability_array)), 6),
        "average_precision": round(float(average_precision_score(
            y_array, probability_array
        )), 6),
        "false_positive_rate": round(float(fp / max(1, fp + tn)), 6),
        "false_negative_rate": round(float(fn / max(1, fn + tp)), 6),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def select_threshold(
    y_true,
    probabilities,
    max_false_positive_rate: float = MAX_VALIDATION_FPR,
) -> tuple[float, dict]:
    """Maximize validation MCC while keeping validation FPR under the ceiling."""
    if not 0.0 <= max_false_positive_rate <= 1.0:
        raise ValueError("Maximum validation FPR must be between 0 and 1.")

    probability_array = np.asarray(probabilities, dtype=float)
    thresholds = np.unique(np.concatenate((
        probability_array,
        np.asarray([0.0, 1.000001], dtype=float),
    )))
    eligible = []

    for threshold in thresholds:
        metrics = classification_metrics(y_true, probability_array, float(threshold))
        if metrics["false_positive_rate"] <= max_false_positive_rate:
            eligible.append((float(threshold), metrics))

    if not eligible:
        raise RuntimeError("No decision threshold satisfied the validation FPR ceiling.")

    selected_threshold, selected_metrics = max(
        eligible,
        key=lambda item: (
            item[1]["mcc"],
            item[1]["recall_phishing"],
            -item[1]["false_positive_rate"],
            item[1]["precision_phishing"],
            item[0],
        ),
    )
    return float(selected_threshold), selected_metrics


def positive_class_probabilities(model, urls) -> np.ndarray:
    classes = list(model.classes_)
    if 1 not in classes:
        raise RuntimeError("The trained model has no phishing class (label 1).")
    return model.predict_proba(urls)[:, classes.index(1)]


def main() -> None:
    if not 0.0 < MAX_VALIDATION_FPR < 1.0:
        raise ValueError("ML_MAX_VALIDATION_FPR must be greater than 0 and less than 1.")

    download_dataset()
    frame = pd.read_csv(DATA_PATH, usecols=["URL", "Label"])
    frame["URL"] = frame["URL"].astype(str).str.strip()
    frame["Label"] = pd.to_numeric(frame["Label"], errors="coerce")
    frame = frame.dropna(subset=["URL", "Label"])
    frame = frame[frame["URL"].str.len().between(4, 2048)]
    frame = frame[frame["Label"].isin([0, 1])]
    frame = frame.drop_duplicates(subset=["URL"]).reset_index(drop=True)

    if frame["Label"].nunique() != 2:
        raise RuntimeError("Dataset must contain both legitimate and phishing labels.")

    # Source: 1=legitimate, 0=phishing. Internal convention: 0=legitimate, 1=phishing.
    frame["target"] = (frame["Label"] == 0).astype(int)
    per_class = min(
        max(1, MAX_SAMPLES // 2),
        int(frame["target"].value_counts().min()),
    )
    sampled = (
        frame.groupby("target", group_keys=False)
        .sample(n=per_class, random_state=RANDOM_STATE)
        .reset_index(drop=True)
    )
    if sampled["target"].nunique() != 2 or len(sampled) < 1000:
        raise RuntimeError("Not enough balanced labelled URLs to train the model.")

    urls = sampled["URL"].reset_index(drop=True)
    targets = sampled["target"].reset_index(drop=True)
    groups = urls.map(hostname_group)

    partitions = make_grouped_splits(urls, targets, groups)
    partition_data = {
        name: (urls.iloc[indexes].reset_index(drop=True),
               targets.iloc[indexes].reset_index(drop=True))
        for name, indexes in partitions.items()
    }

    for split_name, (_, split_targets) in partition_data.items():
        if split_targets.nunique() != 2:
            raise RuntimeError(
                f"The domain-held-out {split_name} split does not contain both classes. "
                "Increase ML_TRAIN_MAX_SAMPLES or use a more diverse dataset."
            )

    group_sets = {
        name: set(groups.iloc[indexes].astype(str))
        for name, indexes in partitions.items()
    }
    split_names = list(group_sets)
    for left_index, left_name in enumerate(split_names):
        for right_name in split_names[left_index + 1:]:
            if group_sets[left_name] & group_sets[right_name]:
                raise RuntimeError(
                    f"Registrable-domain leakage detected between {left_name} and {right_name}."
                )

    x_train, y_train = partition_data["training"]
    x_calibration, y_calibration = partition_data["calibration"]
    x_validation, y_validation = partition_data["validation"]
    x_test, y_test = partition_data["test"]

    candidate_results = {}
    best_name = None
    best_model = None
    best_threshold = None
    best_validation_metrics = None
    best_rank = None

    for candidate_name, base_model in build_model_candidates().items():
        print(f"Training candidate: {candidate_name}")
        base_model.fit(x_train, y_train)

        calibrated_model = CalibratedClassifierCV(
            estimator=FrozenEstimator(base_model),
            method="sigmoid",
        )
        calibrated_model.fit(x_calibration, y_calibration)

        validation_probabilities = positive_class_probabilities(
            calibrated_model, x_validation
        )
        threshold, validation_metrics = select_threshold(
            y_validation,
            validation_probabilities,
            max_false_positive_rate=MAX_VALIDATION_FPR,
        )

        candidate_results[candidate_name] = {
            "validation_metrics": validation_metrics,
            "passes_validation_fpr_target": (
                validation_metrics["false_positive_rate"] <= MAX_VALIDATION_FPR
            ),
        }
        rank = (
            validation_metrics["mcc"],
            validation_metrics["recall_phishing"],
            -validation_metrics["false_positive_rate"],
            validation_metrics["precision_phishing"],
        )
        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_name = candidate_name
            best_model = calibrated_model
            best_threshold = threshold
            best_validation_metrics = validation_metrics

    if best_model is None or best_name is None or best_threshold is None:
        raise RuntimeError("No model candidate completed validation.")

    test_probabilities = positive_class_probabilities(best_model, x_test)
    test_metrics = classification_metrics(y_test, test_probabilities, best_threshold)
    test_metrics["classification_report"] = classification_report(
        y_test,
        (test_probabilities >= best_threshold).astype(int),
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        output_dict=True,
        zero_division=0,
    )

    held_out_calibration = calibration_summary(y_test, test_probabilities)
    all_development_sites = sorted(set(groups.astype(str)))
    metadata = {
        "model_version": MODEL_VERSION,
        "feature_schema_version": 1,
        "model_family": "model-selection among URL text, hybrid, and structured-feature baselines",
        "selected_model": best_name,
        "dataset_source": DATA_URL,
        "dataset_rows_after_cleaning": int(len(frame)),
        "training_sample_rows": int(len(sampled)),
        "training_rows": int(len(x_train)),
        "calibration_rows": int(len(x_calibration)),
        "validation_rows": int(len(x_validation)),
        "test_rows": int(len(x_test)),
        "training_unique_hosts": int(len(group_sets["training"])),
        "calibration_unique_hosts": int(len(group_sets["calibration"])),
        "validation_unique_hosts": int(len(group_sets["validation"])),
        "test_unique_hosts": int(len(group_sets["test"])),
        "split_strategy": (
            "Four disjoint partitions grouped by offline eTLD+1: "
            "training, calibration, validation, and final test"
        ),
        "decision_threshold": float(best_threshold),
        "threshold_selection": {
            "method": "maximize validation MCC subject to maximum validation FPR",
            "maximum_validation_fpr": MAX_VALIDATION_FPR,
            "selected_validation_metrics": best_validation_metrics,
            "candidate_validation_results": candidate_results,
            "test_partition_used_for_selection": False,
        },
        "test_metrics": test_metrics,
        "calibration_metrics": {
            "method": "sigmoid (Platt scaling)",
            "held_out_test_score_summary": held_out_calibration,
            "interpretation": (
                "These diagnostics are measured on a balanced, domain-held-out benchmark. "
                "They are not real-world phishing probabilities or prevalence estimates."
            ),
        },
        "feature_names": list(FEATURE_NAMES),
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "random_state": RANDOM_STATE,
        "probabilities_are_real_world_prevalence_estimates": False,
        "development_site_hashes": [hash_site(site) for site in all_development_sites],
        "release_gate": {
            "status": "pending_external_validation",
            "passed": False,
            "reason": (
                "A grouped holdout from the training source is not independent external "
                "validation. Do not enable live ML inference from these metrics alone."
            ),
            "required_checks": [
                "Evaluate on a separately sourced and independently labelled URL dataset.",
                "Check that external registrable sites do not overlap the development sites.",
                "Report false-positive rate, false-negative rate, precision, recall, MCC, and PR-AUC.",
                "Include well-known legitimate domains and varied hosting providers.",
                "Review error samples and dataset collection dates before release approval.",
            ],
        },
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"pipeline": best_model, "metadata": metadata},
        MODEL_PATH,
        compress=3,
    )
    METRICS_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Selected model:", best_name)
    print("Validation threshold:", best_threshold)
    print("Validation metrics:")
    print(json.dumps(best_validation_metrics, indent=2))
    print("Untouched domain-held-out test metrics:")
    print(json.dumps(test_metrics, indent=2))
    print("ML release gate:", metadata["release_gate"]["status"])
    print("Saved model:", MODEL_PATH)


if __name__ == "__main__":
    main()
