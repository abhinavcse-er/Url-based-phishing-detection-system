"""Train PhishGuard V5 on multiple independent URL-only development sources.

Training sources: PhishFusion, Ebbu2017, and PhishStorm.
External holdouts: PhishTank and PhreshPhish; neither is used for fitting,
calibration, threshold selection, or model selection.

Source label convention in all three training corpora: 0=benign, 1=phishing.
The model uses the original cleaned URL text and URL-intrinsic features only.
No DNS, WHOIS, HTTP request, page rendering, or live-site inspection is used.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import confusion_matrix, matthews_corrcoef
from sklearn.model_selection import StratifiedGroupKFold

from train_model_v4 import (
    build_model_candidates,
    calibration_summary,
    classification_metrics,
    hash_site,
    positive_class_probabilities,
)


MODEL_VERSION = 5
FEATURE_SCHEMA_VERSION = 1
RANDOM_STATE = 42
MODEL_DIR = Path(os.getenv("MODEL_DIR", "models"))
MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"
METRICS_PATH = MODEL_DIR / "training_metrics.json"
MAX_PER_SOURCE_CLASS = max(1000, int(os.getenv("ML_V5_MAX_PER_SOURCE_CLASS", "10000")))
MAX_VALIDATION_FPR = float(os.getenv("ML_V5_MAX_VALIDATION_FPR", "0.01"))
MAX_SOURCE_VALIDATION_FPR = float(os.getenv("ML_V5_MAX_SOURCE_VALIDATION_FPR", "0.02"))

UPSTREAM_COMMIT = "aedc3dd65fd92a187f5c174cd8a93a89588a98f6"
DATASET_ROOT = (
    "https://raw.githubusercontent.com/aI-area/PhishDetecting/"
    + UPSTREAM_COMMIT
    + "/dataset/"
)
SOURCES = (
    {
        "name": "PhishFusion",
        "filename": "PhishFusion.csv",
        "url": DATASET_ROOT + "PhishFusion.csv",
        "git_blob_sha1": "b698ebad3a81bf81c3868f60b1d1fefb4f1e2361",
        "expected_rows": 105752,
    },
    {
        "name": "Ebbu2017",
        "filename": "ebbu2017.csv",
        "url": DATASET_ROOT + "ebbu2017.csv",
        "git_blob_sha1": "7995c4d7b1d74c42c7fa82d2f7fd4a1676f5ad93",
        "expected_rows": 73575,
    },
    {
        "name": "PhishStorm",
        "filename": "phishstorm.csv",
        "url": DATASET_ROOT + "phishstorm.csv",
        "git_blob_sha1": "b62bd184e843c271c3a7683b1e92be922e97bf0a",
        "expected_rows": 95911,
    },
)

PRIVATE_DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def download_source(source: dict, cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / source["filename"]
    if path.exists():
        data = path.read_bytes()
    else:
        request = Request(
            source["url"],
            headers={"User-Agent": "PhishGuard-V5-MultiSource-Trainer/5.0"},
        )
        with urlopen(request, timeout=120) as response:
            data = response.read()
        path.write_bytes(data)

    actual = git_blob_sha1(data)
    if actual != source["git_blob_sha1"]:
        raise RuntimeError(
            f"{source['name']} dataset pin mismatch: expected "
            f"{source['git_blob_sha1']}, received {actual}."
        )
    return path


def normalized_http_url(raw_url: str) -> tuple[str, str, str] | None:
    """Return a scheme-independent URL key, original model text, and PSL site."""
    try:
        cleaned = html.unescape(str(raw_url).strip())
        candidate = cleaned if "://" in cleaned else "https://" + cleaned
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not hostname:
            return None
        if parsed.username or parsed.password:
            return None
        port = parsed.port
        port_text = f":{port}" if port is not None else ""
        normalized = urlunsplit((
            "",
            hostname + port_text,
            parsed.path or "/",
            parsed.query,
            "",
        ))
        extracted = PRIVATE_DOMAIN_EXTRACTOR(hostname)
        site = (
            extracted.top_domain_under_public_suffix or hostname
        ).lower()
        model_url = cleaned if "://" in cleaned else candidate
        return normalized, model_url, site
    except (TypeError, ValueError):
        return None


def load_source_corpora(cache_dir: Path) -> tuple[pd.DataFrame, dict]:
    """Download pinned corpora, validate labels/URLs, and remove conflicts."""
    source_frames = []
    source_diagnostics = {}

    for source in SOURCES:
        path = download_source(source, cache_dir)
        raw = pd.read_csv(
            path,
            usecols=["url", "phishing"],
            dtype=str,
            keep_default_na=False,
        )
        if len(raw) != source["expected_rows"]:
            raise RuntimeError(
                f"{source['name']} row count changed: expected "
                f"{source['expected_rows']}, got {len(raw)}."
            )

        labels = raw["phishing"].astype(str).str.strip()
        if not labels.isin({"0", "1"}).all():
            bad = sorted(set(labels) - {"0", "1"})
            raise ValueError(
                f"{source['name']} has unexpected phishing labels: {bad[:10]}"
            )

        parsed = raw["url"].map(normalized_http_url)
        valid_mask = parsed.notna() & raw["url"].astype(str).str.len().between(4, 2048)
        invalid_rows = int((~valid_mask).sum())
        valid = raw.loc[valid_mask].copy()
        parsed_valid = parsed.loc[valid_mask]

        valid["normalized_url"] = parsed_valid.map(lambda item: item[0])
        valid["url"] = parsed_valid.map(lambda item: item[1])
        valid["site"] = parsed_valid.map(lambda item: item[2])
        valid["target"] = labels.loc[valid_mask].astype(int)
        valid["source"] = source["name"]
        source_frames.append(valid[["url", "normalized_url", "site", "target", "source"]])

        source_diagnostics[source["name"]] = {
            "file": source["filename"],
            "git_blob_sha1": source["git_blob_sha1"],
            "input_rows": int(len(raw)),
            "invalid_or_non_http_rows_removed": invalid_rows,
            "valid_rows_before_cross_source_deduplication": int(len(valid)),
            "benign_rows": int((valid["target"] == 0).sum()),
            "phishing_rows": int((valid["target"] == 1).sum()),
        }

    combined = pd.concat(source_frames, ignore_index=True)
    conflict_sizes = combined.groupby("normalized_url")["target"].nunique()
    conflict_keys = set(conflict_sizes[conflict_sizes > 1].index)
    conflict_rows = int(combined["normalized_url"].isin(conflict_keys).sum())
    if conflict_keys:
        combined = combined.loc[
            ~combined["normalized_url"].isin(conflict_keys)
        ].copy()

    before_dedup = len(combined)
    combined = combined.drop_duplicates(
        subset=["normalized_url"],
        keep="first",
    ).copy()
    duplicate_rows = before_dedup - len(combined)

    if combined.empty or combined["target"].nunique() != 2:
        raise RuntimeError("Development corpora do not contain both classes after cleaning.")

    diagnostics = {
        "upstream_repository": "aI-area/PhishDetecting",
        "upstream_commit": UPSTREAM_COMMIT,
        "source_corpora": source_diagnostics,
        "input_rows_total": int(sum(x["expected_rows"] for x in SOURCES)),
        "conflicting_normalized_url_rows_removed": conflict_rows,
        "later_normalized_duplicate_rows_removed": int(duplicate_rows),
        "rows_after_cleaning": int(len(combined)),
        "class_counts_after_cleaning": {
            "benign": int((combined["target"] == 0).sum()),
            "phishing": int((combined["target"] == 1).sum()),
        },
        "unique_registered_domains_private_suffix_aware": int(combined["site"].nunique()),
    }
    return combined.reset_index(drop=True), diagnostics


def sample_by_source_and_class(frame: pd.DataFrame) -> pd.DataFrame:
    """Give each source equal class-balanced representation in model development."""
    samples = []
    for source_name in sorted(frame["source"].unique()):
        source_frame = frame.loc[frame["source"] == source_name]
        class_counts = source_frame["target"].value_counts()
        if 0 not in class_counts or 1 not in class_counts:
            raise RuntimeError(f"{source_name} does not contain both classes.")
        per_class = min(
            MAX_PER_SOURCE_CLASS,
            int(class_counts[0]),
            int(class_counts[1]),
        )
        for label in (0, 1):
            samples.append(
                source_frame.loc[source_frame["target"] == label].sample(
                    n=per_class,
                    random_state=RANDOM_STATE + label,
                )
            )
    sampled = (
        pd.concat(samples, ignore_index=True)
        .sample(frac=1.0, random_state=RANDOM_STATE)
        .reset_index(drop=True)
    )
    if sampled["source"].nunique() < len(SOURCES):
        raise RuntimeError("All three development sources must contribute to V5.")
    return sampled


def hostname_group(url: str) -> str:
    """Return a private-suffix-aware offline registered-domain grouping key."""
    try:
        candidate = url if "://" in url else "https://" + url
        hostname = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        hostname = ""
    if not hostname:
        return str(url).lower().strip()
    extracted = PRIVATE_DOMAIN_EXTRACTOR(hostname)
    return (extracted.top_domain_under_public_suffix or hostname).lower()


def split_by_hostname(urls, targets, groups, n_splits: int, random_state: int):
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
    """Create nested train/calibration/validation/test splits with no site overlap."""
    train_validation_idx, test_idx = split_by_hostname(
        urls, targets, groups, n_splits=5, random_state=RANDOM_STATE
    )
    remaining_urls = urls.iloc[train_validation_idx].reset_index(drop=True)
    remaining_targets = targets.iloc[train_validation_idx].reset_index(drop=True)
    remaining_groups = groups.iloc[train_validation_idx].reset_index(drop=True)

    train_calibration_idx_local, validation_idx_local = split_by_hostname(
        remaining_urls,
        remaining_targets,
        remaining_groups,
        n_splits=5,
        random_state=RANDOM_STATE + 1,
    )
    train_calibration_idx = train_validation_idx[train_calibration_idx_local]
    validation_idx = train_validation_idx[validation_idx_local]

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


def source_metrics(y_true, probabilities, sources, threshold: float) -> dict:
    result = {}
    source_values = np.asarray(sources)
    for source_name in sorted(set(source_values.tolist())):
        indexes = np.flatnonzero(source_values == source_name)
        labels = np.asarray(y_true, dtype=int)[indexes]
        if len(indexes) < 20 or len(np.unique(labels)) < 2:
            result[source_name] = {
                "rows": int(len(indexes)),
                "metrics": None,
                "reason": "Insufficient rows or one class absent in this split.",
            }
            continue
        result[source_name] = {
            "rows": int(len(indexes)),
            "metrics": classification_metrics(
                labels,
                np.asarray(probabilities, dtype=float)[indexes],
                threshold,
            ),
        }
    return result


def select_multisource_threshold(
    y_true,
    probabilities,
    sources,
    max_false_positive_rate: float = MAX_VALIDATION_FPR,
    max_source_false_positive_rate: float = MAX_SOURCE_VALIDATION_FPR,
) -> tuple[float, dict]:
    """Maximize validation MCC under global and per-source FPR constraints."""
    if not 0.0 <= max_false_positive_rate <= 1.0:
        raise ValueError("Maximum validation FPR must be between 0 and 1.")
    if not 0.0 <= max_source_false_positive_rate <= 1.0:
        raise ValueError("Maximum source validation FPR must be between 0 and 1.")

    labels = np.asarray(y_true, dtype=int)
    scores = np.asarray(probabilities, dtype=float)
    source_values = np.asarray(sources)
    thresholds = np.unique(np.concatenate((
        scores,
        np.asarray([0.0, 1.000001], dtype=float),
    )))
    eligible = []
    source_names = sorted(set(source_values.tolist()))

    for threshold in thresholds:
        global_metrics = classification_metrics(labels, scores, float(threshold))
        if global_metrics["false_positive_rate"] > max_false_positive_rate:
            continue
        per_source = source_metrics(labels, scores, source_values, float(threshold))
        usable = [
            item["metrics"]["false_positive_rate"]
            for item in per_source.values()
            if item.get("metrics") is not None
        ]
        if len(usable) != len(source_names):
            continue
        worst_source_fpr = max(usable, default=0.0)
        if worst_source_fpr > max_source_false_positive_rate:
            continue
        eligible.append((
            float(threshold),
            global_metrics,
            per_source,
            worst_source_fpr,
        ))

    if not eligible:
        fallback_threshold = 1.000001
        fallback_metrics = classification_metrics(
            labels,
            scores,
            fallback_threshold,
        )
        return fallback_threshold, {
            "feasible": False,
            "reason": (
                "No validation threshold met both the global and every-source "
                "false-positive ceilings; no positive predictions are enabled."
            ),
            "global_metrics": fallback_metrics,
            "source_metrics": source_metrics(
                labels, scores, source_values, fallback_threshold
            ),
            "worst_source_false_positive_rate": None,
            "maximum_validation_false_positive_rate": max_false_positive_rate,
            "maximum_source_validation_false_positive_rate": max_source_false_positive_rate,
        }

    selected = max(
        eligible,
        key=lambda item: (
            item[1]["mcc"],
            item[1]["recall_phishing"],
            -item[3],
            -item[1]["false_positive_rate"],
            item[0],
        ),
    )
    return selected[0], {
        "feasible": True,
        "global_metrics": selected[1],
        "source_metrics": selected[2],
        "worst_source_false_positive_rate": round(float(selected[3]), 6),
        "maximum_validation_false_positive_rate": max_false_positive_rate,
        "maximum_source_validation_false_positive_rate": max_source_false_positive_rate,
    }


def main() -> None:
    if not 0.0 < MAX_VALIDATION_FPR < 1.0:
        raise ValueError("ML_V5_MAX_VALIDATION_FPR must be greater than 0 and less than 1.")
    if not 0.0 < MAX_SOURCE_VALIDATION_FPR < 1.0:
        raise ValueError("ML_V5_MAX_SOURCE_VALIDATION_FPR must be greater than 0 and less than 1.")

    cache_dir = Path(os.getenv("ML_V5_DATA_DIR", "/tmp/phishguard-v5-data"))
    full_frame, data_diagnostics = load_source_corpora(cache_dir)

    # Preserve hashes for all valid domains in all development rows, not only
    # the sampled rows used to fit the model. External evaluation excludes all.
    all_development_sites = sorted(set(full_frame["site"].astype(str)))
    sampled = sample_by_source_and_class(full_frame)

    urls = sampled["url"].reset_index(drop=True)
    targets = sampled["target"].astype(int).reset_index(drop=True)
    sources = sampled["source"].reset_index(drop=True)
    groups = urls.map(hostname_group)

    partitions = make_grouped_splits(urls, targets, groups)
    group_sets = {
        name: set(groups.iloc[indexes].astype(str))
        for name, indexes in partitions.items()
    }
    split_names = list(group_sets)
    for left_index, left_name in enumerate(split_names):
        for right_name in split_names[left_index + 1:]:
            overlap = group_sets[left_name] & group_sets[right_name]
            if overlap:
                raise RuntimeError(
                    f"Private-suffix-aware domain leakage between "
                    f"{left_name} and {right_name}."
                )

    partition_data = {
        name: (
            urls.iloc[indexes].reset_index(drop=True),
            targets.iloc[indexes].reset_index(drop=True),
            sources.iloc[indexes].reset_index(drop=True),
        )
        for name, indexes in partitions.items()
    }
    for split_name, (_, split_targets, split_sources) in partition_data.items():
        if split_targets.nunique() != 2 or split_sources.nunique() != len(SOURCES):
            raise RuntimeError(
                f"The {split_name} split must contain both classes and all three sources. "
                "Increase the per-source sample cap or inspect the source diversity."
            )

    x_train, y_train, source_train = partition_data["training"]
    x_calibration, y_calibration, source_calibration = partition_data["calibration"]
    x_validation, y_validation, source_validation = partition_data["validation"]
    x_test, y_test, source_test = partition_data["test"]

    candidates = {}
    best_name = None
    best_model = None
    best_threshold = None
    best_validation = None
    best_rank = None

    for candidate_name, base_model in build_model_candidates().items():
        print(f"Training V5 candidate: {candidate_name}")
        base_model.fit(x_train, y_train)

        calibrated_model = CalibratedClassifierCV(
            estimator=FrozenEstimator(base_model),
            method="sigmoid",
        )
        calibrated_model.fit(x_calibration, y_calibration)

        validation_probabilities = positive_class_probabilities(
            calibrated_model,
            x_validation,
        )
        threshold, validation_selection = select_multisource_threshold(
            y_validation,
            validation_probabilities,
            source_validation,
        )
        validation_selection["source_score_summary"] = source_metrics(
            y_validation,
            validation_probabilities,
            source_validation,
            threshold,
        )
        candidates[candidate_name] = validation_selection

        global_metrics = validation_selection["global_metrics"]
        worst_source_fpr = validation_selection.get(
            "worst_source_false_positive_rate"
        )
        rank = (
            int(validation_selection.get("feasible", False)),
            global_metrics["mcc"],
            global_metrics["recall_phishing"],
            -(worst_source_fpr if worst_source_fpr is not None else 1.0),
            global_metrics["roc_auc"],
        )
        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_name = candidate_name
            best_model = calibrated_model
            best_threshold = threshold
            best_validation = validation_selection

    if best_model is None or best_name is None or best_threshold is None:
        raise RuntimeError("No V5 model candidate completed validation.")

    # The grouped final test is used only for reporting, never for selection.
    test_probabilities = positive_class_probabilities(best_model, x_test)
    test_metrics = classification_metrics(
        y_test,
        test_probabilities,
        best_threshold,
    )
    test_metrics["source_metrics"] = source_metrics(
        y_test,
        test_probabilities,
        source_test,
        best_threshold,
    )
    test_metrics["threshold_selected_without_test_partition"] = True

    metadata = {
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_family": "multi-source selection among character, hybrid, and structured URL-only candidates",
        "selected_model": best_name,
        "dataset_source": "PhishFusion + Ebbu2017 + PhishStorm",
        "dataset_upstream_commit": UPSTREAM_COMMIT,
        "source_manifest": data_diagnostics,
        "training_sample_rows": int(len(sampled)),
        "training_rows": int(len(x_train)),
        "calibration_rows": int(len(x_calibration)),
        "validation_rows": int(len(x_validation)),
        "test_rows": int(len(x_test)),
        "training_unique_sites": int(len(group_sets["training"])),
        "calibration_unique_sites": int(len(group_sets["calibration"])),
        "validation_unique_sites": int(len(group_sets["validation"])),
        "test_unique_sites": int(len(group_sets["test"])),
        "source_sample_counts": {
            split_name: {
                source_name: int((split_sources == source_name).sum())
                for source_name in sorted(set(sources))
            }
            for split_name, (_, _, split_sources) in partition_data.items()
        },
        "split_strategy": (
            "Nested StratifiedGroupKFold over private-suffix-aware registered domains; "
            "all three source datasets are present in every split and no registered "
            "domain appears in more than one split."
        ),
        "domain_grouping_version": "offline PSL snapshot including private suffixes",
        "decision_threshold": float(best_threshold),
        "threshold_selection": {
            "method": (
                "maximize validation MCC subject to global and every-source "
                "false-positive-rate ceilings"
            ),
            "selected_validation": best_validation,
            "final_test_partition_used_for_selection": False,
        },
        "test_metrics": test_metrics,
        "calibration_metrics": {
            "method": "sigmoid (Platt scaling) on a separate multi-source domain-disjoint partition",
            "held_out_test_score_summary": calibration_summary(
                y_test,
                test_probabilities,
            ),
            "interpretation": (
                "These are benchmark diagnostics on a balanced multi-source cohort, "
                "not real-world phishing probabilities or prevalence estimates."
            ),
        },
        "label_mapping": {"0": "benign", "1": "phishing"},
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "random_state": RANDOM_STATE,
        "development_site_hashes": [
            hash_site(site) for site in all_development_sites
        ],
        "development_unique_sites": int(len(all_development_sites)),
        "release_gate": {
            "status": "pending_external_validation",
            "passed": False,
            "reason": (
                "V5 has only multi-source domain-disjoint development evaluation. "
                "No independent external cohort has been reviewed for this artifact."
            ),
            "required_checks": [
                "Evaluate on a separately sourced external dataset not used for model fitting, calibration, or threshold selection.",
                "Exclude every registered domain from all three development corpora.",
                "Report aggregate and source-specific false-positive rates, recall, ROC-AUC, MCC, and confusion matrices.",
                "Pass the predeclared maximum 1% false-positive rate and minimum 80% phishing recall.",
                "Review false-positive examples and popular legitimate domains before manual approval.",
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

    print("Selected V5 model:", best_name)
    print("Decision threshold:", best_threshold)
    print("Validation selection:", json.dumps(best_validation, indent=2))
    print("Untouched domain-disjoint test metrics:", json.dumps(test_metrics, indent=2))
    print("Release gate:", metadata["release_gate"]["status"])
    print("Saved model:", MODEL_PATH)


if __name__ == "__main__":
    main()
