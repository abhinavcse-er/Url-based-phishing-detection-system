"""Evaluate a trained PhishGuard v4 model on a separately sourced labelled CSV.

The script never visits submitted URLs. It validates optional per-row hashes,
removes invalid URLs, conflicting normalized labels and normalized duplicates,
then reports both the full cohort and development-site-disjoint performance.
It does not enable live inference; production approval remains a manual decision.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd

from train_model import (
    classification_metrics,
    hash_site,
    hostname_group,
    positive_class_probabilities,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate a PhishGuard v4 model on independent labelled URLs."
    )
    parser.add_argument("--dataset", required=True, help="Path to an independently sourced CSV or CSV.GZ.")
    parser.add_argument("--url-column", default="URL")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument(
        "--phishing-label",
        default="0",
        help="Value in the CSV label column that means phishing (default: 0).",
    )
    parser.add_argument(
        "--benign-label",
        default="1",
        help="Value in the CSV label column that means legitimate (default: 1).",
    )
    parser.add_argument(
        "--model",
        default="models/url_phishing_model.joblib",
        help="Path to the trained v4 joblib artifact.",
    )
    parser.add_argument("--output", default="external_validation_report.json")
    parser.add_argument("--minimum-per-class", type=int, default=500)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-recall", type=float, default=0.80)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_http_url(value: str) -> tuple[str, str] | None:
    """Return a scheme-independent URL key and eTLD+1 for a valid HTTP(S) URL."""
    try:
        text = html.unescape(str(value).strip())
        parsed = urlsplit(text if "://" in text else "//" + text)
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
        registered_domain = hostname_group(text)
        if not registered_domain:
            return None
        return normalized, registered_domain
    except (TypeError, ValueError):
        return None


def load_external_dataset(
    dataset_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
    benign_label: str,
) -> tuple[pd.DataFrame, dict]:
    """Load, validate and de-duplicate a labelled external URL cohort."""
    frame = pd.read_csv(dataset_path, compression="infer", keep_default_na=False)
    required = {url_column, label_column}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"External CSV is missing required columns: {sorted(missing)}")

    frame = frame.copy()
    has_url_sha256 = "url_sha256" in frame.columns
    frame["url"] = frame[url_column].astype(str).str.strip()
    frame["source_label"] = frame[label_column].astype(str).str.strip().str.lower()
    frame["calculated_url_sha256"] = frame["url"].map(
        lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    )

    hash_checks = {}
    if has_url_sha256:
        source_hashes = frame["url_sha256"].astype(str).str.lower().reset_index(drop=True)
        calculated_hashes = frame["calculated_url_sha256"].astype(str).str.lower().reset_index(drop=True)
        hash_checks["url_sha256_rows"] = int((source_hashes == calculated_hashes).sum())
        if not (source_hashes == calculated_hashes).all():
            raise ValueError("One or more URL values do not match the CSV's url_sha256 column.")

    if "source_id" in frame.columns:
        source_ids = frame["source_id"].astype(str).str.lower().reset_index(drop=True)
        calculated = frame["calculated_url_sha256"].astype(str).str.lower().reset_index(drop=True)
        hash_checks["source_id_rows"] = int((source_ids == calculated).sum())
        if not (source_ids == calculated).all():
            raise ValueError("One or more URL values do not match the CSV's source_id column.")

    input_rows = len(frame)
    allowed_labels = {phishing_label.lower(), benign_label.lower()}
    label_mask = frame["source_label"].isin(allowed_labels)
    unknown_label_rows = int((~label_mask).sum())
    frame = frame.loc[label_mask].copy()

    frame["url_length"] = frame["url"].str.len()
    length_mask = frame["url_length"].between(4, 2048)
    overlength_rows = int((~length_mask).sum())
    frame = frame.loc[length_mask].copy()

    parsed = frame["url"].map(normalized_http_url)
    valid_mask = parsed.notna()
    invalid_url_rows = int((~valid_mask).sum())
    frame = frame.loc[valid_mask].copy()
    parsed = parsed.loc[valid_mask]

    frame["normalized_url"] = parsed.map(lambda item: item[0])
    frame["site"] = parsed.map(lambda item: item[1])

    conflict_sizes = frame.groupby("normalized_url")["source_label"].nunique()
    conflict_keys = set(conflict_sizes[conflict_sizes > 1].index)
    conflict_rows = int(frame["normalized_url"].isin(conflict_keys).sum())
    if conflict_keys:
        frame = frame.loc[~frame["normalized_url"].isin(conflict_keys)].copy()

    before_dedup = len(frame)
    frame = frame.drop_duplicates(subset=["normalized_url"], keep="first").copy()
    duplicate_rows = before_dedup - len(frame)

    frame["target"] = (
        frame["source_label"] == phishing_label.lower()
    ).astype(int)
    frame["site_hash"] = frame["site"].map(hash_site)

    if frame.empty or frame["target"].nunique() != 2:
        raise RuntimeError(
            "After URL validation and de-duplication, the external CSV must contain both classes."
        )

    diagnostics = {
        "input_rows": int(input_rows),
        "unknown_label_rows_removed": unknown_label_rows,
        "overlength_rows_removed": overlength_rows,
        "invalid_or_non_http_url_rows_removed": invalid_url_rows,
        "normalized_label_conflict_rows_removed": conflict_rows,
        "normalized_duplicate_rows_removed": int(duplicate_rows),
        "rows_after_cleaning": int(len(frame)),
        "class_counts_after_cleaning": {
            "benign": int((frame["target"] == 0).sum()),
            "phishing": int((frame["target"] == 1).sum()),
        },
        "unique_registered_domains_after_cleaning": int(frame["site"].nunique()),
        "url_hash_integrity": hash_checks,
    }
    return frame.reset_index(drop=True), diagnostics


def main() -> None:
    args = parse_args()
    if args.minimum_per_class < 1:
        raise ValueError("--minimum-per-class must be at least 1.")
    if not 0.0 <= args.max_fpr <= 1.0:
        raise ValueError("--max-fpr must be between 0 and 1.")
    if not 0.0 <= args.min_recall <= 1.0:
        raise ValueError("--min-recall must be between 0 and 1.")
    if args.phishing_label.lower() == args.benign_label.lower():
        raise ValueError("Phishing and benign label values must be different.")

    dataset_path = Path(args.dataset)
    model_path = Path(args.model)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"External dataset not found: {dataset_path}")
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {model_path}")

    saved_model = joblib.load(model_path)
    metadata = saved_model.get("metadata", {})
    pipeline = saved_model.get("pipeline")
    if pipeline is None or metadata.get("model_version") != 4:
        raise RuntimeError("The supplied artifact is not a compatible PhishGuard v4 model.")

    frame, cleaning = load_external_dataset(
        dataset_path,
        args.url_column,
        args.label_column,
        args.phishing_label,
        args.benign_label,
    )

    development_hashes = set(metadata.get("development_site_hashes", []))
    if not development_hashes:
        raise RuntimeError(
            "Model artifact has no development-site manifest; retrain with the v4 trainer."
        )

    overlap_mask = frame["site_hash"].isin(development_hashes)
    overlap_frame = frame.loc[overlap_mask].copy()
    disjoint_frame = frame.loc[~overlap_mask].copy()

    threshold = float(metadata["decision_threshold"])
    all_scores = positive_class_probabilities(pipeline, frame["url"].tolist())
    all_metrics = classification_metrics(frame["target"], all_scores, threshold)

    if disjoint_frame["target"].nunique() == 2:
        disjoint_scores = positive_class_probabilities(
            pipeline,
            disjoint_frame["url"].tolist(),
        )
        disjoint_metrics = classification_metrics(
            disjoint_frame["target"],
            disjoint_scores,
            threshold,
        )
    else:
        disjoint_metrics = None

    disjoint_counts = {
        "benign": int((disjoint_frame["target"] == 0).sum()),
        "phishing": int((disjoint_frame["target"] == 1).sum()),
    }
    enough_data = all(
        disjoint_counts[label] >= args.minimum_per_class
        for label in ("benign", "phishing")
    )
    no_development_site_overlap = not bool(
        disjoint_frame["site_hash"].isin(development_hashes).any()
    )
    fpr_pass = (
        disjoint_metrics is not None
        and disjoint_metrics["false_positive_rate"] <= args.max_fpr
    )
    recall_pass = (
        disjoint_metrics is not None
        and disjoint_metrics["recall_phishing"] >= args.min_recall
    )

    checks = {
        "minimum_per_class_met_on_disjoint_sites": enough_data,
        "development_sites_excluded_from_disjoint_evaluation": no_development_site_overlap,
        "false_positive_rate_within_limit": fpr_pass,
        "phishing_recall_meets_minimum": recall_pass,
    }
    candidate_passed = all(checks.values())

    report = {
        "report_type": "independent_external_url_model_evaluation",
        "model_version": metadata.get("model_version"),
        "selected_model": metadata.get("selected_model"),
        "dataset_file": dataset_path.name,
        "dataset_sha256": sha256_file(dataset_path),
        "cleaning": cleaning,
        "full_external_metrics": all_metrics,
        "site_disjoint_external_evaluation": {
            "rows": int(len(disjoint_frame)),
            "unique_sites": int(disjoint_frame["site"].nunique()),
            "class_counts": disjoint_counts,
            "metrics": disjoint_metrics,
        },
        "development_overlap_excluded": {
            "rows_excluded": int(len(overlap_frame)),
            "unique_overlapping_sites": int(overlap_frame["site"].nunique()),
            "benign_rows_excluded": int((overlap_frame["target"] == 0).sum()),
            "phishing_rows_excluded": int((overlap_frame["target"] == 1).sum()),
        },
        "decision_threshold": threshold,
        "release_gate_checks": checks,
        "release_gate_candidate_passed": candidate_passed,
        "automatic_production_enablement": False,
        "manual_review_required": True,
        "release_gate_note": (
            "This report does not change the model artifact or enable live inference. "
            "Review source provenance, label quality, collection dates, error samples, "
            "development-overlap exclusions, and these metrics before setting both "
            "production approval environment variables."
        ),
    }

    Path(args.output).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
