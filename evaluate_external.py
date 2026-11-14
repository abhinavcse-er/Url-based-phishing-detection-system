"""Evaluate a trained PhishGuard v4 model on a separately sourced labelled CSV.

The script never visits submitted URLs. It reports performance on the full
external set and on registrable sites absent from every development partition.
It does not enable live inference; production approval remains a manual decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

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
    parser.add_argument("--dataset", required=True, help="Path to an independently sourced CSV.")
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


def main() -> None:
    args = parse_args()
    if args.minimum_per_class < 1:
        raise ValueError("--minimum-per-class must be at least 1.")
    if not 0.0 <= args.max_fpr <= 1.0:
        raise ValueError("--max-fpr must be between 0 and 1.")
    if not 0.0 <= args.min_recall <= 1.0:
        raise ValueError("--min-recall must be between 0 and 1.")

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

    if args.phishing_label == args.benign_label:
        raise ValueError("Phishing and benign label values must be different.")

    frame = pd.read_csv(
        dataset_path,
        usecols=[args.url_column, args.label_column],
    )
    frame = frame.rename(columns={
        args.url_column: "url",
        args.label_column: "source_label",
    })
    frame["url"] = frame["url"].astype(str).str.strip()
    frame["source_label"] = frame["source_label"].astype(str).str.strip()
    frame = frame[frame["url"].str.len().between(4, 2048)]
    frame = frame[
        frame["source_label"].isin([args.phishing_label, args.benign_label])
    ].drop_duplicates(subset=["url"]).reset_index(drop=True)

    if frame.empty or frame["source_label"].nunique() != 2:
        raise RuntimeError(
            "External CSV must contain valid URL rows for both the phishing and benign labels."
        )

    frame["target"] = (
        frame["source_label"] == args.phishing_label
    ).astype(int)
    frame["site"] = frame["url"].map(hostname_group)
    frame["site_hash"] = frame["site"].map(hash_site)

    development_hashes = set(metadata.get("development_site_hashes", []))
    if not development_hashes:
        raise RuntimeError(
            "Model artifact has no development-site manifest; retrain with the v4 trainer."
        )

    overlap_hashes = set(frame["site_hash"]) & development_hashes
    disjoint_frame = frame[~frame["site_hash"].isin(development_hashes)].copy()

    threshold = float(metadata["decision_threshold"])
    all_scores = positive_class_probabilities(pipeline, frame["url"])
    all_metrics = classification_metrics(frame["target"], all_scores, threshold)

    if disjoint_frame["target"].nunique() == 2:
        disjoint_scores = positive_class_probabilities(
            pipeline, disjoint_frame["url"]
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
    no_development_site_overlap = len(overlap_hashes) == 0
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
        "no_development_site_overlap": no_development_site_overlap,
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
        "dataset_rows_after_cleaning": int(len(frame)),
        "full_external_metrics": all_metrics,
        "site_disjoint_external_evaluation": {
            "rows": int(len(disjoint_frame)),
            "unique_sites": int(disjoint_frame["site"].nunique()),
            "class_counts": disjoint_counts,
            "metrics": disjoint_metrics,
        },
        "development_overlap": {
            "overlapping_sites": int(len(overlap_hashes)),
            "external_unique_sites": int(frame["site"].nunique()),
            "overlap_free_external_sites": int(disjoint_frame["site"].nunique()),
        },
        "decision_threshold": threshold,
        "release_gate_checks": checks,
        "release_gate_candidate_passed": candidate_passed,
        "automatic_production_enablement": False,
        "manual_review_required": True,
        "release_gate_note": (
            "This report does not change the model artifact or enable live inference. "
            "Review source provenance, label quality, collection dates, error samples, "
            "and these metrics before setting both production approval environment variables."
        ),
    }

    Path(args.output).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
