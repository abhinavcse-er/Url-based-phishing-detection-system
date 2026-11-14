"""Evaluate PhishGuard V5 on untouched CSVs without visiting submitted URLs.

Every development corpus supplied on the command line is excluded by normalized
URL and private-suffix-aware registered-domain overlap. The V5 model artifact
also carries hashes for every registered domain in all development corpora.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from evaluate_external import (
    class_counts,
    load_external_dataset,
    load_phishfusion_source,
    metrics_for_frame,
    sha256_file,
)
from train_model_v5 import hostname_group


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate a V5 model on independently sourced labelled URLs."
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="phishing")
    parser.add_argument("--phishing-label", default="1")
    parser.add_argument("--benign-label", default="0")
    parser.add_argument(
        "--source-training-csv",
        action="append",
        required=True,
        help="A V5 development source CSV; repeat once for every training source.",
    )
    parser.add_argument("--model", default="models/url_phishing_model.joblib")
    parser.add_argument("--output", default="v5_external_validation_report.json")
    parser.add_argument("--minimum-per-class", type=int, default=500)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-recall", type=float, default=0.80)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.minimum_per_class < 1:
        raise ValueError("--minimum-per-class must be at least 1.")
    if not 0.0 <= args.max_fpr <= 1.0:
        raise ValueError("--max-fpr must be between 0 and 1.")
    if not 0.0 <= args.min_recall <= 1.0:
        raise ValueError("--min-recall must be between 0 and 1.")
    if args.phishing_label == args.benign_label:
        raise ValueError("Phishing and benign labels must be different.")

    dataset_path = Path(args.dataset)
    source_paths = [Path(value) for value in args.source_training_csv]
    model_path = Path(args.model)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"External dataset not found: {dataset_path}")
    if not model_path.is_file():
        raise FileNotFoundError(f"V5 model not found: {model_path}")
    for path in source_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Development source CSV not found: {path}")

    saved_model = joblib.load(model_path)
    metadata = saved_model.get("metadata", {})
    pipeline = saved_model.get("pipeline")
    if pipeline is None or metadata.get("model_version") != 5:
        raise RuntimeError("The supplied artifact is not a compatible PhishGuard V5 model.")
    development_hashes = set(metadata.get("development_site_hashes", []))
    if not development_hashes:
        raise RuntimeError("V5 artifact has no full-development-domain manifest.")

    frame, cleaning = load_external_dataset(
        dataset_path,
        args.url_column,
        args.label_column,
        args.phishing_label,
        args.benign_label,
        domain_group_fn=hostname_group,
    )

    all_source_urls: set[str] = set()
    all_source_domains: set[str] = set()
    source_reports = []
    for path in source_paths:
        source_urls, source_domains, diagnostics = load_phishfusion_source(path)
        all_source_urls.update(source_urls)
        all_source_domains.update(source_domains)
        source_reports.append(diagnostics)

    source_url_overlap_mask = frame["normalized_url"].isin(all_source_urls)
    source_url_overlap = frame.loc[source_url_overlap_mask].copy()
    url_disjoint = frame.loc[~source_url_overlap_mask].copy()
    if url_disjoint["target"].nunique() != 2:
        raise RuntimeError("URL-disjoint external cohort does not contain both classes.")

    source_domain_overlap_mask = url_disjoint["private_site"].isin(
        all_source_domains
    )
    source_domain_overlap = url_disjoint.loc[source_domain_overlap_mask].copy()
    source_domain_disjoint = url_disjoint.loc[
        ~source_domain_overlap_mask
    ].copy()

    development_overlap_mask = source_domain_disjoint["site_hash"].isin(
        development_hashes
    )
    development_overlap = source_domain_disjoint.loc[
        development_overlap_mask
    ].copy()
    strict_frame = source_domain_disjoint.loc[
        ~development_overlap_mask
    ].copy()

    threshold = float(metadata["decision_threshold"])
    full_metrics = metrics_for_frame(pipeline, url_disjoint, threshold)
    source_domain_metrics = metrics_for_frame(
        pipeline, source_domain_disjoint, threshold
    )
    strict_metrics = metrics_for_frame(pipeline, strict_frame, threshold)
    strict_counts = class_counts(strict_frame)

    enough_data = all(
        strict_counts[label] >= args.minimum_per_class
        for label in ("benign", "phishing")
    )
    no_source_url_overlap = not bool(
        strict_frame["normalized_url"].isin(all_source_urls).any()
    )
    no_source_domain_overlap = not bool(
        strict_frame["private_site"].isin(all_source_domains).any()
    )
    no_development_domain_overlap = not bool(
        strict_frame["site_hash"].isin(development_hashes).any()
    )
    fpr_pass = (
        strict_metrics is not None
        and strict_metrics["false_positive_rate"] <= args.max_fpr
    )
    recall_pass = (
        strict_metrics is not None
        and strict_metrics["recall_phishing"] >= args.min_recall
    )

    checks = {
        "all_development_source_url_overlaps_excluded": no_source_url_overlap,
        "all_development_source_domains_excluded": no_source_domain_overlap,
        "all_v5_development_domains_excluded": no_development_domain_overlap,
        "minimum_per_class_met_on_strict_cohort": enough_data,
        "false_positive_rate_within_limit": fpr_pass,
        "phishing_recall_meets_minimum": recall_pass,
    }

    report = {
        "report_type": "phishguard_v5_independent_external_evaluation",
        "model_version": 5,
        "selected_model": metadata.get("selected_model"),
        "model_source_commit": metadata.get("source_commit"),
        "dataset_file": dataset_path.name,
        "dataset_sha256": sha256_file(dataset_path),
        "development_sources": {
            "upstream_repository": metadata.get("source_manifest", {}).get(
                "upstream_repository"
            ),
            "upstream_commit": metadata.get("source_manifest", {}).get(
                "upstream_commit"
            ),
            "source_corpora": source_reports,
            "development_unique_sites": metadata.get("development_unique_sites"),
        },
        "cleaning": cleaning,
        "development_source_url_overlap_excluded": {
            "rows": int(len(source_url_overlap)),
            "class_counts": class_counts(source_url_overlap),
        },
        "url_disjoint_external_evaluation": {
            "rows": int(len(url_disjoint)),
            "unique_sites": int(url_disjoint["private_site"].nunique()),
            "class_counts": class_counts(url_disjoint),
            "metrics": full_metrics,
        },
        "development_source_domain_overlap_excluded": {
            "rows": int(len(source_domain_overlap)),
            "class_counts": class_counts(source_domain_overlap),
        },
        "source_domain_disjoint_external_evaluation": {
            "rows": int(len(source_domain_disjoint)),
            "unique_sites": int(source_domain_disjoint["private_site"].nunique()),
            "class_counts": class_counts(source_domain_disjoint),
            "metrics": source_domain_metrics,
        },
        "v5_development_domain_overlap_excluded": {
            "rows": int(len(development_overlap)),
            "class_counts": class_counts(development_overlap),
            "unique_sites": int(development_overlap["private_site"].nunique()),
        },
        "strict_external_evaluation": {
            "description": (
                "External URLs after invalid/duplicate/conflict cleanup, exclusion "
                "of normalized URL and private-suffix-aware registered-domain "
                "overlap with all three V5 development corpora, and exclusion of "
                "every V5 development domain recorded in the model artifact."
            ),
            "rows": int(len(strict_frame)),
            "unique_sites": int(strict_frame["private_site"].nunique()),
            "class_counts": strict_counts,
            "decision_threshold": threshold,
            "metrics": strict_metrics,
        },
        "release_gate": {
            "maximum_false_positive_rate": args.max_fpr,
            "minimum_phishing_recall": args.min_recall,
            "checks": checks,
            "candidate_passed": all(checks.values()),
        },
        "automatic_production_enablement": False,
        "manual_review_required": True,
        "decision": (
            "CANDIDATE_PASSES_METRIC_GATES_REVIEW_REQUIRED"
            if all(checks.values())
            else "FAILED_DO_NOT_ENABLE"
        ),
        "notes": [
            "The external cohort is never used for model fitting, calibration, feature selection, or threshold selection.",
            "No submitted URL is fetched, resolved, or opened.",
            "The benchmark is a curated research dataset, not a probability sample of ordinary browsing.",
            "This report never enables production inference automatically.",
        ],
    }
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
