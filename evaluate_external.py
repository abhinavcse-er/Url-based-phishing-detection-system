"""Evaluate PhishGuard v4 on independent labelled URLs without visiting them.

For the pinned PhreshPhish export, pass the matching PhishFusion source CSV.
The evaluator reproduces the documented URL-overlap exclusion, then reports
URL-disjoint, PhishFusion-domain-disjoint, and additionally development-domain-
disjoint performance. It never enables production inference.
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
import tldextract

from train_model import (
    classification_metrics,
    hash_site,
    hostname_group,
    positive_class_probabilities,
)


PRIVATE_DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate a PhishGuard v4 model on independent labelled URLs."
    )
    parser.add_argument("--dataset", required=True, help="Independent labelled CSV or CSV.GZ.")
    parser.add_argument("--url-column", default="URL")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--phishing-label", default="0")
    parser.add_argument("--benign-label", default="1")
    parser.add_argument(
        "--source-training-csv",
        default=None,
        help="Source training CSV to remove exact/normalized URL and registered-domain overlap.",
    )
    parser.add_argument("--model", default="models/url_phishing_model.joblib")
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


def normalized_http_url(value: str) -> tuple[str, str, str] | None:
    """Return overlap key, trainer eTLD+1, and private-suffix-aware eTLD+1.

    This normalization is only for exclusion checks. Model predictions always
    receive the original, unchanged URL string.
    """
    try:
        text = html.unescape(str(value).strip())
        parsed = urlsplit(text)
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
        trainer_site = hostname_group(text)
        private_extract = PRIVATE_DOMAIN_EXTRACTOR(hostname)
        private_site = (
            private_extract.top_domain_under_public_suffix or hostname
        ).lower()
        return normalized, trainer_site, private_site
    except (TypeError, ValueError):
        return None


def load_phishfusion_source(path: Path) -> tuple[set[str], set[str], dict]:
    """Load UTF-8 and Latin-1 interpretations used in the upstream overlap audit."""
    normalized_urls: set[str] = set()
    registered_domains: set[str] = set()
    row_counts = {}

    for encoding in ("utf-8", "latin-1"):
        source = pd.read_csv(
            path,
            usecols=["url"],
            encoding=encoding,
            keep_default_na=False,
        )
        row_counts[encoding] = int(len(source))
        for value in source["url"].astype(str):
            parsed = normalized_http_url(value)
            if parsed is not None:
                normalized_urls.add(parsed[0])
                registered_domains.add(parsed[2])

    diagnostics = {
        "file": path.name,
        "sha256": sha256_file(path),
        "rows_read_by_encoding": row_counts,
        "unique_normalized_urls": int(len(normalized_urls)),
        "unique_registered_domains_private_suffix_aware": int(len(registered_domains)),
        "overlap_normalization": (
            "HTML entity decode; trim surrounding whitespace; lowercase hostname; "
            "ignore scheme and fragment; retain explicit port and path/query; "
            "use / for an empty path; compare UTF-8 and Latin-1 source interpretations"
        ),
    }
    return normalized_urls, registered_domains, diagnostics


def load_external_dataset(
    dataset_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
    benign_label: str,
) -> tuple[pd.DataFrame, dict]:
    """Validate hashes, HTTP(S) URLs, labels, conflicts, and normalized duplicates."""
    frame = pd.read_csv(
        dataset_path,
        compression="infer",
        keep_default_na=False,
    )
    missing = {url_column, label_column} - set(frame.columns)
    if missing:
        raise ValueError(f"External CSV is missing required columns: {sorted(missing)}")

    frame = frame.copy()
    frame["url"] = frame[url_column].astype(str).str.strip()
    frame["source_label"] = frame[label_column].astype(str).str.strip().str.lower()
    frame["calculated_url_sha256"] = frame["url"].map(
        lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    )

    hash_checks = {}
    if "url_sha256" in frame.columns:
        supplied = frame["url_sha256"].astype(str).str.lower().reset_index(drop=True)
        calculated = frame["calculated_url_sha256"].astype(str).str.lower().reset_index(drop=True)
        hash_checks["url_sha256_rows"] = int((supplied == calculated).sum())
        if not (supplied == calculated).all():
            raise ValueError("One or more URL values do not match the CSV's url_sha256 column.")

    if "source_id" in frame.columns:
        supplied = frame["source_id"].astype(str).str.lower().reset_index(drop=True)
        calculated = frame["calculated_url_sha256"].astype(str).str.lower().reset_index(drop=True)
        hash_checks["source_id_rows"] = int((supplied == calculated).sum())
        if not (supplied == calculated).all():
            raise ValueError("One or more URL values do not match the CSV's source_id column.")

    input_rows = len(frame)
    allowed_labels = {phishing_label.lower(), benign_label.lower()}
    label_mask = frame["source_label"].isin(allowed_labels)
    unknown_label_rows = int((~label_mask).sum())
    frame = frame.loc[label_mask].copy()

    length_mask = frame["url"].str.len().between(4, 2048)
    overlength_rows = int((~length_mask).sum())
    frame = frame.loc[length_mask].copy()

    parsed = frame["url"].map(normalized_http_url)
    valid_mask = parsed.notna()
    invalid_url_rows = int((~valid_mask).sum())
    frame = frame.loc[valid_mask].copy()
    parsed = parsed.loc[valid_mask]

    frame["normalized_url"] = parsed.map(lambda item: item[0])
    frame["site"] = parsed.map(lambda item: item[1])
    frame["private_site"] = parsed.map(lambda item: item[2])

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
        "rows_after_basic_cleaning_before_source_overlap": int(len(frame)),
        "class_counts_before_source_overlap": {
            "benign": int((frame["target"] == 0).sum()),
            "phishing": int((frame["target"] == 1).sum()),
        },
        "unique_registered_domains_before_source_overlap": int(frame["site"].nunique()),
        "url_hash_integrity": hash_checks,
    }
    return frame.reset_index(drop=True), diagnostics


def metrics_for_frame(pipeline, frame: pd.DataFrame, threshold: float):
    if frame is None or frame.empty or frame["target"].nunique() != 2:
        return None
    scores = positive_class_probabilities(pipeline, frame["url"].tolist())
    return classification_metrics(frame["target"], scores, threshold)


def class_counts(frame: pd.DataFrame | None) -> dict:
    if frame is None or frame.empty:
        return {"benign": 0, "phishing": 0}
    return {
        "benign": int((frame["target"] == 0).sum()),
        "phishing": int((frame["target"] == 1).sum()),
    }


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
    source_path = Path(args.source_training_csv) if args.source_training_csv else None
    if not dataset_path.is_file():
        raise FileNotFoundError(f"External dataset not found: {dataset_path}")
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {model_path}")
    if source_path is not None and not source_path.is_file():
        raise FileNotFoundError(f"Source training CSV not found: {source_path}")

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

    source_diagnostics = None
    source_urls: set[str] = set()
    source_domains: set[str] = set()
    if source_path is not None:
        source_urls, source_domains, source_diagnostics = load_phishfusion_source(
            source_path
        )
        source_overlap_mask = frame["normalized_url"].isin(source_urls)
        source_overlap_frame = frame.loc[source_overlap_mask].copy()
        url_disjoint_frame = frame.loc[~source_overlap_mask].copy()
    else:
        source_overlap_frame = frame.iloc[0:0].copy()
        url_disjoint_frame = frame.copy()

    if url_disjoint_frame["target"].nunique() != 2:
        raise RuntimeError("The URL-disjoint external cohort does not contain both classes.")

    if source_path is not None:
        source_domain_overlap_mask = url_disjoint_frame["private_site"].isin(source_domains)
        source_domain_overlap_frame = url_disjoint_frame.loc[source_domain_overlap_mask].copy()
        source_domain_disjoint_frame = url_disjoint_frame.loc[
            ~source_domain_overlap_mask
        ].copy()
    else:
        source_domain_overlap_frame = None
        source_domain_disjoint_frame = None

    development_hashes = set(metadata.get("development_site_hashes", []))
    if not development_hashes:
        raise RuntimeError(
            "Model artifact has no development-site manifest; retrain with the v4 trainer."
        )

    if source_domain_disjoint_frame is not None:
        development_overlap_mask = source_domain_disjoint_frame["site_hash"].isin(
            development_hashes
        )
        development_overlap_frame = source_domain_disjoint_frame.loc[
            development_overlap_mask
        ].copy()
        strict_frame = source_domain_disjoint_frame.loc[
            ~development_overlap_mask
        ].copy()
    else:
        development_overlap_mask = url_disjoint_frame["site_hash"].isin(
            development_hashes
        )
        development_overlap_frame = url_disjoint_frame.loc[
            development_overlap_mask
        ].copy()
        strict_frame = url_disjoint_frame.loc[~development_overlap_mask].copy()

    threshold = float(metadata["decision_threshold"])
    url_disjoint_metrics = metrics_for_frame(pipeline, url_disjoint_frame, threshold)
    source_domain_metrics = (
        metrics_for_frame(pipeline, source_domain_disjoint_frame, threshold)
        if source_domain_disjoint_frame is not None else None
    )
    strict_metrics = metrics_for_frame(pipeline, strict_frame, threshold)

    strict_counts = class_counts(strict_frame)
    enough_data = all(
        strict_counts[label] >= args.minimum_per_class
        for label in ("benign", "phishing")
    )
    source_filter_applied = source_path is not None
    no_source_domain_overlap = (
        source_domain_disjoint_frame is not None
        and not bool(strict_frame["private_site"].isin(source_domains).any())
    )
    no_development_site_overlap = not bool(
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
        "phishfusion_url_overlap_filter_applied": source_filter_applied,
        "phishfusion_registered_domain_overlap_excluded": no_source_domain_overlap,
        "development_sites_excluded_from_strict_evaluation": no_development_site_overlap,
        "minimum_per_class_met_on_strict_sites": enough_data,
        "false_positive_rate_within_limit": fpr_pass,
        "phishing_recall_meets_minimum": recall_pass,
    }

    report = {
        "report_type": "independent_external_url_model_evaluation",
        "model_version": metadata.get("model_version"),
        "selected_model": metadata.get("selected_model"),
        "dataset_file": dataset_path.name,
        "dataset_sha256": sha256_file(dataset_path),
        "source_training_corpus": source_diagnostics,
        "cleaning": cleaning,
        "phishfusion_url_overlap_excluded": {
            "rows": int(len(source_overlap_frame)),
            "class_counts": class_counts(source_overlap_frame),
        },
        "url_disjoint_external_evaluation": {
            "rows": int(len(url_disjoint_frame)),
            "unique_sites": int(url_disjoint_frame["site"].nunique()),
            "class_counts": class_counts(url_disjoint_frame),
            "metrics": url_disjoint_metrics,
        },
        "phishfusion_source_domain_overlap_excluded": {
            "rows": (
                int(len(source_domain_overlap_frame))
                if source_domain_overlap_frame is not None else None
            ),
            "class_counts": (
                class_counts(source_domain_overlap_frame)
                if source_domain_overlap_frame is not None else None
            ),
        },
        "source_domain_disjoint_external_evaluation": {
            "rows": (
                int(len(source_domain_disjoint_frame))
                if source_domain_disjoint_frame is not None else None
            ),
            "unique_domains": (
                int(source_domain_disjoint_frame["private_site"].nunique())
                if source_domain_disjoint_frame is not None else None
            ),
            "class_counts": (
                class_counts(source_domain_disjoint_frame)
                if source_domain_disjoint_frame is not None else None
            ),
            "metrics": source_domain_metrics,
        },
        "development_site_overlap_excluded_after_source_domain_filter": {
            "rows": int(len(development_overlap_frame)),
            "class_counts": class_counts(development_overlap_frame),
            "unique_sites": int(development_overlap_frame["site"].nunique()),
        },
        "strict_external_evaluation": {
            "description": (
                "PhreshPhish rows excluding PhishFusion normalized-URL overlap, "
                "PhishFusion registered-domain overlap, and every PhishGuard v4 "
                "development registered-domain hash"
            ),
            "rows": int(len(strict_frame)),
            "unique_sites": int(strict_frame["site"].nunique()),
            "class_counts": strict_counts,
            "metrics": strict_metrics,
        },
        "decision_threshold": threshold,
        "release_gate_checks": checks,
        "release_gate_candidate_passed": all(checks.values()),
        "automatic_production_enablement": False,
        "manual_review_required": True,
        "release_gate_note": (
            "This report does not change the model artifact or enable live inference. "
            "The cohort is a curated research benchmark, not a random sample of consumer "
            "browsing. Review provenance, dates, label quality, overlap counts, class "
            "errors, and false-positive examples before any production approval."
        ),
    }

    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
