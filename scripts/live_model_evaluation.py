#!/usr/bin/env python3
"""Probe the deployed URL classifier against independent, current URL sources.

Submitted URLs are only sent as text to the PhishGuard API. This script never
visits the phishing URLs themselves. Tranco popular domains are a proxy set,
not verified benign ground truth, so no combined accuracy is reported.
"""
import csv
import io
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

API_BASE = os.getenv(
    "PHISHING_API_BASE",
    "https://phishing-backend-2kib.onrender.com",
).rstrip("/")
OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_DOWNLOAD = "https://tranco-list.eu/download/{list_id}/500"
SAMPLE_SIZE = int(os.getenv("LIVE_EVAL_SAMPLE_SIZE", "100"))
BATCH_SIZE = 20
USER_AGENT = "PhishGuard-Live-Evaluation/1.0 (URL text classification only)"


def request_bytes(url, data=None, headers=None, timeout=90, attempts=3):
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    for attempt in range(attempts):
        request = Request(url, data=data, headers=request_headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read()
        except (HTTPError, URLError, TimeoutError) as exc:
            if attempt + 1 == attempts:
                raise RuntimeError(f"Request failed for {url.split('?')[0]}: {exc}") from exc
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("Request retries exhausted.")


def get_json(url):
    raw = request_bytes(url, headers={"Accept": "application/json"})
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Expected JSON from {url}") from exc


def post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    raw = request_bytes(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Scan API returned invalid JSON.") from exc


def host_key(url):
    try:
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        hostname = ""
    return hostname


def load_openphish_urls():
    text = request_bytes(OPENPHISH_FEED).decode("utf-8", errors="replace")
    urls = []
    seen_hosts = set()
    for line in text.splitlines():
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        host = host_key(url)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        urls.append(url)
        if len(urls) >= SAMPLE_SIZE:
            break
    if len(urls) < min(50, SAMPLE_SIZE):
        raise RuntimeError(
            f"OpenPhish feed supplied only {len(urls)} unique hosts; need at least "
            f"{min(50, SAMPLE_SIZE)} for a useful smoke benchmark."
        )
    return urls, len(text.splitlines())


def load_tranco_domains():
    list_id = request_bytes(TRANCO_ID_URL).decode("utf-8", errors="replace").strip()
    if not list_id or any(ch.isspace() for ch in list_id):
        raise RuntimeError("Could not resolve the latest Tranco list ID.")
    raw = request_bytes(TRANCO_DOWNLOAD.format(list_id=list_id))
    rows = csv.reader(io.StringIO(raw.decode("utf-8", errors="replace")))
    domains = []
    for row in rows:
        if len(row) < 2:
            continue
        domain = row[1].strip().lower().rstrip(".")
        if not domain or "." not in domain:
            continue
        domains.append(domain)
        if len(domains) >= SAMPLE_SIZE:
            break
    if len(domains) < min(50, SAMPLE_SIZE):
        raise RuntimeError(f"Tranco supplied only {len(domains)} domains.")
    return list_id, domains


def classify_urls(urls):
    predictions = []
    for start in range(0, len(urls), BATCH_SIZE):
        batch = urls[start:start + BATCH_SIZE]
        response = post_json(API_BASE + "/api/batch_scan", {"urls": batch})
        results = response.get("results")
        if not response.get("ok") or not isinstance(results, list) or len(results) != len(batch):
            raise RuntimeError("Scan API response did not match the submitted batch.")
        for item in results:
            if item.get("error") or item.get("ml_status") != "used":
                raise RuntimeError("ML prediction unavailable for one or more test URLs.")
            model_result = item.get("ml_result") or {}
            try:
                label = int(model_result["ml_label"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError("Scan API returned an invalid ML class label.") from exc
            if label not in (0, 1):
                raise RuntimeError("ML class label must be 0 (legitimate) or 1 (phishing).")
            predictions.append(label)
        time.sleep(1)
    return predictions


def main():
    health = get_json(API_BASE + "/health")
    if health.get("status") != "healthy" or health.get("ml_model") != "loaded":
        raise RuntimeError("Live API health check failed or the ML model is not loaded.")
    if health.get("ml_evaluation_status") != "available":
        raise RuntimeError("The live API does not report current model evaluation metadata.")

    phishing_urls, feed_lines = load_openphish_urls()
    tranco_id, popular_domains = load_tranco_domains()
    popular_urls = ["https://" + domain + "/" for domain in popular_domains]

    phishing_predictions = classify_urls(phishing_urls)
    popular_predictions = classify_urls(popular_urls)

    # Small, explicit control set helps distinguish a source-label issue from
    # poor generalization to short homepage URLs. These are not a benchmark.
    control_urls = [
        "https://www.google.com/",
        "https://www.microsoft.com/",
        "https://github.com/",
        "https://www.wikipedia.org/",
        "https://www.amazon.com/",
        "https://example.org/",
    ]
    control_predictions = classify_urls(control_urls)
    control_results = [
        {"host": host_key(url), "ml_label": label,
         "ml_label_text": "Phishing-like URL pattern" if label == 1
         else "Legitimate-like URL pattern"}
        for url, label in zip(control_urls, control_predictions)
    ]

    detected = sum(label == 1 for label in phishing_predictions)
    missed = len(phishing_predictions) - detected
    popular_flagged = sum(label == 1 for label in popular_predictions)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "api_base": API_BASE,
        "model_evaluation_status": health.get("ml_evaluation_status"),
        "model_metrics_from_training_benchmark": health.get("ml_metrics"),
        "sanity_controls": {
            "results": control_results,
            "note": "Small manual control list for diagnosis only; not sufficient to estimate accuracy.",
        },
        "sources": {
            "phishing": {
                "name": "OpenPhish community feed",
                "url": OPENPHISH_FEED,
                "feed_line_count": feed_lines,
                "sample_unique_hostnames": len(phishing_urls),
                "ml_phishing_predictions": detected,
                "ml_legitimate_predictions": missed,
                "feed_detection_rate": round(detected / len(phishing_predictions), 6),
                "note": "Detection rate against a live external phishing feed; feed membership is a proxy label and can contain stale or disputed entries.",
            },
            "popular_domains": {
                "name": "Tranco latest top-sites list",
                "list_id": tranco_id,
                "url": f"https://tranco-list.eu/list/{tranco_id}",
                "sample_domains": len(popular_urls),
                "ml_phishing_predictions": popular_flagged,
                "ml_legitimate_predictions": len(popular_predictions) - popular_flagged,
                "model_flag_rate": round(popular_flagged / len(popular_predictions), 6),
                "note": "Popular-domain proxy only, not a verified benign ground-truth set; this rate must not be called a false-positive rate.",
            },
        },
        "interpretation": (
            "This is a time-stamped external-feed probe, not a representative real-world accuracy estimate. "
            "No combined accuracy, precision, or false-positive rate is computed because the two sources "
            "do not provide symmetric, URL-level verified ground truth. The phishing feed and popular-domain "
            "ranking can overlap with historical training sources; exact overlap cannot be ruled out."
        ),
    }

    with open("live_model_evaluation.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print("LIVE MODEL EXTERNAL-FEED PROBE")
    print(json.dumps({
        "generated_at_utc": report["generated_at_utc"],
        "model_status": health.get("ml_evaluation_status"),
        "phishing_feed_sample": len(phishing_urls),
        "phishing_feed_detected": detected,
        "phishing_feed_detection_rate": report["sources"]["phishing"]["feed_detection_rate"],
        "tranco_list_id": tranco_id,
        "popular_domain_sample": len(popular_urls),
        "popular_domains_flagged_as_phishing": popular_flagged,
        "popular_domain_model_flag_rate": report["sources"]["popular_domains"]["model_flag_rate"],
        "sanity_controls": control_results,
        "benchmark_caution": report["interpretation"],
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"LIVE EVALUATION FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
