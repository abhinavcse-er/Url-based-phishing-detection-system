import ipaddress
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import tldextract
import url_features  # Required so joblib can resolve the v4 feature-transformer functions.
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("phishguard")

app = FastAPI(title="PhishGuard URL Analysis API", version="3.4.0")

# Setting ENABLE_ML_INFERENCE alone is not sufficient. Live inference also
# requires an explicit operator approval after an independent external test.
ML_INFERENCE_REQUESTED = os.getenv("ENABLE_ML_INFERENCE", "false").strip().lower() in {
    "1", "true", "yes", "on"
}
ML_EXTERNAL_VALIDATION_APPROVED = os.getenv(
    "ML_EXTERNAL_VALIDATION_APPROVED", "false"
).strip().lower() in {"1", "true", "yes", "on"}
ML_INFERENCE_ENABLED = (
    ML_INFERENCE_REQUESTED and ML_EXTERNAL_VALIDATION_APPROVED
)

DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

configured_origins = [
    item.strip()
    for item in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if item.strip()
]
required_origins = [
    "https://detectphishing.netlify.app",
    "https://abhinavcse-er.github.io",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]
origins = list(dict.fromkeys(required_origins + configured_origins))
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

MODEL_PATH = Path(os.getenv("MODEL_PATH", "models/url_phishing_model.joblib"))
ML_MODEL = None
ML_METADATA = {}

try:
    if MODEL_PATH.is_file():
        saved_model = joblib.load(MODEL_PATH)
        ML_MODEL = saved_model.get("pipeline")
        ML_METADATA = saved_model.get("metadata", {})

        if ML_MODEL is None:
            raise ValueError("Model artifact does not contain a pipeline.")
        if (
            ML_METADATA.get("model_version") != 4
            or ML_METADATA.get("feature_schema_version") != 1
            or not ML_METADATA.get("test_metrics")
            or not ML_METADATA.get("calibration_metrics")
            or not ML_METADATA.get("decision_threshold")
            or ML_METADATA.get("release_gate", {}).get("passed") is not False
        ):
            raise ValueError(
                "Model artifact is not a complete v4 candidate or its release-gate "
                "metadata is unexpected. Rebuild it using train_model.py."
            )

        logger.info(
            "PhishGuard ML v4 candidate loaded: %s",
            ML_METADATA.get("selected_model", "unknown"),
        )
    else:
        logger.warning(
            "ML model artifact not found at %s; ML assessment is unavailable.",
            MODEL_PATH,
        )
except Exception:
    logger.exception("Could not load ML model; heuristic analysis will remain available.")
    ML_MODEL = None
    ML_METADATA = {}


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        candidate = value if "://" in value else "https://" + value
        parsed = urlsplit(candidate)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Enter a valid http or https URL.")
        if parsed.username or parsed.password:
            raise ValueError("Enter a valid URL without embedded credentials.")
        try:
            parsed.port
        except ValueError:
            raise ValueError("The URL contains an invalid port.")
        return candidate


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)


SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "country", "gq", "ml", "cf",
    "tk", "work", "loan",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly",
    "rb.gy", "buff.ly",
}
BRANDS = {
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "instagram", "facebook", "bank",
}

# Exact legitimate registrable domains for the brands the heuristic checks.
# This is not a blanket allowlist: only an exact registrable-domain match counts.
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.me"},
    "google": {"google.com", "google.co.uk", "google.co.in"},
    "apple": {"apple.com"},
    "microsoft": {"microsoft.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
}
SUSPICIOUS_HOST_WORDS = {
    "login", "signin", "signon", "verify", "verification", "secure",
    "password", "account", "update", "wallet", "billing", "confirm",
    "support", "auth", "recover", "unlock", "webscr",
}


def tokenize(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (value or "").lower()))


def registered_domain_for(host: str) -> tuple[str, str]:
    extracted = DOMAIN_EXTRACTOR(host)
    registered = extracted.top_domain_under_public_suffix or host
    return registered.lower(), extracted.subdomain.lower()


def analyze(url: str) -> dict:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    registered_domain, subdomain = registered_domain_for(host)
    labels = host.split(".")
    host_tokens = tokenize(host)
    path_query = (parsed.path + "?" + parsed.query).lower()
    path_tokens = tokenize(path_query)

    hostname_brands = {
        brand for brand in BRAND_DOMAINS
        if any(brand in tokenize(label) for label in labels)
    }
    path_brands = {brand for brand in BRAND_DOMAINS if brand in path_tokens}
    spoofed_host_brands = {
        brand for brand in hostname_brands
        if registered_domain not in BRAND_DOMAINS[brand]
    }
    spoofed_path_brands = {
        brand for brand in path_brands
        if registered_domain not in BRAND_DOMAINS[brand]
    }
    spoofed_brands = spoofed_host_brands | spoofed_path_brands

    suspicious_host_words = sorted(host_tokens & SUSPICIOUS_HOST_WORDS)
    suspicious_path_words = sorted(path_tokens & SUSPICIOUS_HOST_WORDS)
    suspicious_words = sorted(set(suspicious_host_words + suspicious_path_words))
    suffix = labels[-1] if len(labels) > 1 else ""

    features = {
        "uses_https": parsed.scheme == "https",
        "is_ip_host": is_ip,
        "suspicious_tld": suffix in SUSPICIOUS_TLDS,
        "uses_shortener": host in SHORTENERS,
        "has_at_symbol": "@" in url,
        "has_hyphen": any("-" in label for label in labels),
        "url_length": len(url),
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_digits_host": sum(char.isdigit() for char in host),
        "contains_punycode": "xn--" in host,
        "brand_mismatch": bool(spoofed_brands),
        "brand_impersonation": bool(spoofed_host_brands),
        "keyword_in_host_or_path": bool(suspicious_words),
        "suspicious_host_words": suspicious_host_words,
        "suspicious_path_words": suspicious_path_words,
        "has_many_subdomains": len([item for item in subdomain.split(".") if item]) >= 3,
    }

    checks = [
        (8, "URL does not use HTTPS", not features["uses_https"]),
        (24, "Host is an IP address", is_ip),
        (18, "Suspicious top-level domain", features["suspicious_tld"]),
        (10, "Known URL shortener", features["uses_shortener"]),
        (
            35,
            "A known brand appears in the hostname or URL path but not in its legitimate registrable domain",
            features["brand_mismatch"],
        ),
        (8, "Unusually many subdomains", features["has_many_subdomains"]),
        (12, "Punycode hostname", features["contains_punycode"]),
        (6, "Long URL", len(url) > 120),
        (5, "Many digits in hostname", features["num_digits_host"] >= 5),
        (
            8,
            "Login, verification, account or security wording in hostname/path",
            features["keyword_in_host_or_path"],
        ),
        (4, "Hyphenated hostname labels", features["has_hyphen"]),
        (10, "At-sign present in URL", features["has_at_symbol"]),
    ]
    triggered = [
        {"points": points, "reason": reason}
        for points, reason, condition in checks
        if condition
    ]
    risk_score = min(100, sum(item["points"] for item in triggered))
    label = (
        "likely_phishing" if risk_score >= 60
        else "suspicious" if risk_score >= 25
        else "probably_safe"
    )

    return {
        "details": {
            "parsed_url": url,
            "domain": registered_domain,
            "hostname": host,
            "subdomain": subdomain,
            "features": features,
            "matched_brand_indicators": sorted(spoofed_brands),
        },
        "verdict": {
            "risk_score": risk_score,
            "label": label,
            "reasons": triggered,
        },
    }


def assess_with_ml(url: str) -> dict:
    if ML_MODEL is None:
        return {
            "ml_status": "unavailable",
            "ml_reason": "No compatible v4 model artifact is loaded.",
            "ml_result": None,
        }

    if not ML_INFERENCE_ENABLED:
        if ML_INFERENCE_REQUESTED and not ML_EXTERNAL_VALIDATION_APPROVED:
            reason = (
                "ML inference was requested, but independent external validation "
                "has not been operator-approved. The model does not influence this scan."
            )
        else:
            reason = (
                "The v4 model candidate is loaded for diagnostics, but live inference "
                "remains disabled pending independent external validation. "
                "The scanner uses explainable URL heuristics only."
            )
        return {
            "ml_status": "disabled",
            "ml_reason": reason,
            "ml_result": None,
        }

    try:
        classes = list(ML_MODEL.classes_)
        if 1 not in classes:
            raise ValueError("The loaded model has no phishing class.")
        phishing_index = classes.index(1)
        phishing_score = float(ML_MODEL.predict_proba([url])[0][phishing_index])
        threshold = float(ML_METADATA["decision_threshold"])
        is_phishing_like = phishing_score >= threshold

        return {
            "ml_status": "used",
            "ml_result": {
                "ml_label": "1" if is_phishing_like else "0",
                "ml_label_text": (
                    "Phishing-like URL pattern"
                    if is_phishing_like
                    else "No strong ML phishing signal"
                ),
                "selected_model": ML_METADATA.get("selected_model"),
                "decision_threshold": threshold,
                "interpretation": (
                    "This is a model signal, not a real-world probability or a safety guarantee."
                ),
            },
        }
    except Exception:
        logger.exception("ML prediction failed; returning heuristic result only.")
        return {
            "ml_status": "error",
            "ml_reason": "Prediction failed; heuristic analysis is still available.",
            "ml_result": None,
        }


def ml_inference_gate(
    inference_requested: bool,
    external_validation_approved: bool,
) -> bool:
    """Require both explicit runtime opt-in and independent-validation approval."""
    return bool(inference_requested and external_validation_approved)


@app.get("/")
def root():
    return {
        "name": "PhishGuard API",
        "status": "ok",
        "docs": "/docs",
        "ml_model": "loaded" if ML_MODEL is not None else "unavailable",
        "ml_model_version": ML_METADATA.get("model_version") if ML_MODEL is not None else None,
        "selected_model": ML_METADATA.get("selected_model") if ML_MODEL is not None else None,
        "ml_inference_status": (
            "enabled" if ML_MODEL is not None and ML_INFERENCE_ENABLED
            else "disabled_pending_external_validation" if ML_MODEL is not None
            else "unavailable"
        ),
    }


@app.get("/health")
def health():
    test_metrics = ML_METADATA.get("test_metrics", {})
    calibration_metrics = ML_METADATA.get("calibration_metrics", {})
    evaluation_available = bool(test_metrics and calibration_metrics)

    return {
        "status": "healthy",
        "ml_model": "loaded" if ML_MODEL is not None else "unavailable",
        "ml_model_version": ML_METADATA.get("model_version") if ML_MODEL is not None else None,
        "selected_model": ML_METADATA.get("selected_model") if ML_MODEL is not None else None,
        "ml_inference_status": (
            "enabled" if ML_MODEL is not None and ML_INFERENCE_ENABLED
            else "disabled_pending_external_validation" if ML_MODEL is not None
            else "unavailable"
        ),
        "ml_evaluation_status": (
            "available" if evaluation_available
            else "retrain_required" if ML_MODEL is not None
            else "unavailable"
        ),
        "ml_release_status": (
            "operator_approved" if ML_MODEL is not None and ML_INFERENCE_ENABLED
            else ML_METADATA.get("release_gate", {}).get(
                "status", "disabled_pending_external_validation"
            ) if ML_MODEL is not None
            else "model_unavailable"
        ),
        "ml_metrics": {
            "accuracy": test_metrics.get("accuracy"),
            "balanced_accuracy": test_metrics.get("balanced_accuracy"),
            "precision_phishing": test_metrics.get("precision_phishing"),
            "recall_phishing": test_metrics.get("recall_phishing"),
            "f1_phishing": test_metrics.get("f1_phishing"),
            "mcc": test_metrics.get("mcc"),
            "roc_auc": test_metrics.get("roc_auc"),
            "average_precision": test_metrics.get("average_precision"),
            "false_positive_rate": test_metrics.get("false_positive_rate"),
            "false_negative_rate": test_metrics.get("false_negative_rate"),
            "training_sample_rows": ML_METADATA.get("training_sample_rows"),
            "training_rows": ML_METADATA.get("training_rows"),
            "calibration_rows": ML_METADATA.get("calibration_rows"),
            "validation_rows": ML_METADATA.get("validation_rows"),
            "test_rows": ML_METADATA.get("test_rows"),
            "training_unique_hosts": ML_METADATA.get("training_unique_hosts"),
            "calibration_unique_hosts": ML_METADATA.get("calibration_unique_hosts"),
            "validation_unique_hosts": ML_METADATA.get("validation_unique_hosts"),
            "test_unique_hosts": ML_METADATA.get("test_unique_hosts"),
            "decision_threshold": ML_METADATA.get("decision_threshold"),
            "validation_threshold_metrics": ML_METADATA.get(
                "threshold_selection", {}
            ).get("selected_validation_metrics"),
        } if ML_MODEL is not None else None,
        "ml_calibration": calibration_metrics if ML_MODEL is not None else None,
        "ml_release_gate": (
            ML_METADATA.get("release_gate") if ML_MODEL is not None else None
        ),
        "ml_evaluation_note": (
            "The grouped test scores are benchmark diagnostics only. They are not real-world "
            "phishing probabilities. Live inference requires separate external validation "
            "and explicit operator approval."
            if ML_MODEL is not None else None
        ),
    }


@app.post("/api/scan")
def scan(body: ScanRequest):
    return {
        "ok": True,
        "input": body.url,
        **analyze(body.url),
        **assess_with_ml(body.url),
    }


@app.post("/api/batch_scan")
def batch_scan(body: BatchScanRequest):
    results = []
    for raw_url in body.urls:
        try:
            item = ScanRequest(url=raw_url)
            results.append({
                "input": item.url,
                **analyze(item.url),
                **assess_with_ml(item.url),
            })
        except Exception as exc:
            results.append({"input": raw_url, "error": str(exc)})
    return {"ok": True, "results": results}
