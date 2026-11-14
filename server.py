import ipaddress
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("phishguard")

app = FastAPI(title="PhishGuard URL Analysis API", version="3.1.0")

configured_origins = [item.strip() for item in os.getenv("ALLOWED_ORIGINS", "").split(",") if item.strip()]
required_origins = ["https://detectphishing.netlify.app", "http://localhost:5500", "http://127.0.0.1:5500"]
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
        logger.info("ML model loaded from %s", MODEL_PATH)
    else:
        logger.warning("ML model artifact not found at %s; ML assessment disabled.", MODEL_PATH)
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
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Enter a valid URL without embedded credentials.")
        try:
            parsed.port
        except ValueError:
            raise ValueError("The URL contains an invalid port.")
        return candidate


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)


SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "country", "gq", "ml", "cf", "tk", "work", "loan"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "buff.ly"}
BRANDS = {"paypal", "google", "apple", "microsoft", "amazon", "netflix", "instagram", "facebook", "bank"}


def analyze(url: str) -> dict:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    labels = host.split(".")
    suffix = labels[-1] if len(labels) > 1 else ""
    registered_hint = ".".join(labels[-2:]) if len(labels) > 1 else host
    path_query = (parsed.path + "?" + parsed.query).lower()
    host_is_brand = any(brand in registered_hint for brand in BRANDS)
    brand_in_path = any(brand in path_query for brand in BRANDS)
    features = {
        "uses_https": parsed.scheme == "https",
        "is_ip_host": is_ip,
        "suspicious_tld": suffix in SUSPICIOUS_TLDS,
        "uses_shortener": host in SHORTENERS,
        "has_at_symbol": "@" in url,
        "has_hyphen": "-" in (labels[-2] if len(labels) > 1 else host),
        "url_length": len(url),
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_digits_host": sum(char.isdigit() for char in host),
        "contains_punycode": "xn--" in host,
        "brand_mismatch": brand_in_path and not host_is_brand,
        "keyword_in_path": any(word in path_query for word in ("login", "verify", "update", "secure", "password", "account")),
        "has_many_subdomains": len(labels) >= 5,
    }
    checks = [
        (12, "URL does not use HTTPS", not features["uses_https"]),
        (22, "Host is an IP address", is_ip),
        (18, "Suspicious top-level domain", features["suspicious_tld"]),
        (12, "Known URL shortener", features["uses_shortener"]),
        (10, "Brand name appears in path/query but not the registered-domain hint", features["brand_mismatch"]),
        (10, "Unusually many subdomain labels", features["has_many_subdomains"]),
        (8, "Punycode hostname", features["contains_punycode"]),
        (6, "Long URL", len(url) > 100),
        (5, "Many digits in hostname", features["num_digits_host"] >= 5),
        (5, "Login/security-related words in path or query", features["keyword_in_path"]),
        (4, "Hyphen in domain label", features["has_hyphen"]),
        (4, "At-sign present in URL", features["has_at_symbol"]),
    ]
    triggered = [{"points": points, "reason": reason} for points, reason, condition in checks if condition]
    risk_score = min(100, sum(item["points"] for item in triggered))
    label = "likely_phishing" if risk_score >= 60 else "suspicious" if risk_score >= 30 else "probably_safe"
    return {
        "details": {
            "parsed_url": url,
            "domain": registered_hint,
            "hostname": host,
            "subdomain": ".".join(labels[:-2]) if len(labels) > 2 else "",
            "features": features,
        },
        "verdict": {"risk_score": risk_score, "label": label, "reasons": triggered},
    }


def assess_with_ml(url: str) -> dict:
    if ML_MODEL is None:
        return {"ml_status": "unavailable", "ml_result": None}
    try:
        probabilities = ML_MODEL.predict_proba([url])[0]
        classes = list(ML_MODEL.classes_)
        phishing_index = classes.index(1)
        phishing_probability = float(probabilities[phishing_index])
        is_phishing = phishing_probability >= 0.5
        return {
            "ml_status": "used",
            "ml_result": {
                "ml_label": "1" if is_phishing else "0",
                "ml_label_text": "Likely phishing" if is_phishing else "Likely legitimate",
                "ml_phishing_probability": round(phishing_probability, 6),
            },
        }
    except Exception:
        logger.exception("ML prediction failed; returning heuristic result only.")
        return {"ml_status": "error", "ml_result": None}


@app.get("/")
def root():
    return {"name": "PhishGuard API", "status": "ok", "docs": "/docs", "ml_model": "loaded" if ML_MODEL else "unavailable"}


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ml_model": "loaded" if ML_MODEL is not None else "unavailable",
        "ml_metrics": {
            "accuracy": ML_METADATA.get("accuracy"),
            "f1_phishing": ML_METADATA.get("f1_phishing"),
            "training_sample_rows": ML_METADATA.get("training_sample_rows"),
        } if ML_MODEL is not None else None,
    }


@app.post("/api/scan")
def scan(body: ScanRequest):
    return {"ok": True, "input": body.url, **analyze(body.url), **assess_with_ml(body.url)}


@app.post("/api/batch_scan")
def batch_scan(body: BatchScanRequest):
    results = []
    for raw_url in body.urls:
        try:
            item = ScanRequest(url=raw_url)
            results.append({"input": item.url, **analyze(item.url), **assess_with_ml(item.url)})
        except Exception as exc:
            results.append({"input": raw_url, "error": str(exc)})
    return {"ok": True, "results": results}
