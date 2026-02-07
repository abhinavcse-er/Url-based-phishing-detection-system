from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib.parse import urlparse
import re, socket, os
import tldextract

# --------- Initialize App ----------
app = FastAPI(title="Phishing Detection API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# --------- Serve Frontend ----------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "../frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

# Serve static assets (CSS, JS)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Serve main pages
@app.get("/")
def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/about")
def serve_about():
    return FileResponse(os.path.join(FRONTEND_DIR, "about.html"))

@app.get("/contact")
def serve_contact():
    return FileResponse(os.path.join(FRONTEND_DIR, "contact.html"))


# --------- Model & Detection Logic ----------
class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

SUSPICIOUS_TLDS = {
    "zip","biz","top","country","gq","ml","cf","tk","work","men","loan","click","link"
}
BRAND_KEYWORDS = [
    "login","verify","update","secure","account","support","billing","unlock",
    "reset","confirm","invoice","security","pay","wallet","password"
]
TRUSTED_BRANDS = [
    "google","facebook","instagram","apple","microsoft","netflix",
    "amazon","paypal","bank","yahoo","outlook"
]

IP_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)(\.|$)){4}")
URL_SHORTENERS = {
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","cutt.ly","rb.gy","buff.ly"
}
PUNY_PREFIX = "xn--"

def safe_parse(url: str):
    if not re.match(r"^\w+://", url):
        url = "http://" + url  # allow users to omit scheme
    return urlparse(url)

def count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)

def entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    probs = [n/len(s) for n in c.values()]
    return -sum(p*math.log2(p) for p in probs)

def extract_features(url: str) -> Dict[str, Any]:
    parsed = safe_parse(url)
    ext = tldextract.extract(parsed.netloc)
    hostname = parsed.netloc.lower()
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain or ""
    path = parsed.path or "/"

    features = {
        "uses_https": parsed.scheme == "https",
        "url_length": len(url),
        "host_length": len(hostname),
        "num_dots": hostname.count("."),
        "has_at_symbol": "@" in url,
        "has_hyphen": "-" in ext.domain,
        "has_port": ":" in hostname and not hostname.endswith("]"),
        "is_ip_host": bool(IP_RE.match(hostname)),
        "num_digits_host": count_digits(hostname),
        "suspicious_tld": ext.suffix in SUSPICIOUS_TLDS,
        "contains_punycode": PUNY_PREFIX in hostname,
        "uses_shortener": hostname in URL_SHORTENERS,
        "subdomain_len": len(subdomain),
        "subdomain_entropy": round(entropy(subdomain), 3),
        "keyword_in_path": any(k in path.lower() for k in BRAND_KEYWORDS),
        "brand_mismatch": any(b in path.lower() for b in TRUSTED_BRANDS) and \
                          not any(b in domain for b in TRUSTED_BRANDS),
        "query_len": len(parsed.query),
    }

    try:
        socket.getaddrinfo(hostname.split(":")[0], None)
        features["dns_resolves"] = True
    except Exception:
        features["dns_resolves"] = False

    return {
        "parsed_url": parsed.geturl(),
        "hostname": hostname,
        "domain": domain,
        "subdomain": subdomain,
        "path": path,
        "features": features,
    }

def score(features: Dict[str, Any]) -> Dict[str, Any]:
    f = features["features"]
    risk = 0
    reasons = []

    def add(points, reason, cond=True):
        nonlocal risk, reasons
        if cond:
            risk += points
            reasons.append((points, reason))

    add(2, "Not using HTTPS", not f["uses_https"])
    add(4, "Host is an IP address", f["is_ip_host"])
    add(3, "Suspicious TLD", f["suspicious_tld"])
    add(2, "URL shortener", f["uses_shortener"])
    add(2, "Contains '@' symbol", f["has_at_symbol"])
    add(1, "Hyphenated domain", f["has_hyphen"])
    add(1, "Port specified in host", f["has_port"])
    add(2, "High subdomain entropy", f["subdomain_entropy"] >= 3.5 and f["subdomain_len"] >= 10)
    add(2, "Brand in path but not in domain (mismatch)", f["brand_mismatch"])
    add(1, "Login/verify/security keyword in path", f["keyword_in_path"])
    add(1, "Long URL", f["url_length"] > 80)
    add(1, "Many dots in host", f["num_dots"] >= 4)
    add(1, "Many digits in host", f["num_digits_host"] >= 4)
    add(3, "DNS does not resolve", not f["dns_resolves"])
    add(2, "Punycode present", f["contains_punycode"])
    add(1, "Very long query string", f["query_len"] > 60)

    max_risk = 25
    risk_pct = min(100, int(risk / max_risk * 100))

    if risk_pct >= 60:
        label, color = "likely_phishing", "red"
    elif risk_pct >= 30:
        label, color = "suspicious", "orange"
    else:
        label, color = "probably_safe", "green"

    return {
        "risk_score": risk_pct,
        "label": label,
        "color": color,
        "reasons": [{"points": p, "reason": r} for p, r in sorted(reasons, key=lambda x: -x[0])]
    }

@app.post("/predict")
def predict(data: dict):
    url = data["url"]
    prediction = "Safe"
    risk_score = 90 if prediction == "Safe" else 30
    return {"prediction": prediction, "risk_score": risk_score}

@app.post("/api/scan")
def scan(body: ScanRequest):
    details = extract_features(body.url.strip())
    verdict = score(details)
    return {
        "ok": True,
        "input": body.url,
        "details": details,
        "verdict": verdict
    }

@app.post("/api/batch_scan")
def batch_scan(body: BatchScanRequest):
    results = []
    for url in body.urls:
        details = extract_features(url.strip())
        verdict = score(details)
        results.append({
            "input": url,
            "details": details,
            "verdict": verdict
        })
    return {"ok": True, "results": results}

# --------- Run directly ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=5500, reload=True)