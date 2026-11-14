"""Deterministic URL-only feature extraction for PhishGuard model v4.

No DNS, WHOIS, HTTP requests, page rendering, or external lookups are performed.
The extractor is deliberately offline so training and inference use identical inputs.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from math import log2
from urllib.parse import parse_qsl, urlsplit

import numpy as np
from scipy.sparse import csr_matrix
import tldextract


DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

SUSPICIOUS_KEYWORDS = {
    "account", "auth", "billing", "confirm", "credential", "customer",
    "identity", "invoice", "login", "logon", "password", "pay", "payment",
    "recover", "security", "signin", "unlock", "update", "validate",
    "verification", "verify", "wallet", "webscr",
}
REDIRECT_PARAMETER_NAMES = {
    "continue", "dest", "destination", "next", "redirect", "redirect_uri",
    "return", "returnto", "target", "url",
}
KNOWN_SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy",
    "t.co", "tinyurl.com",
}

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "hostname_dot_count",
    "subdomain_count",
    "url_digit_count",
    "url_digit_ratio",
    "hostname_digit_count",
    "hostname_hyphen_count",
    "url_at_count",
    "url_equals_count",
    "url_ampersand_count",
    "url_percent_count",
    "url_slash_count",
    "url_colon_count",
    "query_parameter_count",
    "hostname_token_count",
    "path_token_count",
    "suspicious_hostname_keyword_count",
    "suspicious_path_keyword_count",
    "hostname_entropy",
    "url_entropy",
    "tld_length",
    "is_https",
    "is_ip_hostname",
    "has_punycode",
    "has_explicit_port",
    "has_userinfo",
    "has_fragment",
    "has_double_slash_in_path",
    "uses_known_shortener",
    "redirect_parameter_count",
    "non_ascii_character_count",
    "encoded_character_count",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return float(-sum((count / length) * log2(count / length) for count in counts.values()))


def _extract_one(raw_url: str) -> list[float]:
    value = str(raw_url or "").strip()
    candidate = value if "://" in value else "https://" + value

    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        has_userinfo = bool(parsed.username or parsed.password)
    except ValueError:
        parsed = urlsplit("https://invalid.invalid")
        hostname = ""
        port = None
        has_userinfo = False

    lower_url = value.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    host_labels = [part for part in hostname.split(".") if part]

    extracted = DOMAIN_EXTRACTOR(hostname) if hostname else None
    registered_domain = (
        extracted.top_domain_under_public_suffix if extracted else ""
    ) or hostname
    suffix = (extracted.suffix if extracted else "") or (
        host_labels[-1] if host_labels else ""
    )
    subdomain_count = max(
        0,
        len(host_labels) - len([part for part in registered_domain.split(".") if part]),
    )

    try:
        ipaddress.ip_address(hostname)
        is_ip_hostname = 1.0
    except ValueError:
        is_ip_hostname = 0.0

    hostname_tokens = re.findall(r"[a-z0-9]+", hostname)
    path_query_tokens = re.findall(r"[a-z0-9]+", (path + " " + query).lower())
    hostname_keyword_count = sum(
        token in SUSPICIOUS_KEYWORDS for token in hostname_tokens
    )
    path_keyword_count = sum(
        token in SUSPICIOUS_KEYWORDS for token in path_query_tokens
    )

    try:
        query_pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=500)
    except ValueError:
        query_pairs = []
    redirect_count = sum(
        str(key).lower() in REDIRECT_PARAMETER_NAMES for key, _ in query_pairs
    )

    url_digits = sum(character.isdigit() for character in value)
    hostname_digits = sum(character.isdigit() for character in hostname)

    return [
        float(len(value)),
        float(len(hostname)),
        float(len(path)),
        float(len(query)),
        float(len(fragment)),
        float(hostname.count(".")),
        float(subdomain_count),
        float(url_digits),
        float(url_digits / max(1, len(value))),
        float(hostname_digits),
        float(hostname.count("-")),
        float(value.count("@")),
        float(value.count("=")),
        float(value.count("&")),
        float(value.count("%")),
        float(value.count("/")),
        float(value.count(":")),
        float(len(query_pairs)),
        float(len(hostname_tokens)),
        float(len(path_query_tokens)),
        float(hostname_keyword_count),
        float(path_keyword_count),
        _entropy(hostname),
        _entropy(lower_url),
        float(len(suffix)),
        float(parsed.scheme.lower() == "https"),
        is_ip_hostname,
        float("xn--" in hostname),
        float(port is not None),
        float(has_userinfo),
        float(bool(fragment)),
        float(path.startswith("//")),
        float(hostname in KNOWN_SHORTENERS),
        float(redirect_count),
        float(sum(ord(character) > 127 for character in value)),
        float(len(re.findall(r"%[0-9a-fA-F]{2}", value))),
    ]


def extract_url_features_dense(urls) -> np.ndarray:
    """Return a dense float32 matrix for tree-based URL classifiers."""
    if isinstance(urls, str):
        urls = [urls]
    rows = [_extract_one(url) for url in urls]
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
    return np.asarray(rows, dtype=np.float32)


def extract_url_features_sparse(urls) -> csr_matrix:
    """Return the same feature schema as sparse data for hybrid TF-IDF models."""
    return csr_matrix(extract_url_features_dense(urls), dtype=np.float32)
