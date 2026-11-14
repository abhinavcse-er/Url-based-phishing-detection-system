"""Local regression checks for PhishGuard's deterministic URL heuristics."""
from server import analyze


SAFE_URLS = [
    "https://www.google.com/",
    "https://www.microsoft.com/",
    "https://github.com/",
    "https://www.wikipedia.org/",
    "https://www.amazon.com/",
    "https://example.org/",
]

SUSPICIOUS_CASES = {
    "http://paypal-login-security.example.com/": "suspicious",
    "https://secure-amazon.com/login": "suspicious",
    "http://192.0.2.10/login": "suspicious",
    "https://google.com.login.evil.xyz/": "likely_phishing",
}


def main():
    for url in SAFE_URLS:
        result = analyze(url)
        assert result["verdict"]["label"] == "probably_safe", (
            url, result["verdict"]
        )
        assert result["verdict"]["risk_score"] == 0, (
            url, result["verdict"]
        )

    for url, expected in SUSPICIOUS_CASES.items():
        result = analyze(url)
        actual = result["verdict"]["label"]
        assert actual == expected, (
            f"{url}: expected {expected}, got {actual}; "
            f"score={result['verdict']['risk_score']}, "
            f"reasons={result['verdict']['reasons']}"
        )

    print(
        f"PASS: {len(SAFE_URLS)} benign controls and "
        f"{len(SUSPICIOUS_CASES)} suspicious URL cases."
    )


if __name__ == "__main__":
    main()
