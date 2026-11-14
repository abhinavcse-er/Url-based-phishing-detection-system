#!/usr/bin/env python3
"""Browser-level end-to-end test for the published PhishGuard site."""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

SITE_URL = os.getenv(
    "PHISHING_SITE_URL",
    "https://abhinavcse-er.github.io/Url-based-phishing-detection-system/",
)
API_URL = os.getenv("PHISHING_API_BASE", "https://phishing-backend-2kib.onrender.com").rstrip("/")
OUTPUT = Path(os.getenv("E2E_REPORT_PATH", "website_e2e_report.json"))
TEST_CASES = [
    {"url": "https://www.google.com/", "expected": "probably_safe"},
    {"url": "https://www.microsoft.com/", "expected": "probably_safe"},
    {"url": "https://github.com/", "expected": "probably_safe"},
    {"url": "https://www.wikipedia.org/", "expected": "probably_safe"},
    {"url": "https://www.amazon.com/", "expected": "probably_safe"},
    {"url": "https://example.org/", "expected": "probably_safe"},
    {"url": "http://paypal-login-security.example.com/", "expected": "suspicious"},
    {"url": "https://secure-amazon.com/login", "expected": "suspicious"},
    {"url": "http://192.0.2.10/login", "expected": "suspicious"},
    {"url": "https://google.com.login.evil.xyz/", "expected": "likely_phishing"},
]


def main():
    report = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "site_url": SITE_URL,
        "api_url": API_URL,
        "checks": [],
        "url_tests": [],
        "console_errors": [],
        "page_errors": [],
        "failed_requests": [],
    }
    failures = []

    def record(name, passed, details=None, required=True):
        entry = {"name": name, "passed": bool(passed), "details": details or {}}
        report["checks"].append(entry)
        if required and not passed:
            failures.append(name)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1365, "height": 900})
        page.on("console", lambda msg: report["console_errors"].append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
        page.on("requestfailed", lambda req: report["failed_requests"].append({
            "url": req.url, "failure": req.failure
        }))

        try:
            response = page.goto(SITE_URL, wait_until="networkidle", timeout=60000)
            record(
                "site_http_200",
                bool(response and response.status == 200),
                {"status": response.status if response else None, "final_url": page.url},
            )
        except Exception as exc:
            record("site_http_200", False, {"error": str(exc)})
            browser.close()
            raise SystemExit(json.dumps(report, indent=2))

        title = page.title()
        record("correct_page_title", "PhishGuard" in title, {"title": title})
        record("scanner_form_present", page.locator("#scanForm").count() == 1)
        record("url_input_present", page.locator("#urlInput").count() == 1)
        record("scan_button_present", page.locator("#scanBtn").count() == 1)
        record("api_config_loaded", page.evaluate("Boolean(window.PHISHING_API_BASE)"), {
            "configured_api": page.evaluate("window.PHISHING_API_BASE")
        })

        # Verify the API health endpoint directly as well as through browser CORS.
        try:
            health_response = page.request.get(API_URL + "/health", timeout=30000)
            health = health_response.json()
            record("backend_health_200", health_response.status == 200, {
                "status_code": health_response.status,
                "ml_model": health.get("ml_model"),
                "ml_evaluation_status": health.get("ml_evaluation_status"),
            })
            record("backend_calibrated_model_loaded_but_inference_gated", (
                health.get("ml_model") == "loaded"
                and health.get("ml_evaluation_status") == "available"
                and health.get("ml_inference_status") == "disabled_pending_external_validation"
            ), {
                "ml_model": health.get("ml_model"),
                "evaluation": health.get("ml_evaluation_status"),
                "inference": health.get("ml_inference_status"),
            })
        except Exception as exc:
            record("backend_health_200", False, {"error": str(exc)})

        # Empty-input validation should not call the API.
        page.locator("#urlInput").fill("")
        page.locator("#scanBtn").click()
        empty_hint = page.locator("#hint").inner_text()
        record("empty_input_validation", "enter" in empty_hint.lower() or "url" in empty_hint.lower(), {
            "hint": empty_hint
        })

        for case in TEST_CASES:
            test_url = case["url"]
            expected_label = case["expected"]
            test = {"url": test_url, "expected_heuristic_label": expected_label}
            try:
                page.locator("#urlInput").fill(test_url)
                with page.expect_response(
                    lambda response: response.url.endswith("/api/scan") and response.request.method == "POST",
                    timeout=30000,
                ) as response_info:
                    page.locator("#scanBtn").click()
                api_response = response_info.value
                test["http_status"] = api_response.status
                try:
                    body = api_response.json()
                except Exception:
                    body = {}
                test["api_ok"] = bool(body.get("ok"))
                test["ml_status"] = body.get("ml_status")
                test["heuristic_score"] = (body.get("verdict") or {}).get("risk_score")
                test["heuristic_label"] = (body.get("verdict") or {}).get("label")
                ml = body.get("ml_result") or {}
                test["legacy_probability_field_present"] = "ml_phishing_probability" in ml
                test["browser_result_visible"] = page.locator("#result").inner_text().strip() != ""
                result_text = page.locator("#result").inner_text()
                test["ui_shows_ml_disabled_notice"] = "Temporarily disabled after external testing" in result_text
                test["ui_shows_old_probability_copy"] = "Estimated phishing probability" in result_text
                test["ui_shows_cors_error"] = "Failed to fetch" in result_text or "CORS" in result_text
                expected_ok = test["heuristic_label"] == expected_label
                test["expected_heuristic_result"] = expected_ok
                test["passed"] = (
                    api_response.status == 200
                    and body.get("ok") is True
                    and body.get("ml_status") == "disabled"
                    and body.get("ml_result") is None
                    and test["browser_result_visible"]
                    and test["ui_shows_ml_disabled_notice"]
                    and not test["legacy_probability_field_present"]
                    and not test["ui_shows_old_probability_copy"]
                    and expected_ok
                )
                if not test["passed"]:
                    failures.append("scan_" + test_url)
            except PlaywrightTimeoutError as exc:
                test["passed"] = False
                test["error"] = "Timed out waiting for the scan API response: " + str(exc)
                failures.append("scan_" + test_url)
            except Exception as exc:
                test["passed"] = False
                test["error"] = str(exc)
                failures.append("scan_" + test_url)
            report["url_tests"].append(test)

        # Check responsive layout at a mobile viewport.
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="domcontentloaded", timeout=30000)
        mobile = page.evaluate("""() => ({
          viewport: document.documentElement.clientWidth,
          document: document.documentElement.scrollWidth,
          formVisible: !!document.querySelector('#scanForm') &&
            document.querySelector('#scanForm').getBoundingClientRect().width > 0
        })""")
        record("mobile_layout_no_horizontal_overflow", (
            mobile["document"] <= mobile["viewport"] + 1 and mobile["formVisible"]
        ), mobile)

        record("no_uncaught_page_errors", len(report["page_errors"]) == 0, {
            "errors": report["page_errors"]
        })
        # A favicon/font CDN can fail independently; record console/network details
        # but do not fail the scanner smoke tests solely for third-party resources.
        record("no_console_errors", len(report["console_errors"]) == 0, {
            "errors": report["console_errors"]
        }, required=False)

        browser.close()

    report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        "checks_passed": sum(1 for item in report["checks"] if item["passed"]),
        "checks_total": len(report["checks"]),
        "url_tests_passed": sum(1 for item in report["url_tests"] if item.get("passed")),
        "url_tests_total": len(report["url_tests"]),
        "failures": failures,
        "overall_pass": len(failures) == 0,
    }
    OUTPUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("PHISHGUARD WEBSITE END-TO-END TEST")
    print(json.dumps(report["summary"], indent=2))
    print("\nPER-URL RESULTS")
    for item in report["url_tests"]:
        print(json.dumps({
            "url": item["url"],
            "passed": item.get("passed"),
            "http_status": item.get("http_status"),
            "heuristic_score": item.get("heuristic_score"),
            "heuristic_label": item.get("heuristic_label"),
            "ml_status": item.get("ml_status"),
            "expected_heuristic_label": item.get("expected_heuristic_label"),
            "heuristic_result": item.get("heuristic_label"),
            "heuristic_score": item.get("heuristic_score"),
            "legacy_probability_field_present": item.get("legacy_probability_field_present"),
            "error": item.get("error"),
        }))
    print("\nFULL REPORT:", OUTPUT)
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
