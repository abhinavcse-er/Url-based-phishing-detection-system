import unittest

import numpy as np

from server import ml_inference_gate
from evaluate_external import load_external_dataset, load_phishfusion_source, normalized_http_url
from train_model import (
    build_model_candidates,
    hostname_group,
    make_grouped_splits,
    select_threshold,
)
from url_features import FEATURE_NAMES, extract_url_features_dense


class URLFeatureTests(unittest.TestCase):
    def test_feature_matrix_has_stable_shape_and_finite_values(self):
        urls = [
            "https://www.google.com/",
            "http://192.0.2.10/login?next=account",
            "https://secure-example.xyz/verify",
        ]
        features = extract_url_features_dense(urls)
        self.assertEqual(features.shape, (3, len(FEATURE_NAMES)))
        self.assertTrue(np.isfinite(features).all())

    def test_ip_and_redirect_indicators_are_extracted_without_network_access(self):
        features = extract_url_features_dense([
            "http://192.0.2.10/login?redirect=https%3A%2F%2Fexample.org"
        ])[0]
        feature_index = {name: index for index, name in enumerate(FEATURE_NAMES)}
        self.assertEqual(features[feature_index["is_ip_hostname"]], 1.0)
        self.assertEqual(features[feature_index["suspicious_path_keyword_count"]], 1.0)
        self.assertEqual(features[feature_index["redirect_parameter_count"]], 1.0)

    def test_empty_input_returns_correct_empty_matrix(self):
        features = extract_url_features_dense([])
        self.assertEqual(features.shape, (0, len(FEATURE_NAMES)))


class GroupedEvaluationTests(unittest.TestCase):
    def test_subdomains_share_the_same_registrable_domain_group(self):
        self.assertEqual(
            hostname_group("https://login.accounts.example.co.uk/path"),
            "example.co.uk",
        )

    def test_training_calibration_validation_and_test_sites_do_not_overlap(self):
        urls = []
        targets = []
        groups = []
        for index in range(240):
            domain = f"sample{index}.example"
            label = index % 2
            urls.append(f"https://{domain}/{'login' if label else 'home'}")
            targets.append(label)
            groups.append(domain)

        import pandas as pd

        url_series = pd.Series(urls)
        target_series = pd.Series(targets)
        group_series = pd.Series(groups)
        partitions = make_grouped_splits(
            url_series,
            target_series,
            group_series,
        )

        self.assertEqual(set(partitions), {
            "training", "calibration", "validation", "test"
        })
        for left_name, left_indices in partitions.items():
            left_groups = set(group_series.iloc[left_indices])
            for right_name, right_indices in partitions.items():
                if left_name >= right_name:
                    continue
                right_groups = set(group_series.iloc[right_indices])
                self.assertFalse(left_groups & right_groups)


class ModelPipelineSmokeTests(unittest.TestCase):
    def test_all_candidate_models_fit_and_return_finite_scores(self):
        legitimate_hosts = [
            "www.google.com", "github.com", "wikipedia.org", "www.microsoft.com"
        ]
        phishing_hosts = [
            "secure-google-login.evil.xyz",
            "paypal-verify-account.example.top",
            "microsoft-password-update.example.click",
            "signin-wallet-confirm.example.work",
        ]
        urls = []
        targets = []
        for index in range(48):
            legitimate_host = legitimate_hosts[index % len(legitimate_hosts)]
            phishing_host = phishing_hosts[index % len(phishing_hosts)]
            urls.append(
                f"https://{legitimate_host}/products/search/item-{index % 12}"
            )
            targets.append(0)
            urls.append(
                f"http://{phishing_host}/login/verify?account={index % 12}"
            )
            targets.append(1)

        for name, candidate in build_model_candidates().items():
            with self.subTest(candidate=name):
                candidate.fit(urls, np.asarray(targets, dtype=int))
                scores = candidate.predict_proba(urls)
                self.assertEqual(scores.shape, (len(urls), 2))
                self.assertTrue(np.isfinite(scores).all())


class ExternalDatasetCleaningTests(unittest.TestCase):
    def test_cleaner_removes_invalid_urls_normalized_duplicates_and_conflicts(self):
        import tempfile
        from pathlib import Path
        import pandas as pd

        rows = [
            {"url": "https://www.google.com/", "label": "benign"},
            {"url": "https://fake-example.xyz/verify", "label": "phish"},
            {"url": "https://same-example.net/login", "label": "benign"},
            {"url": "http://same-example.net/login", "label": "phish"},
            {"url": "https://duplicate-example.org/path", "label": "phish"},
            {"url": "http://duplicate-example.org/path", "label": "phish"},
            {"url": "ftp://not-http.example/login", "label": "phish"},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "external.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            cleaned, diagnostics = load_external_dataset(
                path,
                url_column="url",
                label_column="label",
                phishing_label="phish",
                benign_label="benign",
            )

        self.assertEqual(len(cleaned), 3)
        self.assertEqual(diagnostics["invalid_or_non_http_url_rows_removed"], 1)
        self.assertEqual(diagnostics["normalized_label_conflict_rows_removed"], 2)
        self.assertEqual(diagnostics["normalized_duplicate_rows_removed"], 1)
        self.assertEqual(diagnostics["class_counts_before_source_overlap"], {
            "benign": 1, "phishing": 2
        })


    def test_phishfusion_overlap_normalization_ignores_scheme_and_fragment(self):
        import tempfile
        from pathlib import Path
        import pandas as pd

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "phishfusion.csv"
            pd.DataFrame({
                "url": [
                    "https://Example.com/login?next=home#source-fragment",
                    "https://sub.example.org/path",
                ],
                "phishing": [1, 0],
            }).to_csv(path, index=False)

            overlap_urls, source_domains, diagnostics = load_phishfusion_source(path)

        parsed = normalized_http_url(
            "http://example.com/login?next=home#different-fragment"
        )
        self.assertIsNotNone(parsed)
        self.assertIn(parsed[0], overlap_urls)
        self.assertIn("example.com", source_domains)
        self.assertEqual(diagnostics["rows_read_by_encoding"], {
            "utf-8": 2, "latin-1": 2
        })

    def test_source_hash_columns_are_checked_against_original_url(self):
        import tempfile
        import hashlib
        from pathlib import Path
        import pandas as pd

        url = "https://valid-example.org/"
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "external.csv"
            pd.DataFrame([
                {
                    "url": url,
                    "label": "benign",
                    "source_id": digest,
                    "url_sha256": digest,
                },
                {
                    "url": "https://phishing-example.xyz/login",
                    "label": "phish",
                    "source_id": hashlib.sha256(
                        b"https://phishing-example.xyz/login"
                    ).hexdigest(),
                    "url_sha256": hashlib.sha256(
                        b"https://phishing-example.xyz/login"
                    ).hexdigest(),
                },
            ]).to_csv(path, index=False)
            cleaned, diagnostics = load_external_dataset(
                path,
                url_column="url",
                label_column="label",
                phishing_label="phish",
                benign_label="benign",
            )

        self.assertEqual(len(cleaned), 2)
        self.assertEqual(diagnostics["url_hash_integrity"]["url_sha256_rows"], 2)
        self.assertEqual(diagnostics["url_hash_integrity"]["source_id_rows"], 2)


class DecisionGateTests(unittest.TestCase):
    def test_threshold_respects_validation_false_positive_ceiling(self):
        y_true = np.asarray([0] * 1000 + [1] * 1000)
        probabilities = np.concatenate([
            np.linspace(0.01, 0.30, 1000),
            np.linspace(0.50, 0.99, 1000),
        ])
        threshold, metrics = select_threshold(
            y_true,
            probabilities,
            max_false_positive_rate=0.01,
        )
        self.assertGreater(threshold, 0.30)
        self.assertLessEqual(metrics["false_positive_rate"], 0.01)
        self.assertGreater(metrics["recall_phishing"], 0.0)

    def test_model_inference_requires_both_switches_and_approved_artifact(self):
        self.assertFalse(ml_inference_gate(False, False, "approved", True))
        self.assertFalse(ml_inference_gate(True, False, "approved", True))
        self.assertFalse(
            ml_inference_gate(True, True, "pending_external_validation", False)
        )
        self.assertFalse(ml_inference_gate(True, True, "approved", False))
        self.assertTrue(ml_inference_gate(True, True, "approved", True))


if __name__ == "__main__":
    unittest.main()
