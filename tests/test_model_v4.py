import unittest

import numpy as np

from server import ml_inference_gate
from train_model import (
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

    def test_model_inference_requires_both_operator_switches(self):
        self.assertFalse(ml_inference_gate(False, False))
        self.assertFalse(ml_inference_gate(True, False))
        self.assertFalse(ml_inference_gate(False, True))
        self.assertTrue(ml_inference_gate(True, True))


if __name__ == "__main__":
    unittest.main()
