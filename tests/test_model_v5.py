import unittest

import numpy as np
import pandas as pd

from train_model_v5 import (
    hostname_group,
    make_grouped_splits,
    sample_by_source_and_class,
    select_multisource_threshold,
)


class V5DomainGroupingTests(unittest.TestCase):
    def test_private_suffix_is_part_of_registered_domain_key(self):
        self.assertEqual(
            hostname_group("https://account.customer.github.io/login"),
            "customer.github.io",
        )

    def test_subdomains_of_same_registered_site_share_a_group(self):
        self.assertEqual(
            hostname_group("https://login.example.co.uk/"),
            hostname_group("https://www.example.co.uk/"),
        )


class V5SamplingTests(unittest.TestCase):
    def test_each_development_source_contributes_equal_rows_per_class(self):
        rows = []
        for source_index, source in enumerate(
            ("PhishFusion", "Ebbu2017", "PhishStorm")
        ):
            for label in (0, 1):
                for item in range(18 + source_index):
                    rows.append({
                        "url": f"https://{source.lower()}-{item}-{label}.com/",
                        "normalized_url": f"{source.lower()}-{item}-{label}.com/",
                        "site": f"{source.lower()}-{item}-{label}.com",
                        "target": label,
                        "source": source,
                    })
        sampled = sample_by_source_and_class(pd.DataFrame(rows))
        counts = sampled.groupby(["source", "target"]).size()
        self.assertEqual(counts.nunique(), 1)
        self.assertEqual(sampled["source"].nunique(), 3)
        self.assertEqual(sampled["target"].value_counts().nunique(), 1)


class V5GroupedSplitTests(unittest.TestCase):
    def test_no_registered_domain_crosses_any_partition(self):
        urls = []
        targets = []
        groups = []
        for index in range(300):
            domain = f"tenant{index}.com"
            label = index % 2
            urls.append(f"https://{domain}/{'login' if label else 'home'}")
            targets.append(label)
            groups.append(hostname_group(urls[-1]))

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
        for left_index, left_name in enumerate(partitions):
            left_groups = set(group_series.iloc[partitions[left_name]])
            for right_name in list(partitions)[left_index + 1:]:
                right_groups = set(group_series.iloc[partitions[right_name]])
                self.assertFalse(left_groups & right_groups)


class V5ThresholdTests(unittest.TestCase):
    def test_threshold_meets_global_and_every_source_fpr_limits(self):
        labels = []
        scores = []
        sources = []
        for source in ("PhishFusion", "Ebbu2017", "PhishStorm"):
            labels.extend([0] * 200 + [1] * 200)
            scores.extend(
                np.concatenate([
                    np.linspace(0.01, 0.20, 200),
                    np.linspace(0.55, 0.99, 200),
                ]).tolist()
            )
            sources.extend([source] * 400)

        threshold, selection = select_multisource_threshold(
            labels,
            scores,
            sources,
            max_false_positive_rate=0.01,
            max_source_false_positive_rate=0.02,
        )
        self.assertTrue(selection["feasible"])
        self.assertLessEqual(
            selection["global_metrics"]["false_positive_rate"],
            0.01,
        )
        for item in selection["source_metrics"].values():
            self.assertLessEqual(
                item["metrics"]["false_positive_rate"],
                0.02,
            )
        self.assertGreaterEqual(threshold, 0.20)

    def test_no_feasible_source_threshold_fails_closed(self):
        labels = []
        scores = []
        sources = []
        for source in ("PhishFusion", "Ebbu2017", "PhishStorm"):
            labels.extend([0] * 100 + [1] * 100)
            scores.extend(
                np.concatenate([
                    np.linspace(0.40, 0.90, 100),
                    np.linspace(0.45, 0.95, 100),
                ]).tolist()
            )
            sources.extend([source] * 200)

        threshold, selection = select_multisource_threshold(
            labels,
            scores,
            sources,
            max_false_positive_rate=0.01,
            max_source_false_positive_rate=0.02,
        )
        self.assertFalse(selection["feasible"])
        self.assertEqual(threshold, 1.000001)
        self.assertEqual(
            selection["global_metrics"]["false_positive_rate"],
            0.0,
        )
        self.assertEqual(selection["global_metrics"]["recall_phishing"], 0.0)


if __name__ == "__main__":
    unittest.main()
