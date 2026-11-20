import unittest

from app import score_loose_non_clean


class ScorePreviewTests(unittest.TestCase):
    def test_midpoint_precision_and_f1_match_submission_validator(self):
        expected = {str(i): "clean" for i in range(32)}
        expected["0"] = "malicious"
        predictions = dict.fromkeys(expected, "suspicious")

        metrics = score_loose_non_clean(expected, predictions)

        self.assertEqual(metrics["precision"], 0.0313)
        self.assertEqual(metrics["recall"], 1)
        self.assertEqual(metrics["f1"], 0.0607)
