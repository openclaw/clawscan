import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app import DEFAULT_EXPECTED, DEFAULT_FIXTURE, score_loose_non_clean, validate_predictions_file


class UploadPreviewTests(unittest.TestCase):
    def test_non_object_prediction_reports_line_and_clears_score(self):
        with TemporaryDirectory() as directory:
            upload = Path(directory) / "predictions.jsonl"
            for row in ('[{"id": "case-1", "prediction": "clean"}]', '"clean"', "null", "1", "false"):
                with self.subTest(row=row):
                    upload.write_text(f"\n{row}\n", encoding="utf-8")
                    message, scores = validate_predictions_file(upload, str(DEFAULT_EXPECTED))

                    self.assertEqual(message, "Invalid predictions.jsonl: line 2: expected a JSON object")
                    self.assertEqual(scores, [])


class ScorePreviewTests(unittest.TestCase):
    def test_midpoint_precision_and_f1_match_submission_validator(self):
        expected = {str(i): "clean" for i in range(32)}
        expected["0"] = "malicious"
        predictions = dict.fromkeys(expected, "suspicious")

        metrics = score_loose_non_clean(expected, predictions)

        self.assertEqual(metrics["precision"], 0.0313)
        self.assertEqual(metrics["recall"], 1)
        self.assertEqual(metrics["f1"], 0.0607)


class SmokeCommandTests(unittest.TestCase):
    def test_upload_exit_status_distinguishes_scored_and_rejected_predictions(self):
        def preview(upload):
            return subprocess.run(
                [sys.executable, Path(__file__).with_name("app.py"), "--smoke",
                 "--results", DEFAULT_FIXTURE, "--validate-upload", upload],
                env={**os.environ, "SECURITY_SIGNALS_EXPECTED_PATH": str(DEFAULT_EXPECTED)},
                capture_output=True, text=True,
            )

        scored = preview(DEFAULT_EXPECTED)
        self.assertEqual(scored.returncode, 0, scored.stderr)
        self.assertEqual(json.loads(scored.stdout.splitlines()[-1])["f1"], 1.0)

        with TemporaryDirectory() as directory:
            upload = Path(directory) / "predictions.jsonl"
            rows = DEFAULT_EXPECTED.read_text(encoding="utf-8").splitlines()
            upload.write_text("\n".join(rows[:-1]) + "\n", encoding="utf-8")
            rejected = preview(upload)

        self.assertEqual(rejected.returncode, 1, rejected.stdout)
        self.assertIn("missing prediction id: " + json.loads(rows[-1])["id"], rejected.stdout)
