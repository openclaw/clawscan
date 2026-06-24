from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_FIXTURE = HERE / "fixtures" / "results.jsonl"
DEFAULT_EXPECTED = HERE / "fixtures" / "expected_eval_holdout.jsonl"
RESULTS_FILENAME = "results.jsonl"
VALID_LABELS = {"clean", "suspicious", "malicious"}
APP_CSS = """
.gradio-container { max-width: 1180px !important; }
.metric-note { color: #48515c; font-size: 0.92rem; }
"""


def load_results(path: str | None = None) -> list[dict[str, Any]]:
    configured_path = path or os.environ.get("SECURITY_SIGNALS_RESULTS_PATH")
    if configured_path:
        return read_jsonl(Path(configured_path))

    repo = os.environ.get("SECURITY_SIGNALS_RESULTS_REPO")
    if repo:
        from huggingface_hub import hf_hub_download

        downloaded = hf_hub_download(repo_id=repo, filename=RESULTS_FILENAME, repo_type="dataset")
        return read_jsonl(Path(downloaded))

    local_path = DEFAULT_FIXTURE
    if local_path.exists():
        return read_jsonl(local_path)

    return []


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if text:
                rows.append(json.loads(text))
    return rows


def leaderboard_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in results:
        metrics = result.get("metrics", {})
        benchmark = result.get("benchmark", {})
        system = result.get("system", {})
        rows.append(
            {
                "system": system.get("name", ""),
                "role": system.get("role", ""),
                "verification": result.get("verificationStatus", ""),
                "split": benchmark.get("split", ""),
                "revision": short_revision(benchmark.get("revision", "")),
                "f1": metrics.get("f1", 0),
                "precision": metrics.get("precision", 0),
                "recall": metrics.get("recall", 0),
                "fpr": metrics.get("falsePositiveRate", 0),
                "tp": metrics.get("truePositive", 0),
                "fp": metrics.get("falsePositive", 0),
                "tn": metrics.get("trueNegative", 0),
                "fn": metrics.get("falseNegative", 0),
                "cases": metrics.get("caseCount", 0),
                "metadata": result.get("metadataPath", ""),
                "artifact": result.get("artifactPath", ""),
            }
        )
    return sorted(rows, key=lambda row: (row["f1"], row["recall"], -row["fpr"]), reverse=True)


def short_revision(revision: str) -> str:
    if len(revision) <= 12:
        return revision
    return revision[:12]


def filter_rows(role: str, verification: str, results_path: str = "") -> list[dict[str, Any]]:
    rows = leaderboard_rows(load_results(results_path or None))
    if role and role != "all":
        rows = [row for row in rows if row["role"] == role]
    if verification and verification != "all":
        rows = [row for row in rows if row["verification"] == verification]
    return rows


def load_expected_labels(path: str | None = None) -> dict[str, str]:
    expected_path = Path(path or os.environ.get("SECURITY_SIGNALS_EXPECTED_PATH", DEFAULT_EXPECTED))
    labels: dict[str, str] = {}
    with expected_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            labels[row["id"]] = row["prediction"]
    return labels


def read_predictions(path: str | Path) -> list[dict[str, str]]:
    predictions: list[dict[str, str]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
            predictions.append(
                {
                    "id": str(row.get("id", "")),
                    "prediction": str(row.get("prediction", "")),
                }
            )
    return predictions


def validate_predictions_file(upload_path: str | Path | None, expected_path: str | None = None) -> tuple[str, list[dict[str, Any]]]:
    if upload_path is None:
        return "Upload a predictions.jsonl file to preview a score.", []
    expected = load_expected_labels(expected_path)
    try:
        predictions = read_predictions(upload_path)
    except ValueError as exc:
        return f"Invalid predictions.jsonl: {exc}", []

    errors: list[str] = []
    seen: set[str] = set()
    predicted: dict[str, str] = {}
    for row in predictions:
        case_id = row["id"]
        label = row["prediction"]
        if not case_id:
            errors.append("prediction id is required")
            continue
        if case_id in seen:
            errors.append(f"duplicate prediction id: {case_id}")
        seen.add(case_id)
        predicted[case_id] = label
        if case_id not in expected:
            errors.append(f"unknown prediction id: {case_id}")
        if label not in VALID_LABELS:
            errors.append(f"invalid prediction label for {case_id}: {label}")
    for case_id in expected:
        if case_id not in seen:
            errors.append(f"missing prediction id: {case_id}")

    if errors:
        preview = "\n".join(f"- {error}" for error in errors[:25])
        if len(errors) > 25:
            preview += f"\n- ... {len(errors) - 25} more error(s)"
        return f"Validation failed with {len(errors)} error(s):\n{preview}", []

    metrics = score_loose_non_clean(expected, predicted)
    return "Validation passed. This preview does not publish leaderboard results.", [metrics]


def score_loose_non_clean(expected: dict[str, str], predicted: dict[str, str]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for case_id, expected_label in expected.items():
        expected_positive = expected_label in {"suspicious", "malicious"}
        predicted_positive = predicted[case_id] in {"suspicious", "malicious"}
        if expected_positive and predicted_positive:
            tp += 1
        elif not expected_positive and predicted_positive:
            fp += 1
        elif not expected_positive and not predicted_positive:
            tn += 1
        else:
            fn += 1
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    f1 = divide_float(2 * precision * recall, precision + recall)
    fpr = divide(fp, fp + tn)
    return {
        "caseCount": len(expected),
        "f1": f1,
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def divide(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0
    return round(numerator / denominator, 4)


def divide_float(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0
    return round(numerator / denominator, 4)


def filter_options(results: list[dict[str, Any]], key: str) -> list[str]:
    values = sorted({row[key] for row in leaderboard_rows(results) if row[key]})
    return ["all", *values]


def build_app():
    import gradio as gr

    results = load_results()
    roles = filter_options(results, "role")
    verifications = filter_options(results, "verification")

    with gr.Blocks(title="Security Signals Leaderboard") as app:
        gr.Markdown(
            """
            # Security Signals Leaderboard

            Accepted ClawScan benchmark submissions for
            `OpenClaw/clawhub-security-signals`. Official rows come from merged
            GitHub PRs; this Space is a display and validation surface only.
            """
        )
        with gr.Row():
            role = gr.Dropdown(choices=roles, value="all", label="Role")
            verification = gr.Dropdown(choices=verifications, value="all", label="Verification")
        table = gr.Dataframe(
            value=filter_rows("all", "all"),
            datatype=["str", "str", "str", "str", "str", "number", "number", "number", "number", "number", "number", "number", "number", "number", "str", "str"],
            interactive=False,
            wrap=True,
            label="Accepted Results",
        )
        gr.Markdown(
            """
            <p class="metric-note">
            Loose non-clean scoring maps suspicious and malicious to positive,
            and clean to negative. FPR is FP / (FP + TN).
            </p>
            """
        )
        role.change(filter_rows, inputs=[role, verification], outputs=table)
        verification.change(filter_rows, inputs=[role, verification], outputs=table)

        gr.Markdown(
            """
            ## Preview a predictions file

            Upload validation is local to this Space session. It does not create
            official leaderboard rows; open a GitHub PR with `metadata.json` and
            `predictions.jsonl` for official submission.
            """
        )
        upload = gr.File(label="predictions.jsonl", file_types=[".jsonl"], type="filepath")
        validation_message = gr.Textbox(label="Validation", lines=8, interactive=False)
        preview = gr.Dataframe(interactive=False, label="Score Preview")
        upload.change(validate_predictions_file, inputs=upload, outputs=[validation_message, preview])
    return app


def smoke(path: str | None = None, upload_path: str | None = None) -> None:
    rows = leaderboard_rows(load_results(path))
    print(f"loaded_rows={len(rows)}")
    if rows:
        print(json.dumps(rows[0], sort_keys=True))
    if upload_path:
        message, preview = validate_predictions_file(upload_path)
        print(message)
        if preview:
            print(json.dumps(preview[0], sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--results", default="")
    parser.add_argument("--validate-upload", default="")
    args = parser.parse_args()
    if args.smoke:
        smoke(args.results or None, args.validate_upload or None)
    else:
        build_app().launch(css=APP_CSS)
