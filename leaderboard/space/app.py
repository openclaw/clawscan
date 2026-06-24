from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_FIXTURE = HERE / "fixtures" / "results.jsonl"
RESULTS_FILENAME = "results.jsonl"


def load_results(path: str | None = None) -> list[dict[str, Any]]:
    local_path = Path(path or os.environ.get("SECURITY_SIGNALS_RESULTS_PATH", DEFAULT_FIXTURE))
    if path or local_path.exists():
        return read_jsonl(local_path)

    repo = os.environ.get("SECURITY_SIGNALS_RESULTS_REPO")
    if not repo:
        return []

    from huggingface_hub import hf_hub_download

    downloaded = hf_hub_download(repo_id=repo, filename=RESULTS_FILENAME, repo_type="dataset")
    return read_jsonl(Path(downloaded))


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


def filter_options(results: list[dict[str, Any]], key: str) -> list[str]:
    values = sorted({row[key] for row in leaderboard_rows(results) if row[key]})
    return ["all", *values]


def build_app():
    import gradio as gr

    results = load_results()
    roles = filter_options(results, "role")
    verifications = filter_options(results, "verification")

    css = """
    .gradio-container { max-width: 1180px !important; }
    .metric-note { color: #48515c; font-size: 0.92rem; }
    """

    with gr.Blocks(title="Security Signals Leaderboard", css=css) as app:
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
    return app


def smoke(path: str | None = None) -> None:
    rows = leaderboard_rows(load_results(path))
    print(f"loaded_rows={len(rows)}")
    if rows:
        print(json.dumps(rows[0], sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--results", default="")
    args = parser.parse_args()
    if args.smoke:
        smoke(args.results or None)
    else:
        build_app().launch()
