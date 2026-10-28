"""Conservative shell fences keep their delimiters and bounded exclusions."""

import pytest

from skillspector.markdown_tokens import MarkdownCodeSpanClosers
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool_misuse


@pytest.mark.parametrize("opening,indent", [("   ```sh", "      "), ("- - ```sh", "        ")])
def test_deeply_indented_marker_does_not_close_fence(opening, indent):
    command = "`$(resolve_tool).example` -rf /"
    content = opening + "\n" + indent + "```\n" + command + "\n```\n"
    projected = tool_misuse._markdown_shell_text(content, lambda: None)
    assert command in projected


def test_fence_ownership_exclusions_are_bounded_by_blocks(monkeypatch):
    content = "- ```sh\n" + "\n" * 10_000 + "  ```\n\n"
    content += "Use `$(hostname).example` for the host.\n\n" * 100
    exclusions = []
    original = MarkdownCodeSpanClosers.__init__

    def observe(self, *args, **kwargs):
        exclusions.append(len(kwargs.get("excluded_ranges", ())))
        original(self, *args, **kwargs)

    monkeypatch.setattr(MarkdownCodeSpanClosers, "__init__", observe)
    projected = tool_misuse._markdown_shell_text(content, lambda: None)
    assert exclusions and max(exclusions) <= 1
    assert "$(hostname).example" in projected
