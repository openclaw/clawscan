import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool


@pytest.mark.parametrize("file_type,source", [
    ("json", '{"x":"a del b"}'),
    ("shell", 'echo "a del b"'),
    ("markdown", '"a del b"'),
])
def test_fragment_cannot_establish_outer_quote_ownership(file_type,source):
    assert tool.has_bounded_parse_exhaustion(
        source, lambda: None, file_type=file_type, complete_context=False
    )
