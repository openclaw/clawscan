from collections import Counter

import pytest

from skillspector.llm_analyzer_base import Batch, LLMAnalyzerBase
from skillspector.models import Finding
from skillspector.nodes.meta_analyzer import PER_FILE_ANALYSIS_PROMPT, LLMMetaAnalyzer


def analyzer(prompt=None):
    result = object.__new__(LLMAnalyzerBase)
    result._timeout = None
    result._input_budget = 1256
    # These synthetic layouts reserve the real framing but omit the schema to
    # isolate placement of 1,000 content bytes. Real layouts are checked below.
    result._serialized_input = lambda prompt, **kwargs: prompt
    result._token_counter = lambda text: 0
    result.base_prompt = 'Generated rules'
    if prompt is not None:
        result.build_prompt = prompt
    return result


def members(packet):
    return packet.members or (packet,)


def test_best_fit_reuses_bounded_open_packets_before_starting_new_requests():
    sources = [Batch(file_path=f'{i}.md', content='x' * size)
               for i, size in enumerate([600, 600, 400, 400])]
    a = analyzer(lambda packet, **kwargs: ''.join(s.content for s in members(packet)))
    result = a._pack_semantic_sources(sources)
    assert len(result) == 2, 'next-fit leaves a separate request for the final source'
    assert [[s.file_path for s in members(p)] for p in result] == [['0.md', '2.md'], ['1.md', '3.md']]
    assert Counter(id(s) for p in result for s in members(p)) == Counter(map(id, sources))


def test_actual_serialization_guards_an_unexpected_nonadditive_prompt_builder():
    sources = [Batch(file_path=f'{i}.md', content='x' * size)
               for i, size in enumerate([100, 300, 300])]

    def prompt(packet, **kwargs):
        group = members(packet)
        paths = {s.file_path for s in group}
        penalty = 2000 if {'1.md', '2.md'} <= paths else 0
        return 'x' * (sum(len(s.content) for s in group) + penalty)

    a = analyzer(prompt)
    result = a._pack_semantic_sources(sources)
    assert Counter(id(s) for p in result for s in members(p)) == Counter(map(id, sources))
    assert all(not p.members or len(prompt(p).encode()) <= a._input_budget for p in result)


def test_overflow_fallback_preserves_same_file_order_across_dependent_bins():
    sources = [Batch(file_path=path, content='x' * size, start_line=start, end_line=end)
               for path, size, start, end in [
                   ('first.md', 600, 1, 1), ('second.md', 600, 1, 1),
                   ('same.md', 400, 1, 5), ('same.md', 400, 6, 10),
               ]]

    def prompt(packet, **kwargs):
        group = members(packet)
        paths = {s.file_path for s in group}
        penalty = 2000 if {'first.md', 'same.md'} <= paths else 0
        return 'x' * (sum(len(s.content) for s in group) + penalty)

    result = analyzer(prompt)._pack_semantic_sources(sources)
    assert [m.start_line for p in result for m in members(p) if m.file_path == 'same.md'] == [1, 6]
    assert result == sources


def test_overlapping_same_source_units_never_share_request_identity():
    sources = [Batch(file_path='same.md', content='x' * 100, start_line=start, end_line=end)
               for start, end in [(1, 5), (4, 9), (10, 15)]]
    a = analyzer(lambda packet, **kwargs: ''.join(s.content for s in members(packet)))
    result = a._pack_semantic_sources(sources)
    for packet in result:
        group = members(packet)
        assert not (sources[0] in group and sources[1] in group)
    assert Counter(id(s) for p in result for s in members(p)) == Counter(map(id, sources))


def test_multibyte_actual_prompts_and_oversized_original_single_remain_bounded():
    sources = [Batch(file_path=f'{i}.md', content='é' * size)
               for i, size in enumerate([100, 600, 100, 100])]
    a = analyzer(lambda packet, **kwargs: ''.join(s.content for s in members(packet)))
    result = a._pack_semantic_sources(sources)
    assert sources[1] in result
    assert all(not p.members or len(a.build_prompt(p).encode()) <= a._input_budget for p in result)
    assert Counter(id(s) for p in result for s in members(p)) == Counter(map(id, sources))


def test_planning_checks_the_callers_runtime_budget():
    a = analyzer()

    def expired():
        raise TimeoutError('planning deadline')

    a._require_time_remaining = expired
    with pytest.raises(TimeoutError, match='planning deadline'):
        a._pack_semantic_sources([Batch(file_path='a.md', content='x')])


@pytest.mark.parametrize('meta', [False, True])
def test_real_packet_layouts_keep_all_source_and_finding_identities_with_bounded_builds(meta):
    a = object.__new__(LLMMetaAnalyzer if meta else LLMAnalyzerBase)
    a._timeout = None
    a._input_budget = 96000
    a._token_counter = lambda text: len(text.encode())
    a.base_prompt = PER_FILE_ANALYSIS_PROMPT if meta else 'Generated independent rules'
    sources = []
    for index in range(128):
        path = f'quoted-"é-{index}.md'
        finding = Finding(rule_id='AR2', message='Generated original finding', severity='HIGH',
                          confidence=0.9, file=path, start_line=1)
        sources.append(Batch(file_path=path, content='é' * (20000 if index % 5 == 0 else 100),
                             findings=[finding]))
    calls = []
    real = a.build_prompt

    def observed(batch, **kwargs):
        calls.append(batch)
        return real(batch, **kwargs)

    a.build_prompt = observed
    result = a._pack_semantic_sources(sources, max_findings=16 if meta else None,
                                      metadata_text='Generated metadata')
    assert Counter(id(s) for p in result for s in members(p)) == Counter(map(id, sources))
    assert Counter(f.finding_id for p in result for f in p.findings) == Counter(
        f.finding_id for s in sources for f in s.findings
    )
    assert any(len(p.members) > 10 for p in result)
    assert all(len(p.members) <= 16 for p in result)
    assert all(not p.members or len(real(p, metadata_text='Generated metadata').encode()) <= 96000
               for p in result)
    assert len(calls) <= 2 * len(sources) + 18 + len(result)


@pytest.mark.parametrize('meta', [False, True])
@pytest.mark.parametrize('input_budget', [96000, 787500])
def test_near_limit_packets_reserve_selected_schema_and_framing(meta, input_budget):
    from skillspector.llm_analyzer_base import REQUEST_FRAMING_TOKENS
    from skillspector.llm_utils import _StructuredAgentCLIModel

    a = object.__new__(LLMMetaAnalyzer if meta else LLMAnalyzerBase)
    a._timeout = None
    a._input_budget = input_budget
    a._token_counter = lambda text: len(text.encode())
    a.base_prompt = PER_FILE_ANALYSIS_PROMPT if meta else 'Generated independent rules'
    sources = [
        Batch(file_path=f'original-{index}.md', content='', findings=[Finding(
            rule_id='AR2', message='Original finding stays attached', severity='HIGH',
            file=f'original-{index}.md', start_line=1,
        )])
        for index in range(4)
    ]
    kwargs = {'metadata_text': 'Retained original metadata'}
    def packet():
        return Batch(file_path=sources[0].file_path, content='', members=tuple(sources),
                     findings=[finding for source in sources for finding in source.findings])
    # Fill the raw layout almost to the byte cap. Its actual selected response
    # schema and framing exceed the cap, while a three-member packet fits.
    fixed_bytes = len(a.build_prompt(packet(), **kwargs).encode())
    content_size = (96000 - 128 - fixed_bytes) // len(sources)
    assert content_size > 0
    for source in sources:
        source.content = 'x' * content_size
    combined = packet()
    raw = a.build_prompt(combined, **kwargs)
    assert len(raw.encode()) <= 96000
    assert (len(a._serialized_input(raw, batch=combined).encode())
            + REQUEST_FRAMING_TOKENS > 96000)

    result = a._pack_semantic_sources(sources, max_findings=16 if meta else None, **kwargs)
    assert len(result) == 2, 'schema overhead must split the bin instead of abandoning all packing'
    assert any(len(item.members) == 3 for item in result)
    assert Counter(id(source) for item in result for source in members(item)) == Counter(map(id, sources))
    assert Counter(f.finding_id for item in result for f in item.findings) == Counter(
        f.finding_id for source in sources for f in source.findings
    )
    for item in result:
        prompt = a.build_prompt(item, **kwargs)
        schema = a._packet_response_schema() if item.members else a.response_schema
        cli_input = _StructuredAgentCLIModel(None, schema)._augment(prompt)
        assert cli_input == a._serialized_input(prompt, batch=item)
        assert len(cli_input.encode()) + REQUEST_FRAMING_TOKENS <= 96000
        assert a._count_prompt_tokens(prompt, batch=item) <= a._input_budget
