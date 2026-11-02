"""Inert source fixtures: parse/scan only, never execute their shell content."""
import pytest
from skillspector.nodes.analyzers import static_patterns_tool_misuse as tool
from skillspector import shell_source
from skillspector.markdown_tokens import MarkdownCodeSpanClosers
CASES={'bash-lf-positive': {'content': '```bash\necho "${VALUE}"\n```\n',
                      'sha256': '1f7147d229c710e6e14ecc45de5742d60b566d7b342b754593d5cd55d6c6c021',
                      'expectedBashBodyReceipt': True,
                      'reason': 'bash-lf-positive'},
 'bash-unicode-prefix-positive': {'content': 'Résumé 🦀\n\n```bash\necho "${VALUE}"\n```\n',
                                  'sha256': '84e423d41252381573ee70067927512c656fb3e9a7edff52fd57e9e276a029f6',
                                  'expectedBashBodyReceipt': True,
                                  'reason': 'bash-unicode-prefix-positive'},
 'bash-tilde-positive': {'content': '~~~bash\necho "${VALUE}"\n~~~\n',
                         'sha256': '1b4a3af386abf455ca4d44adb109eeeaa35cc97dd727da260099de5cd580b445',
                         'expectedBashBodyReceipt': True,
                         'reason': 'bash-tilde-positive'},
 'bash-close-eof-positive': {'content': '```bash\necho "${VALUE}"\n```',
                             'sha256': '9933966c340fc5eaed421fbe6c8b8262c9d5b47894c9f2e83e65d6e427aeb21a',
                             'expectedBashBodyReceipt': True,
                             'reason': 'bash-close-eof-positive'},
 'sh-unattested': {'content': '```sh\necho "${VALUE}"\n```\n',
                   'sha256': 'dcb83b2c6de6a5ce0bf54d60dee3cf8b542e305f2e8e42cb4d57c0737fd4b3a8',
                   'expectedBashBodyReceipt': False,
                   'reason': 'sh-unattested'},
 'shell-unattested': {'content': '```shell\necho "${VALUE}"\n```\n',
                      'sha256': '38d5fd5777eef26f5304d1ec41f7444bceb005bbe02cb24b0ca8faade2afc42f',
                      'expectedBashBodyReceipt': False,
                      'reason': 'shell-unattested'},
 'zsh-unattested': {'content': '```zsh\necho "${VALUE}"\n```\n',
                    'sha256': '55b0fea6040e106dfd0a0be50ec22bbc4c0d1266296bcec4991e1301b2f3c7dd',
                    'expectedBashBodyReceipt': False,
                    'reason': 'zsh-unattested'},
 'powershell-unattested': {'content': '```powershell\necho "${VALUE}"\n```\n',
                           'sha256': 'e1ff0a3cab85297f0a1bf32d2d6af4830be436fa61b3a5ce9644c101f91f8a0c',
                           'expectedBashBodyReceipt': False,
                           'reason': 'powershell-unattested'},
 'bash-uppercase-unattested': {'content': '```BASH\necho "${VALUE}"\n```\n',
                               'sha256': 'e23cc3331fa0babc85bc96fc3628c03948cb5f8e5eb99f7c5eb45027353431b6',
                               'expectedBashBodyReceipt': False,
                               'reason': 'bash-uppercase-unattested'},
 'bash-extra-info-unattested': {'content': '```bash extra\necho "${VALUE}"\n```\n',
                                'sha256': 'a4fc98748c0847f1e4c84f8cb639093effdadd375522b5d6d785e22cd5b1dac3',
                                'expectedBashBodyReceipt': False,
                                'reason': 'bash-extra-info-unattested'},
 'u2028-opening-false-line': {'content': '```bash\u2028echo "${VALUE}"\n```\n',
                              'sha256': 'df29197b9161342f818d57088de8f4ecda407b2bae79cb9bd66377788f2116d3',
                              'expectedBashBodyReceipt': False,
                              'reason': 'u2028-opening-false-line'},
 'u2029-opening-false-line': {'content': '```bash\u2029echo "${VALUE}"\n```\n',
                              'sha256': '03a37e417e669422e28f58cf52d29e7dd1f1b9324e7e0f2ca0f097156daaa6df',
                              'expectedBashBodyReceipt': False,
                              'reason': 'u2029-opening-false-line'},
 'nel-opening-false-line': {'content': '```bash\x85echo "${VALUE}"\n```\n',
                            'sha256': '8a1ae42c3b02b5d1f2134b37926b03b35225d6f94f063f09fee24495111de1d4',
                            'expectedBashBodyReceipt': False,
                            'reason': 'nel-opening-false-line'},
 'u2028-closing-false-line': {'content': '```bash\necho "${VALUE}"\n```\u2028tail\n',
                              'sha256': '9d2bfb02c45c339feab3cdf318dd108761c0c8ce2d873e7ef07d631ba15999d6',
                              'expectedBashBodyReceipt': False,
                              'reason': 'u2028-closing-false-line'},
 'list-dedentation': {'content': '- item\n\n  ```bash\necho "${VALUE}"\n  ```\n',
                      'sha256': '357552f8f790514bde8ae03cc2f926bbbe5522a4ed7e7086a6a197adf43b5705',
                      'expectedBashBodyReceipt': False,
                      'reason': 'list-dedentation'},
 'list-nested-fence': {'content': '- ```bash\n  echo "${VALUE}"\n  ```\n',
                       'sha256': '1ad314b32109db130191131ac2598706c5bb67a96823147ece9cee739ace2a05',
                       'expectedBashBodyReceipt': False,
                       'reason': 'list-nested-fence'},
 'blockquote-fence': {'content': '> ```bash\n> echo "${VALUE}"\n> ```\n',
                      'sha256': '062988908024e3828038ad1de32872b7b0ede5c3bc52592a336215f3b1f21f91',
                      'expectedBashBodyReceipt': False,
                      'reason': 'blockquote-fence'},
 'four-space-indent': {'content': '    ```bash\n    echo "${VALUE}"\n    ```\n',
                       'sha256': 'd9f4deadf8970bf6a3c4a549431c27f08e3ae8f32c666351e8934d2fc0d314d3',
                       'expectedBashBodyReceipt': False,
                       'reason': 'four-space-indent'},
 'two-space-fence': {'content': '  ```bash\necho "${VALUE}"\n  ```\n',
                     'sha256': 'd5311a1de5b735ded9a9408ccb6b7dd8b68480ae3dd1ab6872b62c704afc59a4',
                     'expectedBashBodyReceipt': False,
                     'reason': 'two-space-fence'},
 'unclosed-fence': {'content': '```bash\necho "${VALUE}"\n',
                    'sha256': 'aa36b9c2c606b9f91c33972464e87962eec38c8b1697ddeffb270154b1243a4b',
                    'expectedBashBodyReceipt': False,
                    'reason': 'unclosed-fence'},
 'wrong-marker-close': {'content': '```bash\necho "${VALUE}"\n~~~\n',
                        'sha256': '1873ef8bab3c1909350807bda316bae6b85d84a6d87d5df17af78831ec0f1a20',
                        'expectedBashBodyReceipt': False,
                        'reason': 'wrong-marker-close'},
 'short-close': {'content': '````bash\necho "${VALUE}"\n```\n',
                 'sha256': '679459daea570fbaa4ea8b8647f3ea886c6a680ca2f3c58b10a88937ed744906',
                 'expectedBashBodyReceipt': False,
                 'reason': 'short-close'},
 'backtick-in-info': {'content': '```bash`\necho "${VALUE}"\n```\n',
                      'sha256': '4e203357e0a4b3fc1151eb1984ff9604445244068e6275b8c6dc6c828528824c',
                      'expectedBashBodyReceipt': False,
                      'reason': 'backtick-in-info'},
 'crlf-conservative': {'content': '```bash\r\necho "${VALUE}"\r\n```\r\n',
                       'sha256': '1f691535b6c08e7b1f66623569abdece5fb84c55d05d71ab92fbfc3fa1ea9de8',
                       'expectedBashBodyReceipt': False,
                       'reason': 'crlf-conservative'},
 'bare-cr-conservative': {'content': '```bash\recho "${VALUE}"\r```\r',
                          'sha256': 'd6d634b8a23a426ce739e709c750cce53a100f3335eeaaa17fa913509c7dbfde',
                          'expectedBashBodyReceipt': False,
                          'reason': 'bare-cr-conservative'},
 'mixed-cr-body-conservative': {'content': '```bash\necho "${VALUE}"\r\n```\n',
                                'sha256': '1d9ab87d0a6d3a66a84e96efbcfa14b4d0fe3f6d760664c2fc51ff3cbef727f5',
                                'expectedBashBodyReceipt': False,
                                'reason': 'mixed-cr-body-conservative'},
 'quote-before-fence-positive-body': {'content': 'Prose "unclosed\n'
                                                 '\n'
                                                 '```bash\n'
                                                 'echo "${VALUE}"\n'
                                                 '```\n',
                                      'sha256': 'dff50b0c1782c7b0e6f8b531fc8661e3cf28ac4c282c2af4a2ac6d057192c48c',
                                      'expectedBashBodyReceipt': True,
                                      'reason': 'quote-before-fence-positive-body'},
 'other-code-unclosed': {'content': '```python\n'
                                    'text="unclosed\n'
                                    '```\n'
                                    '\n'
                                    '```bash\n'
                                    'echo "${VALUE}"\n'
                                    '```\n',
                         'sha256': 'c1bc38b83962251b874bfbd5d9cacb18c9823f1b6001c45566ddce87e4d10ff8',
                         'expectedBashBodyReceipt': True,
                         'reason': 'other-code-unclosed'},
 'unclosed-other-code-borrows': {'content': '```python\n'
                                            'text="unclosed\n'
                                            '```bash\n'
                                            'echo "${VALUE}"\n'
                                            '```\n',
                                 'sha256': 'ece293df4f0831d0a3fd64b5145409a501a157105b632481d8989fc63bbbc965',
                                 'expectedBashBodyReceipt': False,
                                 'reason': 'unclosed-other-code-borrows'}}
@pytest.mark.parametrize('name',list(CASES))
def test_context_contract(name):
    item=CASES[name];text=item['content'];ranges=[]
    projected=tool._markdown_shell_text(text,lambda:None,shell_fence_ranges=ranges)
    assert bool(ranges)==item['expectedBashBodyReceipt'], (name,ranges)
    for start,end in ranges:
        assert text[start:end]==projected[start:end]
        assert ranges.count((start,end))==1

@pytest.mark.parametrize('name',list(CASES))
def test_canonical_receipt_exact_source(name):
    text=CASES[name]['content']
    bodies=MarkdownCodeSpanClosers(text,lambda:None).bash_fence_bodies()
    assert bool(bodies)==CASES[name]['expectedBashBodyReceipt']
    for start,end in bodies:
        assert text[start:end]=='echo "${VALUE}"\n'


def test_exact_candidate_and_closing_quote():
    text='echo "Résumé ${VALUE}"\n';owner=shell_source.ShellSourceOwnership(text,lambda:None)
    end=text.rindex('"');start=text.index('${VALUE}')
    assert owner.owns_double_quoted_candidate(start,end)
    assert end in owner.quote_closing_offsets()
    assert not owner.owns_double_quoted_candidate(0,end)
    assert not owner.owns_double_quoted_candidate(start,end-1)
    assert not owner.owns_double_quoted_candidate(start+len('${VALUE}')+2,end)

@pytest.mark.parametrize('fault',['missing','deadline','oversize'])
def test_no_canonical_proof_publishes_neither_sink(monkeypatch,fault):
    text='echo "${VALUE}"\n'
    if fault=='missing':monkeypatch.setattr(shell_source.shutil,'which',lambda _:None)
    elif fault=='deadline':monkeypatch.setattr(shell_source,'PARSER_SECONDS',0)
    else:text+='x'*65537
    closers=set()
    assert tool._shell_quoted_candidate_limits(text,lambda:None,quote_closers=closers)=={}
    assert closers==set()

@pytest.mark.parametrize('exc',[TimeoutError,RuntimeError])
def test_receipt_cancellation_propagates(exc):
    def cancel():raise exc('caller cancelled')
    with pytest.raises(exc):tool.has_bounded_parse_exhaustion('```bash\necho "${VALUE}"\n```\n',cancel,file_type='markdown')


def test_unclosed_other_code_cannot_lend_quote_to_bash():
    text=CASES['unclosed-other-code-borrows']['content']
    assert MarkdownCodeSpanClosers(text,lambda:None).bash_fence_bodies()==()


def test_document_budget_refuses_all_fence_receipts():
    text='```bash\necho "${VALUE}"\n```\n'+'x'*1048576
    assert MarkdownCodeSpanClosers(text,lambda:None).bash_fence_bodies()==()

@pytest.mark.parametrize('text', ['```bash\necho x\xa0# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\u2003# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\u2009# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\u3000# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\x85# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\u2028# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\u2029# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x # "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\necho x\t# "\necho test" ; $TOOL -rf / # "\n```\n',
 '```bash\nshopt -s expand_aliases\na\'li\'as q=\': "\'\nq test" ; $TOOL -rf / # "\n```\n'])
def test_unicode_word_boundary_and_quoted_alias_do_not_clear_unknown_command(text):
    from skillspector.nodes.analyzers import static_runner
    result=static_runner.run_static_patterns_with_ledger(
        {'components':['SKILL.md'],'file_cache':{'SKILL.md':text}},[tool])
    assert result['inspection_ledger'][0]['outcome']=='partial'


def test_nested_execution_cannot_borrow_enclosing_quote_receipt():
    text='echo "$(echo "outer $(echo $VALUE) tail")"\n'
    owner=shell_source.ShellSourceOwnership(text,lambda:None)
    candidate=text.index('$VALUE')
    end=text.index('"',text.index(' tail'))
    assert owner.command_starts is not None
    assert not owner.owns_double_quoted_candidate(candidate,end)
    assert owner.quote_closing_offsets()==frozenset()

@pytest.mark.parametrize("text", ['Prose "intro\n$TOOL -rf /\n\n```bash\nclient mcp add example \\\n  --transport streamable-http \\\n  --url https://example.test/api/mcp \\\n  --header "Authorization=Bearer ${EXAMPLE_API_KEY}" \\\n  --header "X-Example-Agent-Platform=client"\n```\n\n```json\n{\n  "mcp": {\n    "servers": {\n      "example": {\n        "transport": "streamable-http",\n        "url": "https://example.test/api/mcp",\n        "headers": {\n          "Authorization": "Bearer ${EXAMPLE_API_KEY}",\n          "X-Example-Agent-Platform": "client"\n        }\n      }\n    }\n  }\n}\n```\n', '```python\ntext="intro\n$TOOL -rf /\n```\n\n```bash\nclient mcp add example \\\n  --transport streamable-http \\\n  --url https://example.test/api/mcp \\\n  --header "Authorization=Bearer ${EXAMPLE_API_KEY}" \\\n  --header "X-Example-Agent-Platform=client"\n```\n\n```json\n{\n  "mcp": {\n    "servers": {\n      "example": {\n        "transport": "streamable-http",\n        "url": "https://example.test/api/mcp",\n        "headers": {\n          "Authorization": "Bearer ${EXAMPLE_API_KEY}",\n          "X-Example-Agent-Platform": "client"\n        }\n      }\n    }\n  }\n}\n```\n'])
def test_dynamic_commands_cannot_borrow_quotes_across_markdown_context(text):
    from skillspector.nodes.analyzers import static_runner
    result=static_runner.run_static_patterns_with_ledger(
        {'components':['SKILL.md'],'file_cache':{'SKILL.md':text}},[tool])
    assert result['inspection_ledger'][0]['outcome']=='partial'
