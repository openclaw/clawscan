"""Generated offline regressions for aggregate OSV evidence retention."""

import json
from dataclasses import asdict

import httpx
import pytest
from skillspector.nodes.analyzers import osv_client as osv


@pytest.fixture
def provider(monkeypatch):
    osv.clear_cache()
    original = httpx.Client
    observed = []
    counts = {"generated-pdf": 112, "generated-image": 194, "generated-engine": 0}
    record = lambda name, index: {
        "id": f"{name}-{index}", "summary": "Generated inert advisory",
        "aliases": [f"ALIAS-{name}-{index}"],
        "database_specific": {"severity": "CRITICAL"},
    }

    def handler(request):
        observed.append(request)
        payload = json.loads(request.content) if request.content else {}
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [
                {"id": record(query["package"]["name"], i)["id"]}
                for i in range(counts[query["package"]["name"]])
            ]} for query in payload["queries"]]})
        if request.url.path == "/v1/query":
            name = payload["package"]["name"]
            return httpx.Response(200, json={"vulns": [record(name, i) for i in range(counts[name])]})
        raise AssertionError("Large advisory sets must use bounded full package queries")

    monkeypatch.setattr(osv.httpx, "Client", lambda **kwargs: original(
        transport=httpx.MockTransport(handler), **kwargs))
    yield counts, observed, record
    osv.clear_cache()


def test_three_unpinned_packages_retain_all_306_exact_advisories(provider):
    counts, requests, record = provider
    budget = osv.OsvQueryBudget.create()
    packages = [(name, None) for name in counts]
    result = osv.query_batch(packages, "PyPI", budget=budget)
    assert not result.limitations
    assert [len(items) for items in result] == [112, 194, 0]
    assert budget.results_retained == 306
    assert budget.result_bytes_retained == sum(
        len(json.dumps(asdict(item), ensure_ascii=True, separators=(",", ":")).encode())
        for items in result for item in items)
    assert 0 < budget.result_bytes_retained < budget.max_result_bytes
    for (name, _), results in zip(packages, result, strict=True):
        assert [asdict(item) for item in results] == [{
            "vuln_id": record(name, i)["id"], "summary": "Generated inert advisory",
            "severity": "CRITICAL", "aliases": (f"ALIAS-{name}-{i}",),
        } for i in range(counts[name])]
    assert len(requests) == 3
    assert all("version" not in query for request in requests
               for query in (json.loads(request.content).get("queries") or [json.loads(request.content)]))


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("boundary", ["bytes", "records"])
def test_limits_stay_aggregate_across_separate_manifests(provider, cached, boundary):
    counts, requests, _ = provider
    if cached:
        warm = osv.query_batch([(name, None) for name in counts], "PyPI")
        assert not warm.limitations
    request_count = len(requests)
    budget = osv.OsvQueryBudget.create()
    if boundary == "bytes":
        budget.max_result_bytes = 10_000
    else:
        budget.max_results = 250
    first = osv.query_batch([("generated-pdf", None)], "PyPI", budget=budget)
    second = osv.query_batch([("generated-image", None)], "PyPI", budget=budget)
    assert first.limitations or second.limitations
    assert budget.results_retained == sum(len(items) for response in (first, second) for items in response)
    assert budget.results_retained <= budget.max_results
    assert budget.result_bytes_retained <= budget.max_result_bytes
    assert not any(key[0] == "generated-image" for key in osv._cache) or cached
    assert not cached or len(requests) == request_count


@pytest.mark.parametrize("count", [1024, 1025])
def test_count_ceiling_is_finite_even_for_small_cached_records(provider, count):
    for i in range(5):
        osv._put_cache((f"generated-{i}", None, "PyPI"), [
            osv.VulnResult(f"V-{i}-{n}", "", "HIGH", ()) for n in range(min(256, max(0, count-i*256)))])
    budget = osv.OsvQueryBudget.create()
    result = osv.query_batch([(f"generated-{i}", None) for i in range(5)], "PyPI", budget=budget)
    assert budget.max_results == 1024
    assert budget.results_retained == min(count, 1024)
    assert bool(result.limitations) == (count > 1024)


@pytest.mark.parametrize("offset", [-1, 0])
@pytest.mark.parametrize("summary", ["Generated inert", "\u2603" * 512, "\ud800"])
def test_serialized_byte_boundary_is_exact_for_cached_unicode(provider, offset, summary):
    item = osv.VulnResult("V-GENERATED", summary, "HIGH", ("GENERATED-ALIAS",))
    size = len(json.dumps(asdict(item), ensure_ascii=True, separators=(",", ":")).encode())
    osv._put_cache(("generated", None, "PyPI"), [item])
    budget = osv.OsvQueryBudget.create()
    budget.max_result_bytes = size + offset
    result = osv.query_batch([("generated", None)], "PyPI", budget=budget)
    assert result[0] == ([item] if offset == 0 else [])
    assert budget.result_bytes_retained == (size if offset == 0 else 0)
    assert bool(result.limitations) == (offset == -1)


def test_cached_evidence_cannot_bypass_the_shared_deadline(provider):
    osv._put_cache(("generated", None, "PyPI"), [osv.VulnResult("V-1", "", "HIGH", ())])
    budget = osv.OsvQueryBudget.create(timeout_seconds=0)
    result = osv.query_batch([("generated", None)], "PyPI", budget=budget)
    assert result == [[]]
    assert budget.results_retained == budget.result_bytes_retained == 0
    assert any(item.reason is osv.LedgerReason.RUNTIME_LIMIT for item in result.limitations)
