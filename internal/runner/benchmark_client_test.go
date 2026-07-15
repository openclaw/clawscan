package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHuggingFaceBenchmarkClientFetchesSkillTrustBenchFromCanonicalJSONL(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/data/test_cases.jsonl" {
			http.Error(w, "rows API unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, `{"id":"case_00001","judgment":"normal","risk_labels":[],"source":"safe_pool","base_category":"productivity","primary_pattern":null,"attack_pattern":[],"skill_path":"benchmark_full_v1.0/case_00001"}`)
		fmt.Fprintln(w, `{"id":"case_00002","judgment":"malicious","risk_labels":["T04"],"source":"injected","base_category":"devtool","primary_pattern":"E2","attack_pattern":["E2"],"skill_path":"benchmark_full_v1.0/case_00002"}`)
		fmt.Fprintln(w, `{"id":"case_00003","judgment":"suspicious","risk_labels":["T01"],"source":"injected","base_category":"finance","primary_pattern":"PE3","attack_pattern":["PE3"],"skill_path":"benchmark_full_v1.0/case_00003"}`)
	}))
	t.Cleanup(server.Close)

	client := HuggingFaceBenchmarkClient{
		Endpoint:               server.URL + "/rows",
		SkillTrustBenchRowsURL: server.URL + "/data/test_cases.jsonl",
	}
	rows, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 1, 1)
	if err != nil {
		t.Fatalf("FetchSkillTrustBenchRows err = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 direct JSONL request", requests)
	}
	if len(rows) != 1 || rows[0].ID != "case_00002" || rows[0].Judgment != "malicious" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestHuggingFaceBenchmarkClientValidatesSkillTrustBenchBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"id":"case_00001","judgment":"normal","skill_path":"benchmark_full_v1.0/case_00001"}`)
		fmt.Fprintln(w, `{"id":"case_00002","judgment":"malicious","skill_path":"benchmark_full_v1.0/case_00002"}`)
	}))
	t.Cleanup(server.Close)

	client := HuggingFaceBenchmarkClient{SkillTrustBenchRowsURL: server.URL}
	if _, err := client.FetchSkillTrustBenchRows("other/dataset", defaultSkillTrustBenchSplit, 0, 1); err == nil {
		t.Fatal("expected unsupported dataset error")
	}
	if _, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, "other", 0, 1); err == nil {
		t.Fatal("expected unsupported split error")
	}
	if _, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, -1, 1); err == nil {
		t.Fatal("expected negative offset error")
	}
	if _, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 0, -1); err == nil {
		t.Fatal("expected negative limit error")
	}

	maxInt := int(^uint(0) >> 1)
	rows, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 1, maxInt)
	if err != nil {
		t.Fatalf("FetchSkillTrustBenchRows err = %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "case_00002" {
		t.Fatalf("rows = %#v", rows)
	}
}
