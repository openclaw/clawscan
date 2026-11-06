package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

// Exercise both feature branches together. An error-level scanner finding is
// evidence, not a verdict; dependencies excluded by the plugin audit must not
// be reintroduced by the judge's artifact reader.
func TestIntegratedPluginAIGDecisionsOverview(t *testing.T) {
	requirePython(t)
	stub, server := newDecisionsStub(t)
	stub.verdict = "benign"
	h := newAIGMCPHarness(t)
	target := filepath.Join(h.dir, "plugin")
	writeAIGMCPPlugin(t, target)
	const marker = "CLAWSCAN_DEPENDENCY_SHOULD_NOT_ENTER_JUDGE"
	writeFile(t, filepath.Join(target, "node_modules", "left-pad", "index.js"), marker+strings.Repeat("x", 100000))
	writeFile(t, filepath.Join(target, "src", "vendor", "node_modules", "dep", "index.js"), marker)
	env := append(h.env("ok"),
		"DECISIONS_BASE_URL="+server.URL,
		"DECISIONS_API_KEY="+testDecisionsKey,
		"DECISIONS_MODEL=",
		"OPENAI_BASE_URL=",
		"CLAWSCAN_TEST_OVERVIEW_JSON="+testOverviewJSON,
	)
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = run([]string{target, "--profile", "clawhub", "--judge", decisionsJudgeCommand, "--sandbox", "off", "--json"}, env)
	})
	var artifact runner.Artifact
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("run: %v judge=%#v", runErr, artifact.Judge)
	}
	if got := scannerIDs(artifact); got != "aig-mcp" {
		t.Fatalf("scanners = %q", got)
	}
	if h.skillScannerCalls(t) != "" {
		t.Fatal("individual skill scanners ran on plugin")
	}
	result := judgeResultMap(t, artifact)
	if result["verdict"] != "benign" {
		t.Fatalf("SARIF severity overrode judge verdict: %#v", result)
	}
	if artifact.Overview == nil || artifact.Overview.Status != "completed" {
		t.Fatalf("overview = %#v", artifact.Overview)
	}
	if !artifact.Complete || artifact.Gate != "pass" {
		t.Fatalf("run incomplete: %#v", artifact)
	}
	if stub.requestCount() != 1 {
		t.Fatalf("Decisions requests = %d", stub.requestCount())
	}
	stub.mu.Lock()
	input, err := json.Marshal(stub.requests[0].Input)
	stub.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(input), "MCP01") {
		t.Fatal("AIG SARIF finding missing from judge")
	}
	if !strings.Contains(string(input), "skills/helper/SKILL.md") {
		t.Fatal("embedded skill omitted from judge")
	}
	if strings.Contains(string(input), marker) {
		t.Fatal("excluded node_modules content reintroduced into judge input")
	}
	if strings.Contains(stdout, testDecisionsKey) {
		t.Fatal("judge credential leaked in artifact")
	}
}
