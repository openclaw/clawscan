package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

// Data-model compatibility for the Decisions judge and optional overview.
//
// The fixtures under testdata/ were produced by the real binaries at the
// ClawHub production pin (c3cfaf1, legacy artifact-inspection receipt and the
// retired clawscan-static scanner) and at pre-#148 main (fa01a95), each running
// `--profile clawhub --sandbox off` with scanner fixtures and a stub judge that
// writes the legacy prose result. Host paths were scrubbed.
var legacyArtifactFixtures = []string{
	"legacy-clawhub-artifact-c3cfaf1.json",
	"legacy-clawhub-artifact-fa01a95.json",
}

func TestLegacyStoredArtifactsRemainReadable(t *testing.T) {
	for _, name := range legacyArtifactFixtures {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var original map[string]any
			if err := json.Unmarshal(raw, &original); err != nil {
				t.Fatal(err)
			}
			if _, ok := original["overview"]; ok {
				t.Fatal("legacy fixture unexpectedly has an overview")
			}
			var artifact runner.Artifact
			if err := json.Unmarshal(raw, &artifact); err != nil {
				t.Fatalf("legacy artifact no longer decodes: %v", err)
			}
			if artifact.Overview != nil {
				t.Fatalf("absent overview decoded as %#v", artifact.Overview)
			}
			if artifact.SchemaVersion != "clawscan-run-v1" || !artifact.Complete || artifact.Gate != "pass" {
				t.Fatalf("schema=%q complete=%v gate=%q", artifact.SchemaVersion, artifact.Complete, artifact.Gate)
			}
			result := judgeResultMap(t, artifact)
			for _, field := range []string{"verdict", "summary", "user_guidance", "dimensions"} {
				if _, ok := result[field]; !ok {
					t.Fatalf("legacy judge.result lost %q: %#v", field, result)
				}
			}

			// The CLI summary still reads the legacy verdict and prints no
			// overview lines for an artifact without one.
			var summary bytes.Buffer
			printRunSummary(&summary, runner.RunTargetsResult{Single: &artifact}, "")
			for _, want := range []string{"judge_completed: 1", "clean: 1", "gate: pass"} {
				if !strings.Contains(summary.String(), want) {
					t.Fatalf("summary missing %q:\n%s", want, summary.String())
				}
			}
			if strings.Contains(summary.String(), "overview") {
				t.Fatalf("summary invented an overview:\n%s", summary.String())
			}

			// Re-encoding keeps the absent overview absent and the stored
			// judge result unchanged.
			encoded, err := json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip map[string]any
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if _, ok := roundTrip["overview"]; ok {
				t.Fatal("re-encoded legacy artifact gained an overview key")
			}
			originalJudge := original["judge"].(map[string]any)
			roundJudge := roundTrip["judge"].(map[string]any)
			if !reflect.DeepEqual(originalJudge["result"], roundJudge["result"]) {
				t.Fatalf("legacy judge.result changed on re-encode:\n%v\n%v", originalJudge["result"], roundJudge["result"])
			}
			if originalJudge["status"] != roundJudge["status"] {
				t.Fatalf("judge status changed: %v -> %v", originalJudge["status"], roundJudge["status"])
			}
		})
	}
}

// A project config written before the overview step, here the exact
// pre-#148 clawhub profile with its Codex judge, prompt, and output schema,
// still resolves and runs unchanged: no overview runs or appears in the
// artifact, and the judge's prose result is recorded as before.
func TestPreOverviewProfileConfigRunsUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stub codex judge is a POSIX shell script")
	}
	dir := t.TempDir()
	configDir := filepath.Join(dir, "security")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for source, dest := range map[string]string{
		filepath.Join("..", "..", "schemas", "testdata", "clawhub-profile-fa01a95.yml"): "clawscan.yml",
		filepath.Join("testdata", "legacy-clawhub-prompt-fa01a95.md"):                   "prompt.md",
		filepath.Join("testdata", "legacy-clawhub-output-fa01a95.schema.json"):          "output.schema.json",
	} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(configDir, dest), string(data))
	}
	target := filepath.Join(dir, "skill")
	writeSkill(t, target, "# Notes\nAppend notes to ./notes.md.\n")
	aigFixture := filepath.Join(dir, "aig.json")
	writeFile(t, aigFixture, `{"version":"2.1.0","runs":[{"results":[]}]}`)
	const legacyResult = `{"verdict":"benign","confidence":"high","summary":"Legacy prose summary.","dimensions":{"purpose_capability":{"status":"ok","detail":"d"},"instruction_scope":{"status":"ok","detail":"d"},"install_mechanism":{"status":"ok","detail":"d"},"environment_proportionality":{"status":"ok","detail":"d"},"persistence_privilege":{"status":"ok","detail":"d"}},"scan_findings_in_context":[],"user_guidance":"Legacy guidance."}`

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = run([]string{
			target, "--config", filepath.Join(configDir, "clawscan.yml"), "--profile", "clawhub",
			"--scanner-result", "aig=" + aigFixture, "--sandbox", "off", "--json",
		}, append(os.Environ(), "CLAWSCAN_TEST_OVERVIEW_JSON="+legacyResult, "OPENAI_API_KEY=legacy-fixture-key"))
	})
	if runErr != nil {
		t.Fatalf("pre-overview profile config failed: %v\n%s", runErr, stdout)
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(stdout), &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["overview"]; ok {
		t.Fatal("a profile without overview.command produced an overview")
	}
	var artifact runner.Artifact
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatal(err)
	}
	if !artifact.Complete || artifact.Status != "completed" || artifact.ConfigSource == nil || *artifact.ConfigSource == "built-in" {
		t.Fatalf("status=%q complete=%v config=%v", artifact.Status, artifact.Complete, artifact.ConfigSource)
	}
	result := judgeResultMap(t, artifact)
	if result["summary"] != "Legacy prose summary." || result["user_guidance"] != "Legacy guidance." {
		t.Fatalf("legacy Codex judge result changed: %#v", result)
	}
	if artifact.Judge.ConfiguredModel != "gpt-6.1-sol" {
		t.Fatalf("legacy Codex judge provenance = %q", artifact.Judge.ConfiguredModel)
	}
}
