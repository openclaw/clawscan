package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
)

const aigMCPStubSARIF = `{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "aig-mcp-scan", "version": "0.2.0", "rules": [
      {"id": "MCP01", "name": "Token Mismanagement and Secret Exposure"},
      {"id": "MCP03", "name": "Tool Poisoning"}
    ]}},
    "results": [
      {
        "ruleId": "MCP01",
        "level": "error",
        "message": {"text": "Tool handler posts gateway credentials to a remote host"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "plugin/index.js"}, "region": {"startLine": 7, "endLine": 9}}}],
        "properties": {"description": "Reads stored credentials and sends them off-box.", "severity": "High"}
      },
      {
        "ruleId": "MCP03",
        "level": "warning",
        "message": {"text": "Tool description hides instructions for the model"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "plugin/src/tool.js"}}}],
        "properties": {"severity": "Medium"}
      }
    ],
    "properties": {"securityScore": 35, "scanNote": "complete"}
  }]
}`

// aigMCPStub is a stand-in aig-mcp-scan that records how ClawScan invoked it
// and what plugin tree it was shown, then behaves as CLAWSCAN_TEST_AIG_MCP_MODE says.
const aigMCPStub = `#!/bin/sh
set -eu
log="$CLAWSCAN_TEST_AIG_MCP_LOG"
printf '%s\n' "$@" > "$log.args"
pwd > "$log.cwd"
repo=""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo=$2; shift 2 ;;
    -o) out=$2; shift 2 ;;
    *) shift ;;
  esac
done
(cd "$repo" && find . -type f | LC_ALL=C sort) > "$log.files"
if [ -n "${LLM_API_KEY:-}" ] || [ -n "${OPENAI_API_KEY:-}" ]; then echo present > "$log.key"; fi
printf 'scanner scratch\n' > "$repo/scanner-scratch.txt"
case "${CLAWSCAN_TEST_AIG_MCP_MODE:-ok}" in
  crash)
    echo "Traceback: openai.NotFoundError: model gpt-unknown does not exist" >&2
    exit 1
    ;;
  model-failure)
    echo "2026-11-03 17:00:00 | ERROR    | LLM chat failed after retries: AuthenticationError: invalid key" >&2
    ;;
esac
cat "$CLAWSCAN_TEST_AIG_MCP_SARIF" > "$out"
`

// skillScannerStub records any invocation of a skill scanner binary. Plugin
// targets must never reach it.
const skillScannerStub = `#!/bin/sh
printf '%s\n' "$0 $*" >> "$CLAWSCAN_TEST_SKILL_SCANNER_LOG"
exit 3
`

type aigMCPHarness struct {
	dir      string
	log      string
	sarif    string
	judge    string
	prompt   string
	baseArgs []string
	// skillFixtures stand in for the skill scanners on skill targets.
	skillFixtures []string
}

func newAIGMCPHarness(t *testing.T) aigMCPHarness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub scanner uses a POSIX shell")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	writeFile(t, filepath.Join(bin, "aig-mcp-scan"), aigMCPStub)
	if err := os.Chmod(filepath.Join(bin, "aig-mcp-scan"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"skillspector", "aig-skill-scan", "uvx", "skill-scanner", "snyk-agent-scan"} {
		writeFile(t, filepath.Join(bin, name), skillScannerStub)
		if err := os.Chmod(filepath.Join(bin, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	harness := aigMCPHarness{
		dir:    dir,
		log:    filepath.Join(dir, "aig-mcp"),
		sarif:  filepath.Join(dir, "stub.sarif.json"),
		prompt: filepath.Join(dir, "rendered-prompt.md"),
	}
	writeFile(t, harness.sarif, aigMCPStubSARIF)
	skillSpector := filepath.Join(dir, "skillspector.json")
	writeFile(t, skillSpector, `{"status":"clean","findings":[]}`)
	aig := filepath.Join(dir, "aig.sarif.json")
	writeFile(t, aig, `{"version":"2.1.0","runs":[{"results":[]}]}`)
	harness.judge = `cat {{ prompt:clawhub/prompt.md }} > "$CLAWSCAN_TEST_PROMPT_PATH"; ` + stubJudgeCommand()
	harness.skillFixtures = []string{
		"--scanner-result", "skillspector=" + skillSpector,
		"--scanner-result", "aig=" + aig,
	}
	harness.baseArgs = []string{
		"--profile", "clawhub",
		"--judge", harness.judge,
		"--sandbox", "off",
		"--json",
	}
	return harness
}

func (harness aigMCPHarness) env(mode string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"OPENAI_API_KEY=fixture-private-openai-key",
		"CLAWSCAN_TEST_AIG_MCP_LOG=" + harness.log,
		"CLAWSCAN_TEST_AIG_MCP_SARIF=" + harness.sarif,
		"CLAWSCAN_TEST_AIG_MCP_MODE=" + mode,
		"CLAWSCAN_TEST_PROMPT_PATH=" + harness.prompt,
		"CLAWSCAN_TEST_SKILL_SCANNER_LOG=" + harness.log + ".skill-scanners",
		// The stub runs on the host; production runs use the Docker sandbox.
		"AIG_MCP_SCAN_ALLOW_HOST_EXEC=1",
	}
}

func (harness aigMCPHarness) skillScannerCalls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(harness.log + ".skill-scanners")
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (harness aigMCPHarness) run(t *testing.T, target string, mode string, extra ...string) (runner.Artifact, error) {
	t.Helper()
	var runErr error
	args := append(append([]string{target}, harness.baseArgs...), extra...)
	stdout := captureStdout(t, func() {
		runErr = run(args, harness.env(mode))
	})
	var artifact runner.Artifact
	if err := json.Unmarshal([]byte(stdout), &artifact); err != nil {
		t.Fatalf("artifact JSON: %v\n%s", err, stdout)
	}
	return artifact, runErr
}

func (harness aigMCPHarness) invoked() bool {
	_, err := os.Stat(harness.log + ".args")
	return err == nil
}

func writeAIGMCPPlugin(t *testing.T, target string) {
	t.Helper()
	writePlugin(t, target, "probe-plugin")
	writeFile(t, filepath.Join(target, "package.json"), `{"name":"probe-plugin","version":"1.0.0"}`)
	writeFile(t, filepath.Join(target, "src", "tool.js"), "export const tool = {};\n")
	writeFile(t, filepath.Join(target, "dist", "index.js"), "export default function register() {}\n")
	writeFile(t, filepath.Join(target, "hooks", "before-prompt.js"), "export {};\n")
	writeFile(t, filepath.Join(target, "skills", "helper", "SKILL.md"), "# Helper skill\n")
	writeFile(t, filepath.Join(target, "skills", "helper", "scripts", "run.sh"), "#!/bin/sh\necho hi\n")
	writeFile(t, filepath.Join(target, "node_modules", "left-pad", "index.js"), "module.exports = 1;\n")
	writeFile(t, filepath.Join(target, "src", "vendor", "node_modules", "dep", "index.js"), "module.exports = 2;\n")
}

func TestClawHubProfileRunsOnlyAIGMCPOnStagedPluginWithoutNodeModules(t *testing.T) {
	harness := newAIGMCPHarness(t)
	target := filepath.Join(harness.dir, "plugin-under-review")
	writeAIGMCPPlugin(t, target)

	artifact, err := harness.run(t, target, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != "plugin" {
		t.Fatalf("target kind = %q", artifact.Target.Kind)
	}
	if got := scannerIDs(artifact); got != "aig-mcp" {
		t.Fatalf("plugin scanners = %q, want exactly aig-mcp", got)
	}
	if calls := harness.skillScannerCalls(t); calls != "" {
		t.Fatalf("skill scanners ran for a plugin target:\n%s", calls)
	}
	result := artifact.Scanners["aig-mcp"]
	if result.Status != "completed" || result.Error != "" {
		t.Fatalf("aig-mcp = %#v", result)
	}
	var raw, want any
	if err := json.Unmarshal(result.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(aigMCPStubSARIF), &want); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(raw, want) {
		t.Fatalf("raw SARIF was not preserved:\n%s", result.Raw)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}

	files, err := os.ReadFile(harness.log + ".files")
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := "./dist/index.js\n./hooks/before-prompt.js\n./index.js\n./openclaw.plugin.json\n./package.json\n" +
		"./skills/helper/SKILL.md\n./skills/helper/scripts/run.sh\n./src/tool.js\n"
	if string(files) != wantFiles {
		t.Fatalf("scanner saw files:\n%s\nwant:\n%s", files, wantFiles)
	}
	cwd, err := os.ReadFile(harness.log + ".cwd")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(cwd)), target) {
		t.Fatalf("scanner ran inside the original target: %s", cwd)
	}
	if _, err := os.Stat(filepath.Join(target, "scanner-scratch.txt")); !os.IsNotExist(err) {
		t.Fatalf("scanner wrote into the original target: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "node_modules", "left-pad", "index.js")); err != nil {
		t.Fatalf("original node_modules changed: %v", err)
	}
	if key, err := os.ReadFile(harness.log + ".key"); err != nil || strings.TrimSpace(string(key)) != "present" {
		t.Fatalf("scanner did not receive the API key through its environment: %v", err)
	}

	args, err := os.ReadFile(harness.log + ".args")
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSuffix(string(args), "\n"), "\n")
	for _, pair := range [][2]string{
		{"--repo", "plugin"},
		{"--language", "en"},
		{"-m", "gpt-6.1-sol"},
		{"-u", "https://api.openai.com/v1"},
		{"-o", "aig-mcp-scan.sarif.json"},
	} {
		if !hasArgPair(argv, pair[0], pair[1]) {
			t.Fatalf("argv missing %s %s: %#v", pair[0], pair[1], argv)
		}
	}
	prompt := argAfter(argv, "-p")
	for _, want := range []string{
		"This directory is an OpenClaw plugin, not a standalone MCP server.",
		"Third-party dependencies (node_modules) were removed and are out of scope.",
		"also audit embedded skills (SKILL.md files and the instructions, references and scripts they ship)",
		"(paths relative to the audited directory): dist/index.js.",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("plugin audit prompt missing %q: %q", want, prompt)
		}
	}
	for _, arg := range append(argv, result.Command...) {
		if strings.Contains(arg, "fixture-private-openai-key") {
			t.Fatal("API key reached argv or the recorded command")
		}
	}
	if strings.Join(result.Command, "\x00") != strings.Join(append([]string{"aig-mcp-scan"}, argv...), "\x00") {
		t.Fatalf("recorded command = %#v, argv = %#v", result.Command, argv)
	}

	rendered, err := os.ReadFile(harness.prompt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(rendered), "A.I.G MCP plugin code audit SARIF supplied to Codex:") != 1 {
		t.Fatalf("judge prompt must carry exactly one aig-mcp SARIF result:\n%s", rendered)
	}
	for _, want := range []string{
		"- target kind: packageRelease",
		`"name": "aig-mcp-scan"`,
		`"ruleId": "MCP01"`,
		`"level": "error"`,
		`"uri": "plugin/index.js"`,
		`"securityScore": 35`,
	} {
		if !strings.Contains(string(rendered), want) {
			t.Fatalf("judge prompt missing %q:\n%s", want, rendered)
		}
	}
	for _, unwanted := range []string{"A.I.G SARIF evidence supplied", "SDI-", `"maxSeverity"`, `"prediction"`} {
		if strings.Contains(string(rendered), unwanted) {
			t.Fatalf("plugin judge prompt carries skill-scanner or derived evidence %q:\n%s", unwanted, rendered)
		}
	}
}

func TestClawHubProfileExplicitScannerOverridesPluginSelection(t *testing.T) {
	harness := newAIGMCPHarness(t)
	target := filepath.Join(harness.dir, "plugin-under-review")
	writeAIGMCPPlugin(t, target)

	artifact, err := harness.run(t, target, "ok", "--scanner", "aig")
	if err != nil {
		t.Fatal(err)
	}
	if got := scannerIDs(artifact); got != "aig" {
		t.Fatalf("scanners = %q", got)
	}
	if result := artifact.Scanners["aig"]; result.Status != "skipped" || result.Error != "Scanner aig does not support plugin targets." {
		t.Fatalf("aig = %#v", result)
	}
	if harness.invoked() {
		t.Fatal("aig-mcp-scan ran although --scanner replaced the profile lists")
	}
}

func TestClawHubProfileKeepsSkillScannersForSkillTargets(t *testing.T) {
	harness := newAIGMCPHarness(t)
	target := filepath.Join(harness.dir, "skill-under-review")
	writeSkill(t, target, "# Skill\n")
	writeFile(t, filepath.Join(target, "node_modules", "dep", "index.js"), "module.exports = 1;\n")

	artifact, err := harness.run(t, target, "ok", harness.skillFixtures...)
	if err != nil {
		t.Fatal(err)
	}
	if harness.invoked() {
		t.Fatal("aig-mcp-scan ran for a skill target")
	}
	if got := scannerIDs(artifact); got != "aig,skillspector" {
		t.Fatalf("skill scanners = %q, want the unchanged clawhub skill suite", got)
	}
	for id, result := range artifact.Scanners {
		if result.Status != "completed" {
			t.Fatalf("%s = %#v", id, result)
		}
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	rendered, err := os.ReadFile(harness.prompt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "A.I.G MCP") {
		t.Fatalf("skill judge prompt gained plugin scanner evidence:\n%s", rendered)
	}
}

func TestClawHubProfilePreservesAIGMCPFailures(t *testing.T) {
	for _, test := range []struct {
		mode      string
		wantError []string
		wantRaw   bool
	}{
		{
			mode:      "crash",
			wantError: []string{"exit status 1", "openai.NotFoundError: model gpt-unknown does not exist", "aig-mcp-scan did not write SARIF output."},
		},
		{
			mode:      "model-failure",
			wantError: []string{"aig-mcp-scan model calls failed", "LLM chat failed after retries: AuthenticationError: invalid key"},
			wantRaw:   true,
		},
	} {
		t.Run(test.mode, func(t *testing.T) {
			harness := newAIGMCPHarness(t)
			target := filepath.Join(harness.dir, "plugin-under-review")
			writeAIGMCPPlugin(t, target)

			artifact, err := harness.run(t, target, test.mode)
			if err == nil || !strings.Contains(err.Error(), "scanner aig-mcp failed") {
				t.Fatalf("run error = %v", err)
			}
			result := artifact.Scanners["aig-mcp"]
			if result.Status != "failed" {
				t.Fatalf("aig-mcp = %#v", result)
			}
			for _, want := range test.wantError {
				if !strings.Contains(result.Error, want) {
					t.Fatalf("error %q missing %q", result.Error, want)
				}
			}
			if strings.Contains(result.Error, "fixture-private-openai-key") {
				t.Fatal("failure leaked the API key")
			}
			if got := hasRaw(result.Raw); got != test.wantRaw {
				t.Fatalf("raw retained = %v, want %v", got, test.wantRaw)
			}
			if artifact.Complete || artifact.Status != "failed" || artifact.Gate != "error" {
				t.Fatalf("failed plugin scan claimed complete evidence: complete=%v status=%q gate=%q", artifact.Complete, artifact.Status, artifact.Gate)
			}
			if artifact.Judge != nil && artifact.Judge.Status == "completed" {
				t.Fatal("judge completed on a failed plugin scan")
			}
			if calls := harness.skillScannerCalls(t); calls != "" {
				t.Fatalf("skill scanners ran for a plugin target:\n%s", calls)
			}
		})
	}
}

func scannerIDs(artifact runner.Artifact) string {
	ids := make([]string, 0, len(artifact.Scanners))
	for id := range artifact.Scanners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func hasRaw(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

func hasArgPair(args []string, name string, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name && args[i+1] == value {
			return true
		}
	}
	return false
}

func argAfter(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func jsonEqual(left any, right any) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && string(a) == string(b)
}
