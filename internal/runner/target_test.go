package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const probePluginManifest = `{
  "id": "probe-plugin",
  "name": "Probe Plugin",
  "contracts": { "tools": ["probe_tool"] }
}`

func writeProbePlugin(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(probePluginManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("// synthetic probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTargetClassifiesPluginDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin {
		t.Fatalf("kind = %q", resolved.kind)
	}
	if resolved.id != "probe-plugin" {
		t.Fatalf("id = %q", resolved.id)
	}
	expected, err := filepath.EvalSymlinks(dir)
	if err != nil {
		expected = dir
	}
	if resolved.resolvedPath != expected {
		t.Fatalf("resolvedPath = %q, want %q", resolved.resolvedPath, expected)
	}
}

func TestResolveTargetClassifiesPluginManifestFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	resolved, err := resolveTarget(filepath.Join(dir, "openclaw.plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin || resolved.id != "probe-plugin" {
		t.Fatalf("resolved = %#v", resolved)
	}
	expected, evalErr := filepath.EvalSymlinks(dir)
	if evalErr != nil {
		expected = dir
	}
	if resolved.resolvedPath != expected {
		t.Fatalf("manifest-file target must scan the plugin directory: resolvedPath = %q, want %q", resolved.resolvedPath, expected)
	}
}

func TestValidPluginIDAcceptsHostGrammar(t *testing.T) {
	valid := []string{"probe-plugin", "memory-lancedb-pro", "@scope/name", "@a/b", "Probe.Plugin_2", "has space", "caf\u00e9-plugin", strings.Repeat("a", 300)}
	for _, id := range valid {
		if !validPluginID(id) {
			t.Fatalf("validPluginID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", "@scope", "@/name", "a/b/c", "../escape", "@scope/..", `a\b`, "@scope/", "bad\x01id", "bad\nid"}
	for _, id := range invalid {
		if validPluginID(id) {
			t.Fatalf("validPluginID(%q) = true, want false", id)
		}
	}
}

func TestResolveTargetAcceptsScopedPluginID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scoped-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(`{"id":"@scope/probe-plugin"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin || resolved.id != "@scope/probe-plugin" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestRunPluginTargetDoesNotDemandSkillOnlyScannerCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{dir, "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	// snyk is skill-only, so a plugin scan must yield its skipped result even
	// though SNYK_TOKEN is absent from the environment.
	artifact, err := Run(opts, RunContext{Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["snyk"]
	if result.Status != "skipped" || !strings.Contains(result.Error, "does not support plugin targets") {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolveTargetKeepsSkillClassification(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skill")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetDefaultsPlainInputsToSkill(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "README.md")
	if err := os.WriteFile(file, []byte("# readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{file, dir, filepath.Join(dir, "missing")} {
		resolved, err := resolveTarget(input)
		if err != nil {
			t.Fatalf("resolveTarget(%q) error = %v", input, err)
		}
		if resolved.kind != targetKindSkill || resolved.id != "" {
			t.Fatalf("resolveTarget(%q) = %#v", input, resolved)
		}
	}
}

func TestResolveTargetRejectsAmbiguousManifests(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ambiguous")
	writeProbePlugin(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveTarget(dir)
	if err == nil || !strings.Contains(err.Error(), "desired manifest") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveTargetExplicitPluginManifestDisambiguatesDualLayout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dual-layout")
	writeProbePlugin(t, dir)
	if err := os.WriteFile(filepath.Join(dir, skillManifestName), []byte("# Bundled skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(filepath.Join(dir, pluginManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin || resolved.id != "probe-plugin" || resolved.resolvedPath != dir {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetIgnoresSymlinkedPluginManifest(t *testing.T) {
	// A hostile target must not be able to point openclaw.plugin.json at a host
	// file outside the target and be classified/read as that plugin.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "openclaw.plugin.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "probe-plugin")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "openclaw.plugin.json")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	resolved, err := resolveTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("symlinked manifest was followed: %#v", resolved)
	}
}

func TestReadPluginIDRejectsSymlinkManifest(t *testing.T) {
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "openclaw.plugin.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	id, err := readPluginID(link)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("id = %q err = %v", id, err)
	}
	if id != "" {
		t.Fatalf("id leaked from symlinked manifest: %q", id)
	}
}

func TestReadPluginIDReadsRegularManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	id, err := readPluginID(filepath.Join(dir, "openclaw.plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if id != "probe-plugin" {
		t.Fatalf("id = %q", id)
	}
}

func TestResolveTargetIgnoresSymlinkManifestNextToSkill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mixed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "openclaw.plugin.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "openclaw.plugin.json")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// The symlinked plugin manifest is not a real manifest, so the directory is
	// an unambiguous skill rather than a rejected ambiguous target.
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetRejectsInvalidPluginID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bad-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(`{"id":"../escape"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveTarget(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid plugin id") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunDispatchesClawHubScannersForPluginTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{
		dir,
		"--scanner", "skillspector",
		"--scanner", "virustotal",
		"--scanner", "clawscan-static",
		"--sandbox", "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	scannerRunner := &recordingPluginScannerRunner{}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"VIRUSTOTAL_API_KEY": "present"},
		ScannerRunner: scannerRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != targetKindPlugin || artifact.Target.ID != "probe-plugin" {
		t.Fatalf("target = %#v", artifact.Target)
	}
	wantScanners := "skillspector,virustotal,clawscan-static"
	if got := strings.Join(scannerRunner.scanners, ","); got != wantScanners {
		t.Fatalf("dispatched scanners = %q, want %q", got, wantScanners)
	}
	for _, scanner := range opts.Scanners {
		result := artifact.Scanners[scanner]
		if result.Status != "completed" {
			t.Fatalf("%s result = %#v", scanner, result)
		}
	}
}

func TestRunPluginTargetRequiresVirusTotalCredential(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{dir, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(opts, RunContext{Env: map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "VIRUSTOTAL_API_KEY required by scanner virustotal") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunPluginTargetRequiresDockerForSkillSpectorByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{dir, "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(opts, RunContext{
		Env: map[string]string{},
		DockerAvailability: func() error {
			return errors.New("sandbox-probe")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "Docker sandbox is required") || !strings.Contains(err.Error(), "sandbox-probe") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunStaticScannerCompletesForPluginTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{dir, "--scanner", "clawscan-static"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != targetKindPlugin || artifact.Target.ID != "probe-plugin" {
		t.Fatalf("target = %#v", artifact.Target)
	}
	result := artifact.Scanners["clawscan-static"]
	if result.Status != "completed" || len(result.Raw) == 0 {
		t.Fatalf("result = %#v", result)
	}
	if !strings.Contains(string(result.Raw), "index.js") {
		t.Fatalf("static scan must cover plugin code, not just the manifest: %s", result.Raw)
	}
}

func TestRunFailsForInvalidPluginManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bad-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{dir, "--scanner", "clawscan-static"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(opts, RunContext{Env: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "not a valid plugin") {
		t.Fatalf("err = %v", err)
	}
}

type recordingPluginScannerRunner struct {
	scanners []string
}

func (runner *recordingPluginScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	runner.scanners = append(runner.scanners, name)
	if _, err := os.Stat(filepath.Join(target, pluginManifestName)); err != nil {
		return ScannerResult{}, err
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: startedAt,
		Raw:         json.RawMessage(`{"ok":true}`),
	}, nil
}
