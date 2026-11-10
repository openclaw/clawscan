package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func templateFixture(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	// Scanner staging is the subject of this test; use the unfiltered copier to
	// materialize fixtures, including hidden, vendored and compiled shipped code.
	fixtures := []string{"benign-mixed"}
	if name != "benign-mixed" {
		fixtures = append(fixtures, name)
	}
	for _, fixture := range fixtures {
		if _, err := copyTargetTreeContext(t.Context(), filepath.Join("testdata", "templates", fixture), root, func(string, os.DirEntry) (bool, error) { return false, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "shipped.txt"), []byte("Shipped hidden content"), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func templateTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

type templateCommandRunner struct {
	t      *testing.T
	want   map[string]string
	output string
	calls  int
}

func (r *templateCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls++
	if command != aigMCPCommand {
		r.t.Fatalf("unexpected command (dependency fetch/execution): %s", command)
	}
	if timeout != 30*time.Minute {
		r.t.Fatalf("timeout = %s", timeout)
	}
	if got := argValue(args, "--repo"); got != "template" {
		r.t.Fatalf("repo = %s", got)
	}
	if got := templateTree(r.t, filepath.Join(cwd, "template")); !reflect.DeepEqual(got, r.want) {
		r.t.Fatalf("staged bytes differ: got %v want %v", got, r.want)
	}
	prompt := argValue(args, "-p")
	for _, phrase := range []string{"CLAW.md contains agent instructions", "BOOTSTRAP.md", "profiles", "automations", "workspace files", "bundled skills", "plugins and code", "shipped node_modules", "do not resolve, install, download, browse, recursively scan", "fetch their security audit results", "without fetching or executing it", "read_file_chunk", "template/plugins/notes/dist/index.js", "template/node_modules/shipped-helper/index.js"} {
		if !strings.Contains(prompt, phrase) {
			r.t.Errorf("prompt missing %q", phrase)
		}
	}
	if strings.Contains(prompt, "Third-party dependencies (node_modules) were removed") {
		r.t.Fatal("plugin prompt leaked into Template audit")
	}
	err := os.WriteFile(filepath.Join(cwd, argValue(args, "-o")), []byte(r.output), 0600)
	return CommandOutput{}, err
}

// These fixtures prove scope/dispatch/integrity, not model detection quality.
// All scanner commands are fake; no bootstrap, fetch or dependency is executed.
func TestAIGMCPTemplateShippedArtifactAndPrompt(t *testing.T) {
	for _, name := range []string{"benign-mixed", "malicious-bootstrap", "malicious-automation", "malicious-download", "external-clawhub-ref"} {
		t.Run(name, func(t *testing.T) {
			root := templateFixture(t, name)
			before := templateTree(t, root)
			raw := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"aig-mcp-scan","version":"0.2.0"}},"properties":{"scanNote":"complete","securityScore":100},"results":[]}]}`
			if strings.HasPrefix(name, "malicious-") {
				raw = aigMCPSARIF
			}
			commands := &templateCommandRunner{t: t, want: before, output: raw}
			artifact := runAIGMCPTest(t, root, map[string]string{"LLM_API_KEY": "fixture-only"}, commands)
			if artifact.Target.Kind != targetKindTemplate || len(artifact.Scanners) != 1 || commands.calls != 1 {
				t.Fatalf("dispatch = %#v calls=%d", artifact.Target, commands.calls)
			}
			result := artifact.Scanners[aigMCPScannerID]
			if result.Status != "completed" || string(result.Raw) != raw {
				t.Fatalf("raw evidence changed: %#v", result)
			}
			if artifact.Judge != nil {
				t.Fatal("scanner-only run invented verdict judge")
			}
			if got := templateTree(t, root); !reflect.DeepEqual(got, before) {
				t.Fatal("original artifact changed")
			}
		})
	}
}

func TestTemplateTargetCanonicalSelectorAndPrecedence(t *testing.T) {
	root := templateFixture(t, "benign-mixed")
	for _, rel := range []string{"SKILL.md", "openclaw.plugin.json"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(`{"id":"bundled"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target, err := resolveTarget(root)
	if err != nil || target.kind != targetKindTemplate || target.resolvedPath != root {
		t.Fatalf("target=%#v err=%v", target, err)
	}
}

func TestTemplateTargetRejectsUnsafeOrRetiredSelectors(t *testing.T) {
	for _, selector := range []any{"../CLAW.md", "/CLAW.md", "x/../CLAW.md", "x//CLAW.md", "manifest.json", true, "missing/CLAW.md", "x\\CLAW.md", "././CLAW.md"} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(string(mustTemplateJSON(t, selector))), "/", "_"), func(t *testing.T) {
			root := t.TempDir()
			pkg := map[string]any{"openclaw": map[string]any{"template": selector}}
			if err := os.WriteFile(filepath.Join(root, "package.json"), mustTemplateJSON(t, pkg), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveTarget(root); err == nil {
				t.Fatalf("accepted %v", selector)
			}
		})
	}
	root := templateFixture(t, "benign-mixed")
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"openclaw":{"template":"manifests/CLAW.md","claw":"CLAW.md"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTarget(root); err == nil {
		t.Fatal("retired selector accepted")
	}
}

func mustTemplateJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTemplateStagingRejectsEscapingLinksAndOversizedVendoredFiles(t *testing.T) {
	root := templateFixture(t, "benign-mixed")
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "escape")); err != nil {
		t.Skip(err)
	}
	if err := stageAIGMCPScanTarget(ExternalScannerRunner{}, root, t.TempDir(), false); err == nil {
		t.Fatal("escaping link accepted")
	}
	if err := os.Remove(filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(root, "node_modules", "too-large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(aigMCPMaxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := stageAIGMCPScanTarget(ExternalScannerRunner{}, root, t.TempDir(), false); err == nil {
		t.Fatal("oversized vendored file ignored")
	}
}

func TestTemplateManifestSymlinksAreRefused(t *testing.T) {
	for _, rel := range []string{"package.json", "manifests/CLAW.md", "manifests"} {
		t.Run(rel, func(t *testing.T) {
			root := templateFixture(t, "benign-mixed")
			if err := os.RemoveAll(filepath.Join(root, rel)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(root, rel)); err != nil {
				t.Skip(err)
			}
			target, err := resolveTarget(root)
			if rel == "package.json" {
				if err != nil || target.kind == targetKindTemplate {
					t.Fatalf("linked metadata changed non-Template classification: %#v %v", target, err)
				}
				if _, err := resolveTargetForOptions(Options{Target: root, TargetKind: targetKindTemplate}); err == nil {
					t.Fatal("linked package metadata accepted as Template")
				}
			} else if err == nil {
				t.Fatal("manifest symlink accepted")
			}
		})
	}
}
