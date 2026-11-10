package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTemplateDetectionPreservesNonTemplatePackageMetadata(t *testing.T) {
	for _, kind := range []string{targetKindSkill, targetKindPlugin} {
		for _, metadata := range []string{"symlink", "large"} {
			t.Run(kind+"/"+metadata, func(t *testing.T) {
				root := t.TempDir()
				manifest, body := skillManifestName, "# Ordinary skill"
				if kind == targetKindPlugin {
					manifest, body = pluginManifestName, `{"id":"ordinary-plugin"}`
				}
				if err := os.WriteFile(filepath.Join(root, manifest), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				if metadata == "symlink" {
					if err := os.Mkdir(filepath.Join(root, "metadata"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, "metadata", "package.json"), []byte(`{"name":"ordinary-package"}`), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join("metadata", "package.json"), filepath.Join(root, "package.json")); err != nil {
						t.Skip(err)
					}
				} else {
					if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"ordinary-package","description":"`+strings.Repeat("x", maxPluginManifestBytes)+`"}`), 0600); err != nil {
						t.Fatal(err)
					}
				}
				target, err := resolveTarget(root)
				if err != nil || target.kind != kind {
					t.Fatalf("unrelated metadata changed dispatch: %#v %v", target, err)
				}
				if kind == targetKindPlugin {
					commands := &aigMCPCommandRunner{output: aigMCPSARIF}
					artifact := runAIGMCPTest(t, root, map[string]string{"LLM_API_KEY": "fixture-only"}, commands)
					if artifact.Scanners[aigMCPScannerID].Status != "completed" || len(commands.calls) != 1 {
						t.Fatalf("plugin scan failed: %#v", artifact.Scanners)
					}
				}
			})
		}
	}
}
