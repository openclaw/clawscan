package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRunTargetsResultBundlePreservesCollidingEvidence(t *testing.T) {
	tests := []struct {
		name     string
		targets  []string
		profiles []string
		scanners []string
	}{
		{
			name:     "target suffix used after collision",
			targets:  []string{"skills/a", "skills/a!", "skills/a-2", "skills/a"},
			scanners: []string{"clawscan-static"},
		},
		{
			name:     "target suffix used before collision",
			targets:  []string{"skills/a-2", "skills/a", "skills/a!", "skills/a"},
			scanners: []string{"clawscan-static"},
		},
		{
			name:     "profile names",
			targets:  []string{"skills/a", "skills/a", "skills/a-2"},
			profiles: []string{"review", "review!", "review"},
			scanners: []string{"clawscan-static"},
		},
		{
			name:     "scanner names",
			targets:  []string{"skills/a"},
			scanners: []string{"custom", "custom-", "custom--", "custom-2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			batch := BatchArtifact{SchemaVersion: "clawscan-batch-v1"}
			for i, target := range tt.targets {
				artifact := Artifact{
					SchemaVersion: "clawscan-run-v1",
					Target:        Target{Kind: "skill", Input: target, ResolvedPath: filepath.Join(dir, target)},
					Scanners:      map[string]ScannerResult{},
				}
				if len(tt.profiles) != 0 {
					artifact.Profile = tt.profiles[i]
				}
				for _, scanner := range tt.scanners {
					artifact.Scanners[scanner] = ScannerResult{
						Status: "completed",
						Raw:    json.RawMessage(fmt.Sprintf(`{"run":%d,"scanner":%q}`, i, scanner)),
					}
				}
				batch.Runs = append(batch.Runs, artifact)
			}
			out := filepath.Join(dir, "artifact.json")
			if err := WriteRunTargetsResultBundle(out, RunTargetsResult{Batch: &batch}); err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, run := range batch.Runs {
				for scanner, result := range run.Scanners {
					if seen[result.OutputPath] {
						t.Errorf("reused evidence path %q", result.OutputPath)
					}
					seen[result.OutputPath] = true
					raw, err := os.ReadFile(filepath.Join(dir, result.OutputPath))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(raw, result.Raw) {
						t.Errorf("evidence for %s/%s = %s, want %s", run.Target.Input, scanner, raw, result.Raw)
					}
				}
			}
		})
	}
}
