package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLibraryLoadedConfigIdentitySurvivesRunAndDeferredWrites(t *testing.T) {
	for _, mode := range []string{"run", "targets", "profiles", "benchmark", "deferred", "sidecar"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "skill")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, skillManifestName), []byte("# Inert generated skill\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "settings.yml")
			if mode == "sidecar" {
				config = filepath.Join(root, "evidence", "skill", "clawscan-static.json")
				if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			body := []byte("version: 1\nprofiles: {}\n")
			if err := os.WriteFile(config, body, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := Options{Target: target, Scanners: []string{"clawscan-static"}, ConfigSource: "built-in", LoadedConfigPath: config, OutputPath: config}
			ctx := RunContext{Env: map[string]string{}}
			var writeErr error
			switch mode {
			case "run":
				_, writeErr = Run(opts, ctx)
			case "targets":
				_, writeErr = RunTargets(opts, ctx, root)
			case "benchmark":
				opts.Target = ""
				opts.Benchmark = benchmarkTestOptions(t, openClawBenchmarkID, "", 0, 0, "").Benchmark
				ctx.BenchmarkClient = staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "generated", ClawScanVerdict: "clean", SkillMDContent: "# Inert\n"}}}
				_, writeErr = RunBenchmark(opts, ctx)
			case "profiles":
				opts.OutputPath = ""
				batch, err := RunProfileBatch([]Options{opts}, ctx, root)
				if err != nil || len(batch.Runs) != 1 || !batch.Runs[0].Complete {
					t.Fatalf("safe profile did not complete: %+v, %v", batch, err)
				}
				writeErr = WriteRunTargetsResultBundle(config, RunTargetsResult{Batch: &batch})
			case "deferred", "sidecar":
				opts.OutputPath = ""
				artifact, err := Run(opts, ctx)
				if err != nil || !artifact.Complete || artifact.ConfigSource == nil || *artifact.ConfigSource != "built-in" {
					t.Fatalf("safe scan or provenance changed: %+v, %v", artifact, err)
				}
				output := config
				if mode == "sidecar" {
					output = filepath.Join(root, "evidence", "artifact.json")
				}
				writeErr = WriteRunTargetsResultBundle(output, RunTargetsResult{Single: &artifact})
			}
			after, err := os.ReadFile(config)
			if writeErr == nil || !strings.Contains(writeErr.Error(), "aliases input") || err != nil || !bytes.Equal(body, after) {
				t.Fatalf("loaded config identity lost: mode=%s intact=%v, %v, %v", mode, bytes.Equal(body, after), writeErr, err)
			}
		})
	}
}
