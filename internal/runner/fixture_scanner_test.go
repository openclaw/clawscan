package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"
)

// TestMain registers the in-process fixture scanner in the default registry
// for this package's tests, so ParseArgs and default-registry runs accept it
// without scanner binaries. Built-in catalog tests use builtInScannerRegistry.
func TestMain(m *testing.M) {
	defaultScannerRegistry = mustScannerRegistry(append(defaultScannerAdapters(), fixtureScannerAdapter{id: fixtureScannerID})...)
	os.Exit(m.Run())
}

func builtInScannerRegistry() ScannerRegistry {
	return mustScannerRegistry(defaultScannerAdapters()...)
}

// fixtureScannerID names an in-process test scanner. It reads the target
// without running a command, so tests need no scanner binaries, credentials,
// or Docker, and its raw evidence proves which files it inspected.
const fixtureScannerID = "fixture"

var fixturePromptInjection = regexp.MustCompile(`(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|earlier)\s+instructions?\b`)

var fixtureCredentialExfiltration = regexp.MustCompile(`(?i)\b(exfiltrate|steal|leak)\s+(credentials?|secrets?|tokens?|api\s*keys?)\b`)

type fixtureScannerReport struct {
	Verdict  string           `json:"verdict"`
	Files    []string         `json:"files"`
	Findings []fixtureFinding `json:"findings"`
}

type fixtureFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
}

type fixtureScannerAdapter struct {
	id string
}

func (adapter fixtureScannerAdapter) ID() string { return adapter.id }

func (adapter fixtureScannerAdapter) Requirements(map[string]string) []EnvRequirement { return nil }

func (adapter fixtureScannerAdapter) Info() ScannerInfo {
	return ScannerInfo{ID: adapter.id, DisplayName: adapter.id}
}

func (adapter fixtureScannerAdapter) InstallPlan() InstallPlan {
	return InstallPlan{ScannerID: adapter.id, NoInstallReason: "built in; no install needed"}
}

func (adapter fixtureScannerAdapter) SupportsTargetKind(kind string) bool {
	return kind != targetKindURL
}

func (adapter fixtureScannerAdapter) Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	ctx := workContext(runner.Context)
	report := fixtureScannerReport{Files: []string{}, Findings: []fixtureFinding{}}
	scanFile := func(path string, rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, err := readContextFile(ctx, path)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		rel = filepath.ToSlash(rel)
		report.Files = append(report.Files, rel)
		if fixturePromptInjection.Match(content) {
			report.Findings = append(report.Findings, fixtureFinding{ID: "fixture.prompt_injection", Severity: "medium", Path: rel})
		}
		if fixtureCredentialExfiltration.Match(content) {
			report.Findings = append(report.Findings, fixtureFinding{ID: "fixture.credential_exfiltration", Severity: "high", Path: rel})
		}
		return nil
	}
	info, err := os.Stat(target)
	if err != nil {
		return ScannerResult{}, err
	}
	if !info.IsDir() {
		err = scanFile(target, filepath.Base(target))
	} else {
		err = filepath.WalkDir(target, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				if shouldSkipTargetDirectory(target, path) {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(target, path)
			if err != nil {
				return err
			}
			return scanFile(path, rel)
		})
	}
	if err != nil {
		return ScannerResult{}, err
	}
	sort.Strings(report.Files)
	report.Verdict = "clean"
	for _, finding := range report.Findings {
		if finding.Severity == "high" {
			report.Verdict = "malicious"
			break
		}
		report.Verdict = "suspicious"
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return ScannerResult{}, err
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Command:     []string{adapter.id},
		Raw:         json.RawMessage(raw),
	}, nil
}

// fixtureScannerRegistry is the built-in registry plus the in-process fixture
// scanner.
func fixtureScannerRegistry(t *testing.T) ScannerRegistry {
	t.Helper()
	return DefaultScannerRegistry()
}
