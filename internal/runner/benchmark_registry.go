package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type BenchmarkAdapter interface {
	Info() DatasetInfo
	Config() string
	RunCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient) ([]BenchmarkCase, error)
}

type DatasetInfo struct {
	ID                        string
	DisplayName               string
	Aliases                   []string
	Source                    string
	SourceURL                 string
	Description               string
	Splits                    []string
	DefaultSplit              string
	RequiredEnv               string
	SupportsPredictionsOutput bool
}

type BenchmarkRegistry struct {
	adapters map[string]BenchmarkAdapter
	lookup   map[string]BenchmarkAdapter
}

func NewBenchmarkRegistry(adapters ...BenchmarkAdapter) (BenchmarkRegistry, error) {
	registry := BenchmarkRegistry{
		adapters: map[string]BenchmarkAdapter{},
		lookup:   map[string]BenchmarkAdapter{},
	}
	for _, adapter := range adapters {
		if adapter == nil {
			return BenchmarkRegistry{}, fmt.Errorf("Benchmark adapter cannot be nil")
		}
		info := adapter.Info()
		id := strings.TrimSpace(info.ID)
		if id == "" {
			return BenchmarkRegistry{}, fmt.Errorf("Benchmark adapter id cannot be empty")
		}
		names := append([]string{id}, info.Aliases...)
		for _, name := range names {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				return BenchmarkRegistry{}, fmt.Errorf("Benchmark adapter alias cannot be empty")
			}
			key := benchmarkLookupKey(trimmed)
			if _, ok := registry.lookup[key]; ok {
				return BenchmarkRegistry{}, fmt.Errorf("Duplicate benchmark adapter id or alias: %s", name)
			}
			registry.lookup[key] = adapter
		}
		registry.adapters[id] = adapter
	}
	return registry, nil
}

func DefaultBenchmarkRegistry() BenchmarkRegistry {
	return defaultBenchmarkRegistry
}

func (registry BenchmarkRegistry) Resolve(id string) (BenchmarkAdapter, error) {
	if registry.lookup == nil {
		return nil, fmt.Errorf("Unsupported benchmark: %s", id)
	}
	adapter, ok := registry.lookup[benchmarkLookupKey(id)]
	if !ok {
		return nil, fmt.Errorf("Unsupported benchmark: %s", id)
	}
	return adapter, nil
}

func (registry BenchmarkRegistry) Info(id string) (DatasetInfo, bool) {
	adapter, ok := registry.adapters[id]
	if !ok {
		return DatasetInfo{}, false
	}
	return datasetInfo(adapter), true
}

func (registry BenchmarkRegistry) Infos() []DatasetInfo {
	infos := make([]DatasetInfo, 0, len(registry.adapters))
	for _, id := range registry.IDs() {
		info, _ := registry.Info(id)
		infos = append(infos, info)
	}
	return infos
}

func (registry BenchmarkRegistry) IDs() []string {
	return sortedKeys(registry.adapters)
}

func datasetInfo(adapter BenchmarkAdapter) DatasetInfo {
	info := adapter.Info()
	if info.DisplayName == "" {
		info.DisplayName = info.ID
	}
	info.Aliases = append([]string(nil), info.Aliases...)
	info.Splits = append([]string(nil), info.Splits...)
	if info.RequiredEnv == "" {
		info.RequiredEnv = "none"
	}
	return info
}

func benchmarkLookupKey(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

var defaultBenchmarkRegistry = mustBenchmarkRegistry(
	openClawBenchmarkAdapter{},
	skillTrustBenchBenchmarkAdapter{},
)

func mustBenchmarkRegistry(adapters ...BenchmarkAdapter) BenchmarkRegistry {
	registry, err := NewBenchmarkRegistry(adapters...)
	if err != nil {
		panic(err)
	}
	return registry
}

type openClawBenchmarkAdapter struct{}

func (openClawBenchmarkAdapter) Info() DatasetInfo {
	return DatasetInfo{
		ID:                        openClawBenchmarkID,
		Aliases:                   []string{openClawBenchmarkDataset},
		Source:                    openClawBenchmarkSource,
		DefaultSplit:              defaultOpenClawBenchmarkSplit,
		Splits:                    sortedKeys(openClawBenchmarkSplits),
		SupportsPredictionsOutput: true,
		DisplayName:               "ClawHub Security Signals",
		SourceURL:                 "https://huggingface.co/datasets/OpenClaw/clawhub-security-signals",
		Description:               "Weekly refreshed ClawHub production security signals for reproducing current behavior and checking regressions; not a human-validated ground-truth benchmark.",
		RequiredEnv:               "none",
	}
}

func (openClawBenchmarkAdapter) Config() string {
	return openClawBenchmarkConfig
}

func (openClawBenchmarkAdapter) RunCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient) ([]BenchmarkCase, error) {
	rows, err := client.FetchOpenClawRows(openClawBenchmarkDataset, opts.Benchmark.Split, opts.Benchmark.Offset, opts.Benchmark.Limit)
	if err != nil {
		return nil, err
	}
	cases := make([]BenchmarkCase, 0, len(rows))
	for _, row := range rows {
		cases = append(cases, openClawBenchmarkCase(opts, env, row))
	}
	return runPreparedBenchmarkCases(opts, ctx, env, now, cases, func(dir string, index int) (string, error) {
		return materializeOpenClawBenchmarkRowContext(workContext(ctx.Context), dir, rows[index])
	})
}

func openClawBenchmarkCase(opts Options, env map[string]string, row OpenClawBenchmarkRow) BenchmarkCase {
	return BenchmarkCase{
		ID:           row.ID,
		SkillSlug:    row.SkillSlug,
		SkillVersion: row.SkillVersion,
		Expected: BenchmarkExpected{
			Verdict:    canonicalExpectedVerdict(row.ClawScanVerdict),
			Confidence: row.ClawScanConfidence,
			Model:      row.ClawScanModel,
			Summary:    row.ClawScanSummary,
			Context:    normalizedRawMessage(row.ClawScanContext),
		},
		Run: unstartedBenchmarkRun(opts, env),
	}
}

func unstartedBenchmarkRun(opts Options, env map[string]string) Artifact {
	artifact := pendingArtifact(opts, "", env)
	artifact.Status = "not_started"
	artifact.Gate = "error"
	return artifact
}

func runPreparedBenchmarkCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, cases []BenchmarkCase, materialize func(string, int) (string, error)) ([]BenchmarkCase, error) {
	runCase := func(index int) (err error) {
		benchmarkCase := &cases[index]
		defer finishBenchmarkCase(benchmarkCase, opts, ctx, now, &err)
		dir, err := os.MkdirTemp("", "clawscan-benchmark-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		target, err := materialize(dir, index)
		if err != nil {
			return err
		}
		benchmarkCase.Run, err = runBenchmarkTarget(opts, ctx, env, now, target)
		return err
	}
	for index := range cases {
		if err := workContext(ctx.Context).Err(); err != nil {
			return cases, err
		}
		if err := runCase(index); err != nil {
			return cases, err
		}
	}
	return cases, nil
}

func finishBenchmarkCase(benchmarkCase *BenchmarkCase, opts Options, ctx RunContext, now func() time.Time, runErr *error) {
	if *runErr == nil || benchmarkCase.Run.Status != "not_started" {
		return
	}
	opts.OutputPath = ""
	finishArtifact(&benchmarkCase.Run, opts, workContext(ctx.Context), now, runErr)
}

func scannerRequested(opts Options, scanner string) bool {
	for _, requested := range opts.Scanners {
		if requested == scanner {
			return true
		}
	}
	return false
}

type skillTrustBenchBenchmarkAdapter struct{}

func (skillTrustBenchBenchmarkAdapter) Info() DatasetInfo {
	return DatasetInfo{
		ID:           skillTrustBenchID,
		Aliases:      []string{skillTrustBenchAlias},
		Source:       skillTrustBenchSource,
		DefaultSplit: defaultSkillTrustBenchSplit,
		Splits:       sortedKeys(skillTrustBenchSplits),
		DisplayName:  "SkillTrustBench",
		SourceURL:    "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench",
		Description:  "Hugging Face benchmark of agent skills with canonical clean and malicious judgments, materialized from the versioned skill archive.",
		RequiredEnv:  "none",
	}
}

func (skillTrustBenchBenchmarkAdapter) Config() string {
	return skillTrustBenchConfig
}

func (adapter skillTrustBenchBenchmarkAdapter) RunCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient) ([]BenchmarkCase, error) {
	offset := opts.Benchmark.Offset
	limit := opts.Benchmark.Limit
	if len(opts.Benchmark.IDs) > 0 {
		offset = 0
		limit = 0
	}
	rows, err := client.FetchSkillTrustBenchRows(opts.Benchmark.ID, opts.Benchmark.Split, offset, limit)
	if err != nil {
		return nil, err
	}
	if len(opts.Benchmark.IDs) > 0 {
		rows, err = selectSkillTrustBenchRows(rows, opts.Benchmark.IDs, opts.Benchmark.Split)
		if err != nil {
			return nil, err
		}
	}
	cases := make([]BenchmarkCase, 0, len(rows))
	for _, row := range rows {
		expected, err := adapter.expected(row)
		if err != nil {
			return cases, err
		}
		cases = append(cases, BenchmarkCase{ID: row.ID, SkillSlug: row.ID, SkillVersion: skillTrustBenchVersion, Expected: expected, Run: unstartedBenchmarkRun(opts, env)})
	}
	return runPreparedBenchmarkCases(opts, ctx, env, now, cases, func(dir string, index int) (string, error) {
		return client.MaterializeSkillTrustBenchRow(dir, rows[index])
	})
}

func selectSkillTrustBenchRows(rows []SkillTrustBenchRow, ids []string, split string) ([]SkillTrustBenchRow, error) {
	byID := make(map[string]SkillTrustBenchRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	selected := make([]SkillTrustBenchRow, 0, len(ids))
	for _, id := range ids {
		row, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("--ids requested benchmark id %s, but it is missing from SkillTrustBench split %s", id, split)
		}
		selected = append(selected, row)
	}
	return selected, nil
}

func (adapter skillTrustBenchBenchmarkAdapter) expected(row SkillTrustBenchRow) (BenchmarkExpected, error) {
	context, err := json.Marshal(struct {
		RiskLabels     []string `json:"risk_labels"`
		Source         string   `json:"source"`
		BaseCategory   string   `json:"base_category"`
		PrimaryPattern *string  `json:"primary_pattern"`
		AttackPattern  []string `json:"attack_pattern"`
		SkillPath      string   `json:"skill_path"`
	}{
		RiskLabels:     row.RiskLabels,
		Source:         row.Source,
		BaseCategory:   row.BaseCategory,
		PrimaryPattern: row.PrimaryPattern,
		AttackPattern:  row.AttackPattern,
		SkillPath:      row.SkillPath,
	})
	if err != nil {
		return BenchmarkExpected{}, err
	}
	return BenchmarkExpected{
		Verdict: canonicalExpectedVerdict(row.Judgment),
		Summary: adapter.summary(row),
		Context: json.RawMessage(context),
	}, nil
}

func (skillTrustBenchBenchmarkAdapter) summary(row SkillTrustBenchRow) string {
	parts := []string{"SkillTrustBench judgment: " + row.Judgment}
	if row.BaseCategory != "" {
		parts = append(parts, "category: "+row.BaseCategory)
	}
	if row.PrimaryPattern != nil && *row.PrimaryPattern != "" {
		parts = append(parts, "primary pattern: "+*row.PrimaryPattern)
	}
	if row.Source != "" {
		parts = append(parts, "source: "+row.Source)
	}
	return strings.Join(parts, "; ")
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
