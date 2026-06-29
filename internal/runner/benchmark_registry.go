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
	ID() string
	Aliases() []string
	Info() DatasetInfo
	Source() string
	Config() string
	DefaultSplit() string
	Splits() []string
	RunCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient) ([]BenchmarkCase, error)
	SupportsPredictionsOutput() bool
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
		id := strings.TrimSpace(adapter.ID())
		if id == "" {
			return BenchmarkRegistry{}, fmt.Errorf("Benchmark adapter id cannot be empty")
		}
		names := append([]string{id}, adapter.Aliases()...)
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

func (registry BenchmarkRegistry) ResolveInfo(id string) (DatasetInfo, error) {
	adapter, err := registry.Resolve(id)
	if err != nil {
		return DatasetInfo{}, err
	}
	return datasetInfo(adapter), nil
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
	ids := make([]string, 0, len(registry.adapters))
	for id := range registry.adapters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func datasetInfo(adapter BenchmarkAdapter) DatasetInfo {
	info := adapter.Info()
	if info.ID == "" {
		info.ID = adapter.ID()
	}
	if info.DisplayName == "" {
		info.DisplayName = info.ID
	}
	info.Aliases = append([]string(nil), adapter.Aliases()...)
	info.Source = adapter.Source()
	info.Splits = append([]string(nil), adapter.Splits()...)
	info.DefaultSplit = adapter.DefaultSplit()
	if info.RequiredEnv == "" {
		info.RequiredEnv = "none"
	}
	info.SupportsPredictionsOutput = adapter.SupportsPredictionsOutput()
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

func (openClawBenchmarkAdapter) ID() string {
	return openClawBenchmarkID
}

func (openClawBenchmarkAdapter) Aliases() []string {
	return []string{openClawBenchmarkDataset}
}

func (openClawBenchmarkAdapter) Info() DatasetInfo {
	return DatasetInfo{
		DisplayName: "ClawHub Security Signals",
		SourceURL:   "https://huggingface.co/datasets/OpenClaw/clawhub-security-signals",
		Description: "Weekly refreshed ClawHub production security signals for reproducing current behavior and checking regressions; not a human-validated ground-truth benchmark.",
		RequiredEnv: "none",
	}
}

func (openClawBenchmarkAdapter) Source() string {
	return openClawBenchmarkSource
}

func (openClawBenchmarkAdapter) Config() string {
	return openClawBenchmarkConfig
}

func (openClawBenchmarkAdapter) DefaultSplit() string {
	return defaultOpenClawBenchmarkSplit
}

func (openClawBenchmarkAdapter) Splits() []string {
	return sortedBenchmarkSplits(openClawBenchmarkSplits)
}

func (openClawBenchmarkAdapter) SupportsPredictionsOutput() bool {
	return true
}

func (adapter openClawBenchmarkAdapter) RunCases(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient) ([]BenchmarkCase, error) {
	rows, err := client.FetchOpenClawRows(openClawBenchmarkDataset, opts.Benchmark.Split, opts.Benchmark.Offset, opts.Benchmark.Limit)
	if err != nil {
		return nil, err
	}
	cases := make([]BenchmarkCase, 0, len(rows))
	for _, row := range rows {
		benchmarkCase, err := adapter.runCase(opts, ctx, env, now, row)
		if err != nil {
			return nil, err
		}
		cases = append(cases, benchmarkCase)
	}
	return cases, nil
}

func (openClawBenchmarkAdapter) runCase(opts Options, ctx RunContext, env map[string]string, now func() time.Time, row OpenClawBenchmarkRow) (BenchmarkCase, error) {
	dir, err := os.MkdirTemp("", "clawscan-benchmark-*")
	if err != nil {
		return BenchmarkCase{}, err
	}
	defer os.RemoveAll(dir)
	target, err := materializeOpenClawBenchmarkRow(dir, row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	run, err := runBenchmarkTarget(opts, ctx, env, now, target)
	if err != nil {
		return BenchmarkCase{}, err
	}
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
		Run: run,
	}, nil
}

type skillTrustBenchBenchmarkAdapter struct{}

func (skillTrustBenchBenchmarkAdapter) ID() string {
	return skillTrustBenchID
}

func (skillTrustBenchBenchmarkAdapter) Aliases() []string {
	return []string{skillTrustBenchAlias}
}

func (skillTrustBenchBenchmarkAdapter) Info() DatasetInfo {
	return DatasetInfo{
		DisplayName: "SkillTrustBench",
		SourceURL:   "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench",
		Description: "Hugging Face benchmark of agent skills with canonical clean and malicious judgments, materialized from the versioned skill archive.",
		RequiredEnv: "none",
	}
}

func (skillTrustBenchBenchmarkAdapter) Source() string {
	return skillTrustBenchSource
}

func (skillTrustBenchBenchmarkAdapter) Config() string {
	return skillTrustBenchConfig
}

func (skillTrustBenchBenchmarkAdapter) DefaultSplit() string {
	return defaultSkillTrustBenchSplit
}

func (skillTrustBenchBenchmarkAdapter) Splits() []string {
	return sortedBenchmarkSplits(skillTrustBenchSplits)
}

func (skillTrustBenchBenchmarkAdapter) SupportsPredictionsOutput() bool {
	return false
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
		benchmarkCase, err := adapter.runCase(opts, ctx, env, now, client, row)
		if err != nil {
			return nil, err
		}
		cases = append(cases, benchmarkCase)
	}
	return cases, nil
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

func (adapter skillTrustBenchBenchmarkAdapter) runCase(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient, row SkillTrustBenchRow) (BenchmarkCase, error) {
	dir, err := os.MkdirTemp("", "clawscan-benchmark-*")
	if err != nil {
		return BenchmarkCase{}, err
	}
	defer os.RemoveAll(dir)
	target, err := client.MaterializeSkillTrustBenchRow(dir, row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	run, err := runBenchmarkTarget(opts, ctx, env, now, target)
	if err != nil {
		return BenchmarkCase{}, err
	}
	expected, err := adapter.expected(row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	return BenchmarkCase{
		ID:           row.ID,
		SkillSlug:    row.ID,
		SkillVersion: skillTrustBenchVersion,
		Expected:     expected,
		Run:          run,
	}, nil
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

func sortedBenchmarkSplits(splits map[string]bool) []string {
	names := make([]string, 0, len(splits))
	for split := range splits {
		names = append(names, split)
	}
	sort.Strings(names)
	return names
}
