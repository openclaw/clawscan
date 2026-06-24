package runner

import (
	"fmt"
	"sort"
	"strings"
)

type ScannerAdapter interface {
	ID() string
	Requirements(env map[string]string) []EnvRequirement
	Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error)
}

type ScannerRegistry struct {
	adapters map[string]ScannerAdapter
}

func NewScannerRegistry(adapters ...ScannerAdapter) (ScannerRegistry, error) {
	registry := ScannerRegistry{adapters: map[string]ScannerAdapter{}}
	for _, adapter := range adapters {
		if adapter == nil {
			return ScannerRegistry{}, fmt.Errorf("Scanner adapter cannot be nil")
		}
		id := strings.TrimSpace(adapter.ID())
		if id == "" {
			return ScannerRegistry{}, fmt.Errorf("Scanner adapter id cannot be empty")
		}
		if _, ok := registry.adapters[id]; ok {
			return ScannerRegistry{}, fmt.Errorf("Duplicate scanner adapter id: %s", id)
		}
		registry.adapters[id] = adapter
	}
	return registry, nil
}

func DefaultScannerRegistry() ScannerRegistry {
	return defaultScannerRegistry
}

func (registry ScannerRegistry) Adapter(id string) (ScannerAdapter, bool) {
	adapter, ok := registry.adapters[id]
	return adapter, ok
}

func (registry ScannerRegistry) Contains(id string) bool {
	_, ok := registry.Adapter(id)
	return ok
}

func (registry ScannerRegistry) IDs() []string {
	ids := make([]string, 0, len(registry.adapters))
	for id := range registry.adapters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (registry ScannerRegistry) isZero() bool {
	return registry.adapters == nil
}

type scannerAdapter struct {
	id           string
	requirements func(env map[string]string) []EnvRequirement
	run          func(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error)
}

func (adapter scannerAdapter) ID() string {
	return adapter.id
}

func (adapter scannerAdapter) Requirements(env map[string]string) []EnvRequirement {
	if adapter.requirements == nil {
		return nil
	}
	return append([]EnvRequirement(nil), adapter.requirements(env)...)
}

func (adapter scannerAdapter) Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	return adapter.run(runner, target, startedAt)
}

var defaultScannerRegistry = mustScannerRegistry(defaultScannerAdapters()...)

func mustScannerRegistry(adapters ...ScannerAdapter) ScannerRegistry {
	registry, err := NewScannerRegistry(adapters...)
	if err != nil {
		panic(err)
	}
	return registry
}

func defaultScannerAdapters() []ScannerAdapter {
	return []ScannerAdapter{
		scannerAdapter{
			id:  "agentverus",
			run: ExternalScannerRunner.runAgentVerus,
		},
		scannerAdapter{
			id:           "ai-infra-guard",
			requirements: staticEnvRequirements("scanner ai-infra-guard", "AIG_BASE_URL", "AIG_MODEL", "AIG_MODEL_API_KEY"),
			run:          ExternalScannerRunner.runAIInfraGuard,
		},
		scannerAdapter{
			id:  "cisco",
			run: ExternalScannerRunner.runCisco,
		},
		scannerAdapter{
			id:  "clawscan-static",
			run: ExternalScannerRunner.runStatic,
		},
		scannerAdapter{
			id:           "skillspector",
			requirements: skillSpectorRequirements,
			run:          ExternalScannerRunner.runSkillSpector,
		},
		scannerAdapter{
			id:           "snyk",
			requirements: staticEnvRequirements("scanner snyk", "SNYK_TOKEN"),
			run:          ExternalScannerRunner.runSnyk,
		},
		scannerAdapter{
			id:           "socket",
			requirements: staticEnvRequirements("scanner socket", "SOCKET_TOKEN"),
			run:          ExternalScannerRunner.runSocket,
		},
		scannerAdapter{
			id:           "virustotal",
			requirements: staticEnvRequirements("scanner virustotal", "VIRUSTOTAL_API_KEY"),
			run:          ExternalScannerRunner.runVirusTotal,
		},
	}
}

func staticEnvRequirements(reason string, envVars ...string) func(env map[string]string) []EnvRequirement {
	return func(env map[string]string) []EnvRequirement {
		reqs := make([]EnvRequirement, 0, len(envVars))
		for _, envVar := range envVars {
			reqs = append(reqs, EnvRequirement{EnvVar: envVar, Reason: reason})
		}
		return reqs
	}
}

func skillSpectorRequirements(env map[string]string) []EnvRequirement {
	if !skillSpectorLLMEnabled(env) {
		return nil
	}
	reqs := []EnvRequirement{
		{EnvVar: "CLAWSCAN_SKILLSPECTOR_LLM", Reason: "scanner skillspector llm opt-in"},
	}
	if envVar := skillSpectorProviderKeyEnv(env); envVar != "" {
		reqs = append(reqs, EnvRequirement{EnvVar: envVar, Reason: "scanner skillspector llm"})
	}
	return reqs
}
