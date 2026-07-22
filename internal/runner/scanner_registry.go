package runner

import (
	"fmt"
	"sort"
	"strings"
)

type ScannerAdapter interface {
	ID() string
	Requirements(env map[string]string) []EnvRequirement
	Info() ScannerInfo
	InstallPlan() InstallPlan
	// SupportsTargetKind reports whether the adapter can analyze a target of the
	// given kind. Adapters support skill and URL targets by default; only
	// plugin-aware adapters accept OpenClaw plugin targets.
	SupportsTargetKind(kind string) bool
	Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error)
}

type ScannerInfo struct {
	ID            string
	DisplayName   string
	RepositoryURL string
	Description   string
	RequiredEnv   []string
	OptionalEnv   []string
	InstallHint   string
	Installable   bool
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

func (registry ScannerRegistry) Infos() []ScannerInfo {
	infos := make([]ScannerInfo, 0, len(registry.adapters))
	for _, id := range registry.IDs() {
		info, _ := registry.Info(id)
		infos = append(infos, info)
	}
	return infos
}

func (registry ScannerRegistry) Info(id string) (ScannerInfo, bool) {
	adapter, ok := registry.Adapter(id)
	if !ok {
		return ScannerInfo{}, false
	}
	return adapter.Info(), true
}

func (registry ScannerRegistry) InstallScannerIDs() []string {
	ids := make([]string, 0, len(registry.adapters))
	for id, adapter := range registry.adapters {
		if strings.TrimSpace(adapter.InstallPlan().InstallUnsupportedReason) == "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (registry ScannerRegistry) isZero() bool {
	return registry.adapters == nil
}

type scannerAdapter struct {
	id            string
	requirements  func(env map[string]string) []EnvRequirement
	info          ScannerInfo
	installPlan   InstallPlan
	commandBacked bool
	// supportsPlugins marks adapters that can analyze OpenClaw plugin
	// targets. Skill and URL kinds are always supported.
	supportsPlugins bool
	run             func(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error)
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

func (adapter scannerAdapter) Info() ScannerInfo {
	info := adapter.info
	if info.ID == "" {
		info.ID = adapter.id
	}
	if len(info.RequiredEnv) == 0 {
		info.RequiredEnv = requiredEnvVars(adapter.Requirements(map[string]string{}))
	} else {
		info.RequiredEnv = append([]string(nil), info.RequiredEnv...)
	}
	info.OptionalEnv = append([]string(nil), info.OptionalEnv...)

	plan := adapter.InstallPlan()
	if info.DisplayName == "" {
		info.DisplayName = plan.Name
	}
	if info.DisplayName == "" {
		info.DisplayName = info.ID
	}
	info.Installable = strings.TrimSpace(plan.InstallUnsupportedReason) == ""
	if info.InstallHint == "" {
		info.InstallHint = installHint(plan)
	}
	return info
}

func (adapter scannerAdapter) InstallPlan() InstallPlan {
	plan := adapter.installPlan
	if plan.ScannerID == "" {
		plan.ScannerID = adapter.id
	}
	return plan
}

func (adapter scannerAdapter) SupportsTargetKind(kind string) bool {
	if kind == targetKindPlugin {
		return adapter.supportsPlugins
	}
	return true
}

func (adapter scannerAdapter) Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	return adapter.run(runner, target, startedAt)
}

func (adapter scannerAdapter) CommandBacked() bool {
	return adapter.commandBacked
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
			id:            "agentverus",
			commandBacked: true,
			info: ScannerInfo{
				DisplayName:   "AgentVerus",
				RepositoryURL: "https://github.com/agentverus/agentverus-scanner",
				Description:   "Local file or directory scanner invoked through agentverus-scanner.",
			},
			installPlan: InstallPlan{
				ScannerID: "agentverus",
				Name:      "AgentVerus",
				Commands: []InstallCommand{
					{Command: "npm", Args: []string{"install", "--save-dev", "agentverus-scanner"}},
				},
				VerifyCommand: InstallCommand{Command: "npx", Args: []string{"agentverus", "--help"}},
			},
			run: ExternalScannerRunner.runAgentVerus,
		},
		scannerAdapter{
			id:            "aig",
			requirements:  aigRequirements,
			commandBacked: true,
			info: ScannerInfo{
				DisplayName:   "Tencent AI-Infra-Guard",
				RepositoryURL: "https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan",
				Description:   "Tencent Zhuque Lab's local directory scanner invoked through aig-skill-scan. Produces SARIF 2.1.0 with SkillTrustBench T01-T09 evidence. Requires LLM_API_KEY or OPENAI_API_KEY.",
				OptionalEnv: []string{
					"OPENAI_API_KEY",
					"DEFAULT_MODEL",
					"DEFAULT_BASE_URL",
					"DEFAULT_MODEL_CONTEXT_WINDOW",
					"LOG_LEVEL",
				},
			},
			installPlan: InstallPlan{
				ScannerID:        "aig",
				Name:             "Tencent AI-Infra-Guard",
				CheckExecutables: []string{"aig-skill-scan"},
				Commands: []InstallCommand{
					{Command: "pip", Args: []string{"install", "aig-skill-scan"}},
				},
				VerifyCommand: InstallCommand{Command: "aig-skill-scan", Args: []string{"--help"}},
			},
			run: ExternalScannerRunner.runAIG,
		},
		scannerAdapter{
			id:            "cisco",
			commandBacked: true,
			info: ScannerInfo{
				DisplayName:   "Cisco AI Defense skill-scanner",
				RepositoryURL: "https://github.com/cisco-ai-defense/skill-scanner",
				Description:   "Local file or directory scanner invoked through skill-scanner with JSON report output. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers.",
				OptionalEnv: []string{
					"SKILL_SCANNER_LLM_API_KEY",
					"SKILL_SCANNER_LLM_PROVIDER",
					"SKILL_SCANNER_LLM_MODEL",
					"SKILL_SCANNER_LLM_BASE_URL",
					"SKILL_SCANNER_LLM_USER",
					"SKILL_SCANNER_LLM_API_VERSION",
					"SKILL_SCANNER_LLM_FORCE_JSON_OBJECT",
					"SKILL_SCANNER_META_LLM_API_KEY",
					"SKILL_SCANNER_META_LLM_MODEL",
					"SKILL_SCANNER_META_LLM_BASE_URL",
					"SKILL_SCANNER_META_LLM_API_VERSION",
					"AWS_PROFILE",
					"AWS_REGION",
					"GOOGLE_APPLICATION_CREDENTIALS",
					"VIRUSTOTAL_API_KEY",
					"AI_DEFENSE_API_KEY",
					"AI_DEFENSE_API_URL",
				},
			},
			installPlan: InstallPlan{
				ScannerID:        "cisco",
				Name:             "Cisco AI Defense skill-scanner",
				CheckExecutables: []string{"skill-scanner"},
				Commands: []InstallCommand{
					{Command: "uv", Args: []string{"pip", "install", "cisco-ai-skill-scanner"}},
				},
				VerifyCommand: InstallCommand{Command: "skill-scanner", Args: []string{"--help"}},
			},
			run: ExternalScannerRunner.runCisco,
		},
		scannerAdapter{
			id:              "clawscan-static",
			supportsPlugins: true,
			info: ScannerInfo{
				DisplayName:   "ClawScan Static",
				RepositoryURL: "https://github.com/openclaw/clawscan",
				Description:   "Built-in deterministic text scanner for high-signal risky skill and plugin patterns.",
			},
			installPlan: InstallPlan{
				ScannerID:       "clawscan-static",
				Name:            "ClawScan Static",
				NoInstallReason: "built in; no install needed",
			},
			run: ExternalScannerRunner.runStatic,
		},
		scannerAdapter{
			id:            "relyable",
			commandBacked: true,
			info: ScannerInfo{
				DisplayName:   "Relyable",
				RepositoryURL: "https://github.com/veriker/relyable",
				Description:   "Functional re-derivation evidence: does the skill still do what its docs claim, recomputed? Emits the strongest grade that applies. exogenous: a declared rederive.json property manifest (idempotence / round-trip), with both sides of the relation computed from the skill's own code and the result mutation-tested against vacuity. self_spec: re-runs the author's own committed oracle (shipped tests or documented I/O examples). cold_golden: when an LLM key is set, a code-blind model infers goldens from SKILL.md alone and abstains unless the docs pin exact behavior; divergences are reported as unconfirmed, never as accusations. non_rederivable: the honest floor, never a fabricated pass. Functional axis only; complements the security scanners and does not detect malware or prompt injection. Skill code runs only inside the Docker sandbox (or with an explicit opt-in), in a scrubbed environment, and the scanner fails closed otherwise. Not preinstalled in the clawscan-runtime image: install on the host with clawscan install relyable, or build a derived sandbox image for Docker-mode runs (see docs/scanners.md).",
				// Deliberately RELYABLE_-prefixed only: generic provider keys
				// (ANTHROPIC_API_KEY / OPENAI_API_KEY) are honored by standalone
				// relyable-scan but are NOT listed here, so the sandbox env
				// passthrough never auto-forwards an operator's generic keys to
				// this scanner. Setting RELYABLE_LLM_API_KEY is an explicit
				// per-scanner opt-in.
				OptionalEnv: []string{
					"RELYABLE_SCAN_ALLOW_HOST_EXEC",
					"RELYABLE_LLM_API_KEY",
					"RELYABLE_LLM_PROVIDER",
					"RELYABLE_LLM_MODEL",
					"RELYABLE_LLM_BASE_URL",
				},
			},
			installPlan: InstallPlan{
				ScannerID:        "relyable",
				Name:             "Relyable",
				CheckExecutables: []string{"relyable-scan"},
				Commands: []InstallCommand{
					{Command: "uv", Args: []string{"tool", "install", "git+https://github.com/veriker/relyable.git", "--with", "pytest"}},
				},
				VerifyCommand: InstallCommand{Command: "relyable-scan", Args: []string{"--help"}},
			},
			run: ExternalScannerRunner.runRelyable,
		},
		scannerAdapter{
			id:              "skillspector",
			commandBacked:   true,
			supportsPlugins: true,
			info: ScannerInfo{
				DisplayName:   "NVIDIA SkillSpector",
				RepositoryURL: "https://github.com/NVIDIA/skillspector",
				Description:   "Local skill or OpenClaw plugin file/directory scanner. Uses SkillSpector LLM mode when provider env vars are set; otherwise runs with --no-llm.",
				OptionalEnv: []string{
					"SKILLSPECTOR_PROVIDER",
					"SKILLSPECTOR_MODEL",
					"SKILLSPECTOR_MODEL_REGISTRY",
					"SKILLSPECTOR_LOG_LEVEL",
					"SKILLSPECTOR_SSL_VERIFY",
					"NVIDIA_INFERENCE_KEY",
					"OPENAI_API_KEY",
					"OPENAI_BASE_URL",
					"ANTHROPIC_API_KEY",
					"ANTHROPIC_PROXY_ENDPOINT_URL",
					"ANTHROPIC_PROXY_API_KEY",
					"ANTHROPIC_PROXY_API_VERSION",
				},
			},
			installPlan: InstallPlan{
				ScannerID:        "skillspector",
				Name:             "NVIDIA SkillSpector",
				CheckExecutables: []string{"skillspector"},
				Commands: []InstallCommand{
					{Command: "uv", Args: []string{"tool", "install", "git+https://github.com/NVIDIA/skillspector.git"}},
				},
				VerifyCommand: InstallCommand{Command: "skillspector", Args: []string{"--help"}},
			},
			run: ExternalScannerRunner.runSkillSpector,
		},
		scannerAdapter{
			id:            "snyk",
			requirements:  staticEnvRequirements("scanner snyk", "SNYK_TOKEN"),
			commandBacked: true,
			info: ScannerInfo{
				DisplayName:   "Snyk Agent Scan",
				RepositoryURL: "https://github.com/snyk/agent-scan",
				Description:   "Local skill scanner invoked through uvx snyk-agent-scan.",
			},
			installPlan: InstallPlan{
				ScannerID:        "snyk",
				Name:             "Snyk Agent Scan",
				CheckExecutables: []string{"uvx"},
			},
			run: ExternalScannerRunner.runSnyk,
		},
		scannerAdapter{
			id:              "socket",
			requirements:    staticEnvRequirements("scanner socket", "SOCKET_CLI_API_TOKEN"),
			commandBacked:   true,
			supportsPlugins: true,
			info: ScannerInfo{
				DisplayName:   "Socket CLI",
				RepositoryURL: "https://github.com/SocketDev/socket-cli",
				Description:   "Local file or directory scanner using Socket's public CLI full-scan path.",
			},
			installPlan: InstallPlan{
				ScannerID:        "socket",
				Name:             "Socket CLI",
				CheckExecutables: []string{"socket"},
				Commands: []InstallCommand{
					{Command: "npm", Args: []string{"install", "-g", "socket"}},
				},
				VerifyCommand: InstallCommand{Command: "socket", Args: []string{"--help"}},
			},
			run: ExternalScannerRunner.runSocket,
		},
		scannerAdapter{
			id:              "virustotal",
			requirements:    staticEnvRequirements("scanner virustotal", "VIRUSTOTAL_API_KEY"),
			supportsPlugins: true,
			info: ScannerInfo{
				DisplayName:   "VirusTotal API",
				RepositoryURL: "https://docs.virustotal.com/reference/file",
				Description:   "API-backed local file hash lookup. Skill and OpenClaw plugin directories are scanned as deterministic ZIP archives.",
			},
			installPlan: InstallPlan{
				ScannerID:       "virustotal",
				Name:            "VirusTotal API",
				NoInstallReason: "API-backed scanner; configure VIRUSTOTAL_API_KEY at scan time",
			},
			run: ExternalScannerRunner.runVirusTotal,
		},
	}
}

func commandBackedScanner(adapter ScannerAdapter) bool {
	type commandBacked interface {
		CommandBacked() bool
	}
	typed, ok := adapter.(commandBacked)
	return ok && typed.CommandBacked()
}

func requiredEnvVars(requirements []EnvRequirement) []string {
	envVars := make([]string, 0, len(requirements))
	seen := map[string]bool{}
	for _, requirement := range requirements {
		envVar := strings.TrimSpace(requirement.EnvVar)
		if envVar == "" || seen[envVar] {
			continue
		}
		seen[envVar] = true
		envVars = append(envVars, envVar)
	}
	sort.Strings(envVars)
	return envVars
}

func installHint(plan InstallPlan) string {
	switch {
	case strings.TrimSpace(plan.InstallUnsupportedReason) != "":
		return plan.InstallUnsupportedReason
	case strings.TrimSpace(plan.NoInstallReason) != "":
		return plan.NoInstallReason
	case len(plan.Commands) > 0:
		commands := make([]string, 0, len(plan.Commands))
		for _, command := range plan.Commands {
			commands = append(commands, formatInstallCommand(command))
		}
		return strings.Join(commands, "; ")
	case len(plan.CheckExecutables) > 0:
		return "requires " + strings.Join(plan.CheckExecutables, ", ") + " on PATH"
	default:
		return "no install guidance"
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
