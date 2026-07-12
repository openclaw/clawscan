package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type stubScannerAdapter struct {
	id              string
	requirements    []EnvRequirement
	info            ScannerInfo
	installPlan     InstallPlan
	supportsPlugins bool
	run             func(target string, startedAt string) (ScannerResult, error)
}

func (adapter stubScannerAdapter) ID() string {
	return adapter.id
}

func (adapter stubScannerAdapter) Requirements(env map[string]string) []EnvRequirement {
	return append([]EnvRequirement(nil), adapter.requirements...)
}

func (adapter stubScannerAdapter) Info() ScannerInfo {
	return adapter.info
}

func (adapter stubScannerAdapter) InstallPlan() InstallPlan {
	return adapter.installPlan
}

func (adapter stubScannerAdapter) SupportsTargetKind(kind string) bool {
	if kind == targetKindPlugin {
		return adapter.supportsPlugins
	}
	return true
}

func (adapter stubScannerAdapter) Run(_ ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	if adapter.run != nil {
		return adapter.run(target, startedAt)
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: startedAt,
		Raw:         json.RawMessage(`{"ok":true}`),
	}, nil
}

func TestScannerRegistryReturnsSortedIDs(t *testing.T) {
	registry, err := NewScannerRegistry(
		stubScannerAdapter{id: "virustotal"},
		stubScannerAdapter{id: "clawscan-static"},
		stubScannerAdapter{id: "skillspector"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(registry.IDs(), ","); got != "clawscan-static,skillspector,virustotal" {
		t.Fatalf("ids = %q", got)
	}
}

func TestScannerRegistryRejectsDuplicateIDs(t *testing.T) {
	_, err := NewScannerRegistry(
		stubScannerAdapter{id: "clawscan-static"},
		stubScannerAdapter{id: "clawscan-static"},
	)
	if err == nil || err.Error() != "Duplicate scanner adapter id: clawscan-static" {
		t.Fatalf("err = %v", err)
	}
}

func TestScannerRegistryRejectsEmptyIDs(t *testing.T) {
	_, err := NewScannerRegistry(stubScannerAdapter{id: " "})
	if err == nil || err.Error() != "Scanner adapter id cannot be empty" {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultScannerRegistryContainsAllBuiltIns(t *testing.T) {
	want := "agentverus,aig,cisco,clawscan-static,skillspector,snyk,socket,virustotal"
	if got := strings.Join(DefaultScannerRegistry().IDs(), ","); got != want {
		t.Fatalf("ids = %q, want %q", got, want)
	}
}

func TestScannerAdaptersDeclareTargetKindSupport(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			t.Fatalf("missing adapter for %s", id)
		}
		if !adapter.SupportsTargetKind(targetKindSkill) {
			t.Fatalf("%s should support skill targets", id)
		}
		if !adapter.SupportsTargetKind(targetKindURL) {
			t.Fatalf("%s should support url targets", id)
		}
		wantPlugin := id == "clawscan-static"
		if got := adapter.SupportsTargetKind(targetKindPlugin); got != wantPlugin {
			t.Fatalf("%s plugin support = %v, want %v", id, got, wantPlugin)
		}
	}
	if !scannerSupportsTargetKind("clawscan-static", targetKindPlugin) {
		t.Fatal("clawscan-static should support plugin targets")
	}
	if scannerSupportsTargetKind("skillspector", targetKindPlugin) {
		t.Fatal("skillspector should not support plugin targets")
	}
	if !scannerSupportsTargetKind("unknown-scanner", targetKindPlugin) {
		t.Fatal("unknown scanners should be permitted so the runner emits its own skipped result")
	}
}

func TestExternalScannerRunnerDispatchesThroughRegistry(t *testing.T) {
	wantErr := errors.New("adapter called")
	registry, err := NewScannerRegistry(stubScannerAdapter{
		id: "demo",
		run: func(target string, startedAt string) (ScannerResult, error) {
			if target != "/tmp/skill" {
				t.Fatalf("target = %q", target)
			}
			if startedAt != "2026-06-23T12:00:00Z" {
				t.Fatalf("startedAt = %q", startedAt)
			}
			return ScannerResult{}, wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (ExternalScannerRunner{Registry: registry}).RunScanner("demo", "/tmp/skill", "2026-06-23T12:00:00Z")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v", err)
	}
}

func TestScannerAdapterRequirementsFeedValidation(t *testing.T) {
	requirements := stubScannerAdapter{
		id: "demo",
		requirements: []EnvRequirement{
			{EnvVar: "DEMO_TOKEN", Reason: "scanner demo"},
		},
	}.Requirements(map[string]string{})
	if len(requirements) != 1 || requirements[0].EnvVar != "DEMO_TOKEN" {
		t.Fatalf("requirements = %#v", requirements)
	}
}

func TestDefaultScannerRegistryProvidesInstallPlans(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			t.Fatalf("missing adapter for %s", id)
		}
		plan := adapter.InstallPlan()
		if plan.ScannerID != id {
			t.Fatalf("%s install plan scanner id = %q", id, plan.ScannerID)
		}
		if strings.TrimSpace(plan.Name) == "" {
			t.Fatalf("%s install plan missing name", id)
		}
	}
}

func TestDefaultScannerRegistryProvidesCatalogInfo(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		info, ok := registry.Info(id)
		if !ok {
			t.Fatalf("missing info for %s", id)
		}
		if info.ID != id {
			t.Fatalf("%s info id = %q", id, info.ID)
		}
		if strings.TrimSpace(info.DisplayName) == "" {
			t.Fatalf("%s info missing display name", id)
		}
		if strings.TrimSpace(info.Description) == "" {
			t.Fatalf("%s info missing description", id)
		}
		if strings.TrimSpace(info.RepositoryURL) == "" {
			t.Fatalf("%s info missing repository URL", id)
		}
	}

	skillspector, _ := registry.Info("skillspector")
	if got := strings.Join(skillspector.OptionalEnv, ","); got != "SKILLSPECTOR_PROVIDER,SKILLSPECTOR_MODEL,SKILLSPECTOR_MODEL_REGISTRY,SKILLSPECTOR_LOG_LEVEL,SKILLSPECTOR_SSL_VERIFY,NVIDIA_INFERENCE_KEY,OPENAI_API_KEY,OPENAI_BASE_URL,ANTHROPIC_API_KEY,ANTHROPIC_PROXY_ENDPOINT_URL,ANTHROPIC_PROXY_API_KEY,ANTHROPIC_PROXY_API_VERSION" {
		t.Fatalf("skillspector optional env = %q", got)
	}

	cisco, _ := registry.Info("cisco")
	if got := strings.Join(cisco.OptionalEnv, ","); got != "SKILL_SCANNER_LLM_API_KEY,SKILL_SCANNER_LLM_PROVIDER,SKILL_SCANNER_LLM_MODEL,SKILL_SCANNER_LLM_BASE_URL,SKILL_SCANNER_LLM_USER,SKILL_SCANNER_LLM_API_VERSION,SKILL_SCANNER_LLM_FORCE_JSON_OBJECT,SKILL_SCANNER_META_LLM_API_KEY,SKILL_SCANNER_META_LLM_MODEL,SKILL_SCANNER_META_LLM_BASE_URL,SKILL_SCANNER_META_LLM_API_VERSION,AWS_PROFILE,AWS_REGION,GOOGLE_APPLICATION_CREDENTIALS,VIRUSTOTAL_API_KEY,AI_DEFENSE_API_KEY,AI_DEFENSE_API_URL" {
		t.Fatalf("cisco optional env = %q", got)
	}

	socket, _ := registry.Info("socket")
	if got := strings.Join(socket.RequiredEnv, ","); got != "SOCKET_CLI_API_TOKEN" {
		t.Fatalf("socket required env = %q", got)
	}

	aig, _ := registry.Info("aig")
	if got := strings.Join(aig.RequiredEnv, ","); got != "LLM_API_KEY" {
		t.Fatalf("aig required env = %q", got)
	}
	if got := strings.Join(aig.OptionalEnv, ","); got != "OPENAI_API_KEY,DEFAULT_MODEL,DEFAULT_BASE_URL,DEFAULT_MODEL_CONTEXT_WINDOW,LOG_LEVEL" {
		t.Fatalf("aig optional env = %q", got)
	}
	if aig.InstallHint != "pip install aig-skill-scan" {
		t.Fatalf("aig install hint = %q", aig.InstallHint)
	}
	if !aig.Installable {
		t.Fatal("aig should be installable")
	}
}
