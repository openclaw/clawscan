package runner

import (
	"maps"
	"reflect"
	"testing"
)

func productionModelDefaults() map[string]string {
	return map[string]string{
		"SKILLSPECTOR_PROVIDER": "openai", "SKILLSPECTOR_MODEL": "gpt-6.1-sol",
		"SKILLSPECTOR_REASONING_EFFORT": "medium", "DEFAULT_MODEL": "gpt-6.1-sol", "REASONING_EFFORT": "medium",
	}
}

func TestProductionScannerModelDefaults(t *testing.T) {
	tests := []struct {
		name      string
		env, want map[string]string
	}{
		{"OpenAI production", map[string]string{"OPENAI_API_KEY": "fixture"}, productionModelDefaults()},
		{"Codex AIG fallback", map[string]string{"CODEX_API_KEY": "fixture"}, map[string]string{"DEFAULT_MODEL": "gpt-6.1-sol", "REASONING_EFFORT": "medium", "LLM_API_KEY": "fixture"}},
		{"dedicated OpenAI AIG", map[string]string{"LLM_API_KEY": "fixture", "DEFAULT_BASE_URL": defaultAIGOpenAIBaseURL}, map[string]string{"DEFAULT_MODEL": "gpt-6.1-sol", "REASONING_EFFORT": "medium"}},
		{"other provider", map[string]string{"SKILLSPECTOR_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "fixture", "LLM_API_KEY": "fixture"}, map[string]string{"SKILLSPECTOR_MODEL": "", "SKILLSPECTOR_REASONING_EFFORT": "", "DEFAULT_MODEL": "", "REASONING_EFFORT": ""}},
		{"explicit model", map[string]string{"OPENAI_API_KEY": "fixture", "SKILLSPECTOR_MODEL": "other-model", "DEFAULT_MODEL": "other-model"}, map[string]string{"SKILLSPECTOR_MODEL": "other-model", "DEFAULT_MODEL": "other-model", "SKILLSPECTOR_REASONING_EFFORT": "", "REASONING_EFFORT": ""}},
		{"explicit effort", map[string]string{"OPENAI_API_KEY": "fixture", "SKILLSPECTOR_REASONING_EFFORT": "high", "REASONING_EFFORT": "low"}, map[string]string{"SKILLSPECTOR_REASONING_EFFORT": "high", "REASONING_EFFORT": "low"}},
		{"third-party endpoint", map[string]string{"LLM_API_KEY": "fixture", "DEFAULT_BASE_URL": "https://provider.example/v1"}, map[string]string{"DEFAULT_MODEL": "", "REASONING_EFFORT": "", "DEFAULT_BASE_URL": "https://provider.example/v1"}},
		{"dedicated provider defaults", map[string]string{"LLM_API_KEY": "fixture"}, map[string]string{"DEFAULT_MODEL": "", "REASONING_EFFORT": "", "DEFAULT_BASE_URL": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := runtimeEnv(Options{Scanners: []string{"skillspector", "aig"}, ScannerEnvDefaults: productionModelDefaults()}, tt.env)
			for name, want := range tt.want {
				if got := env[name]; got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestSkillSpectorModelDefaultsWithInferredProvider(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		env                     map[string]string
		provider, model, effort string
	}{
		{"inferred OpenAI", map[string]string{"OPENAI_API_KEY": "fixture"}, "openai", "gpt-6.1-sol", "medium"},
		{"explicit model", map[string]string{"OPENAI_API_KEY": "fixture", "SKILLSPECTOR_MODEL": "operator-model"}, "openai", "operator-model", ""},
		{"explicit effort", map[string]string{"OPENAI_API_KEY": "fixture", "SKILLSPECTOR_REASONING_EFFORT": "high"}, "openai", "gpt-6.1-sol", "high"},
		{"explicit other provider", map[string]string{"OPENAI_API_KEY": "fixture", "SKILLSPECTOR_PROVIDER": "anthropic"}, "anthropic", "", ""},
		{"no OpenAI credential", map[string]string{"NVIDIA_INFERENCE_KEY": "fixture"}, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := runtimeEnv(Options{Scanners: []string{"skillspector"}, ScannerEnvDefaults: map[string]string{"SKILLSPECTOR_MODEL": "gpt-6.1-sol", "SKILLSPECTOR_REASONING_EFFORT": "medium"}}, tc.env)
			if env["SKILLSPECTOR_PROVIDER"] != tc.provider || env["SKILLSPECTOR_MODEL"] != tc.model || env["SKILLSPECTOR_REASONING_EFFORT"] != tc.effort {
				t.Fatalf("effective controls = provider %q, model %q, effort %q; want %q, %q, %q", env["SKILLSPECTOR_PROVIDER"], env["SKILLSPECTOR_MODEL"], env["SKILLSPECTOR_REASONING_EFFORT"], tc.provider, tc.model, tc.effort)
			}
		})
	}
}

func TestSkillSpectorExplicitProfileProviderPrecedesInference(t *testing.T) {
	env := runtimeEnv(Options{Scanners: []string{"skillspector"}, ScannerEnvDefaults: map[string]string{"SKILLSPECTOR_PROVIDER": "anthropic", "SKILLSPECTOR_MODEL": "gpt-6.1-sol", "SKILLSPECTOR_REASONING_EFFORT": "medium"}}, map[string]string{"OPENAI_API_KEY": "fixture"})
	if env["SKILLSPECTOR_PROVIDER"] != "anthropic" || env["SKILLSPECTOR_MODEL"] != "" || env["SKILLSPECTOR_REASONING_EFFORT"] != "" {
		t.Fatal("OpenAI inference overrode the explicit profile provider")
	}
}

func TestGenericScannersKeepProviderDefaults(t *testing.T) {
	env := runtimeEnv(Options{Scanners: []string{"skillspector", "aig"}}, map[string]string{"OPENAI_API_KEY": "fixture"})
	if env["SKILLSPECTOR_MODEL"] != "" || env["SKILLSPECTOR_REASONING_EFFORT"] != "" || env["REASONING_EFFORT"] != "" || env["DEFAULT_MODEL"] != defaultAIGOpenAIModel {
		t.Fatalf("generic defaults changed: %#v", env)
	}
	env = runtimeEnv(Options{Scanners: []string{fixtureScannerID}, ScannerEnvDefaults: productionModelDefaults()}, map[string]string{"OPENAI_API_KEY": "fixture"})
	if !reflect.DeepEqual(env, map[string]string{"OPENAI_API_KEY": "fixture"}) {
		t.Fatal("unselected scanner defaults applied")
	}
}

func TestScannerEnvDefaultsRejectCredentialsAndShell(t *testing.T) {
	for _, defaults := range []map[string]string{{"OPENAI_API_KEY": "fixture"}, {"PATH": "/tmp"}, {"SKILLSPECTOR_MODEL": "$(touch /tmp/unsafe)"}, {"DEFAULT_MODEL": ""}} {
		if err := ValidateScannerEnvDefaults(defaults); err == nil {
			t.Errorf("accepted unsafe defaults: %v", defaults)
		}
	}
}

func TestRunDoesNotLeakProfileDefaultsToNextRun(t *testing.T) {
	env := map[string]string{"OPENAI_API_KEY": "fixture"}
	opts := Options{Target: t.TempDir(), Scanners: []string{"skillspector"}, ScannerEnvDefaults: productionModelDefaults(), Sandbox: SandboxOptions{Mode: SandboxModeOff}}
	before := maps.Clone(env)
	if _, err := Run(opts, RunContext{Env: env, ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{"skillspector": {Status: "completed", Raw: []byte(`{"status":"clean"}`)}}}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(env, before) {
		t.Fatalf("caller environment mutated: %v", env)
	}
}

func TestBenchmarkKeepsProviderDefaultsLocalToEachProfile(t *testing.T) {
	opts := benchmarkTestOptions(t, "clawhub-security-signals", "eval_holdout", 0, 0, "")
	opts.Scanners = []string{"skillspector"}
	opts.Sandbox.Mode = SandboxModeOff
	ctx := RunContext{
		Env:                 map[string]string{"OPENAI_API_KEY": "fixture"},
		SkillSpectorCommand: []string{"skillspector"},
		CommandRunner:       &recordingCommandRunner{writeOutput: `{"status":"clean","findings":[]}`},
		BenchmarkClient:     staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{ID: "one", SkillMDContent: "# Fixture"}}},
	}
	for _, provider := range []string{"openai", "anthropic"} {
		opts.ScannerEnvDefaults = map[string]string{"SKILLSPECTOR_PROVIDER": provider}
		artifact, err := RunBenchmark(opts, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(artifact.Cases) != 1 || len(artifact.Cases[0].Run.Scanners["skillspector"].Command) == 0 {
			t.Fatalf("provider %s: expected one case with a SkillSpector command", provider)
		}
		command := artifact.Cases[0].Run.Scanners["skillspector"].Command
		if got, want := containsArg(command, "--no-llm"), provider == "anthropic"; got != want {
			t.Errorf("provider %s: --no-llm = %t, want %t", provider, got, want)
		}
	}
	if _, ok := ctx.Env["SKILLSPECTOR_PROVIDER"]; ok {
		t.Error("benchmark added a provider to the caller's environment")
	}
}
