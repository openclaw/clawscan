package runner

import (
	"fmt"
	"regexp"
	"strings"
)

var scannerSettingPattern = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,200}$`)

// ValidateScannerEnvDefaults deliberately admits only non-secret model controls,
// not arbitrary environment assignments or provider implementations.
func ValidateScannerEnvDefaults(defaults map[string]string) error {
	for name, value := range defaults {
		switch name {
		case "SKILLSPECTOR_PROVIDER", "SKILLSPECTOR_MODEL", "SKILLSPECTOR_REASONING_EFFORT", "DEFAULT_MODEL", "REASONING_EFFORT":
		default:
			return fmt.Errorf("scannerEnvDefaults does not support %q; credentials belong in the environment", name)
		}
		if !scannerSettingPattern.MatchString(value) {
			return fmt.Errorf("scannerEnvDefaults %s must be a non-empty model control identifier", name)
		}
	}
	return nil
}

func applyScannerModelDefaults(opts Options, env map[string]string) {
	defaults := opts.ScannerEnvDefaults
	setDefault := func(name string) {
		if strings.TrimSpace(env[name]) == "" && defaults[name] != "" {
			env[name] = defaults[name]
		}
	}
	if scannerRequested(opts, "skillspector") {
		setDefault("SKILLSPECTOR_PROVIDER")
		// Infer the effective provider before considering provider-specific models.
		defaultSkillSpectorOpenAIProvider(env)
		// Other providers keep their own model defaults, even in a production profile.
		if strings.TrimSpace(env["SKILLSPECTOR_PROVIDER"]) == "openai" {
			setDefault("SKILLSPECTOR_MODEL")
			if env["SKILLSPECTOR_MODEL"] == defaults["SKILLSPECTOR_MODEL"] {
				setDefault("SKILLSPECTOR_REASONING_EFFORT")
			}
		}
	}
	if scannerRequested(opts, "aig") && defaults["DEFAULT_MODEL"] != "" {
		// An explicit non-OpenAI endpoint keeps AIG's provider defaults. Never route
		// a dedicated third-party key to OpenAI merely because a profile was selected.
		base := strings.TrimRight(strings.TrimSpace(env["DEFAULT_BASE_URL"]), "/")
		dedicatedKey := strings.TrimSpace(env["LLM_API_KEY"]) != ""
		if base != "" && base != defaultAIGOpenAIBaseURL {
			return
		}
		if dedicatedKey && base == "" {
			return
		}
		setDefault("DEFAULT_MODEL")
		if env["DEFAULT_MODEL"] == defaults["DEFAULT_MODEL"] {
			setDefault("REASONING_EFFORT")
		}
	}
}
