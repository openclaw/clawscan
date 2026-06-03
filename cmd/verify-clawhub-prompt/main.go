package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/openclaw/clawscan/internal/clawhubprompt"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	clawhubDir := flag.String("clawhub-dir", "", "Path to a ClawHub checkout")
	out := flag.String("out", "", "Optional JSON proof output path")
	flag.Parse()
	if *clawhubDir == "" {
		return fmt.Errorf("missing required --clawhub-dir")
	}
	systemPrompt, expected, err := renderClawHubPrompt(*clawhubDir)
	if err != nil {
		return err
	}
	actual, err := clawhubprompt.Build(systemPrompt, proofJob(), []string{"html-comment-injection"}, proofSkillSpectorAnalysis())
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("ClawHub prompt parity check failed")
	}
	proof := map[string]any{
		"ok":                        true,
		"clawhubDir":                filepath.Clean(*clawhubDir),
		"promptSha256":              sha(actual),
		"promptLength":              len(actual),
		"explicitSkillSpectorInput": true,
		"skillSpectorMarkerPresent": bytes.Contains([]byte(actual), []byte("SkillSpector findings supplied to Codex")),
		"skillSpectorIssuePresent":  bytes.Contains([]byte(actual), []byte("SDI-1")),
	}
	encoded, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	fmt.Println(string(encoded))
	return nil
}

func renderClawHubPrompt(clawhubDir string) (string, string, error) {
	script := `
const clawhubDir = process.argv[1];
const worker = await import(clawhubDir + "/scripts/security/run-codex-scan-worker.ts");
const securityPrompt = await import(clawhubDir + "/convex/lib/securityPrompt.ts");
const skillSpectorAnalysis = {
  status: "suspicious",
  score: 55,
  recommendation: "DO_NOT_INSTALL",
  issueCount: 1,
  checkedAt: 123,
  issues: [{ issueId: "SDI-1", severity: "HIGH", explanation: "Mismatch" }],
};
const job = {
  job: {
    _id: "job123",
    hasMaliciousSignal: true,
    leaseToken: "lease-secret",
    source: "publish",
    targetKind: "skillVersion",
    waitForVtUntil: 0,
  },
  target: {
    trustedOpenClawPlugin: true,
    version: {
      vtAnalysis: {
        status: "suspicious",
        source: "engines",
        metadata: { stats: { malicious: 1, suspicious: 0, harmless: 12 } },
      },
    },
  },
};
console.log(JSON.stringify({
  systemPrompt: securityPrompt.SKILL_SECURITY_EVALUATOR_SYSTEM_PROMPT,
  prompt: worker.buildPrompt(job, ["html-comment-injection"], skillSpectorAnalysis),
}));
`
	cmd := exec.Command("bun", "-e", script, "--", clawhubDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("render ClawHub prompt with bun: %w: %s", err, stderr.String())
	}
	var payload struct {
		SystemPrompt string `json:"systemPrompt"`
		Prompt       string `json:"prompt"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return "", "", err
	}
	return payload.SystemPrompt, payload.Prompt, nil
}

func proofJob() clawhubprompt.Job {
	return clawhubprompt.Job{
		Job: clawhubprompt.JobMetadata{
			TargetKind:         "skillVersion",
			Source:             "publish",
			HasMaliciousSignal: true,
		},
		Target: clawhubprompt.Target{
			TrustedOpenClawPlugin: true,
			Version: &clawhubprompt.Version{
				VTAnalysis: vtAnalysis{
					Status: "suspicious",
					Source: "engines",
					Metadata: vtMetadata{
						Stats: vtStats{Malicious: 1, Suspicious: 0, Harmless: 12},
					},
				},
			},
		},
	}
}

func proofSkillSpectorAnalysis() skillSpectorAnalysis {
	return skillSpectorAnalysis{
		Status:         "suspicious",
		Score:          55,
		Recommendation: "DO_NOT_INSTALL",
		IssueCount:     1,
		CheckedAt:      123,
		Issues: []skillSpectorIssue{{
			IssueID:     "SDI-1",
			Severity:    "HIGH",
			Explanation: "Mismatch",
		}},
	}
}

type vtAnalysis struct {
	Status   string     `json:"status"`
	Source   string     `json:"source"`
	Metadata vtMetadata `json:"metadata"`
}

type vtMetadata struct {
	Stats vtStats `json:"stats"`
}

type vtStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
}

type skillSpectorAnalysis struct {
	Status         string              `json:"status"`
	Score          int                 `json:"score"`
	Recommendation string              `json:"recommendation"`
	IssueCount     int                 `json:"issueCount"`
	CheckedAt      int                 `json:"checkedAt"`
	Issues         []skillSpectorIssue `json:"issues"`
}

type skillSpectorIssue struct {
	IssueID     string `json:"issueId"`
	Severity    string `json:"severity"`
	Explanation string `json:"explanation"`
}

func sha(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
