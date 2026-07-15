package clawhubprompt

import (
	"strings"
	"testing"
)

func TestBuildPlacesScannerEvidenceInClawHubSlots(t *testing.T) {
	prompt, err := Build("SYSTEM", fixtureJob(), []string{"html-comment-injection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SYSTEM\n\nAdditional ClawHub policy for this Codex run:",
		"VirusTotal telemetry supplied to Codex:",
		`"malicious": 1`,
		"SkillSpector findings supplied to Codex:",
		"SDI-1",
		"- pre-scan artifact injection signals: html-comment-injection",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
	if !strings.HasSuffix(prompt, "Return the required JSON object only.") {
		t.Fatalf("unexpected suffix: %q", prompt[len(prompt)-80:])
	}
}

func TestBuildUsesExplicitSkillSpectorAnalysis(t *testing.T) {
	job := fixtureJob()
	job.Target.Version.SkillSpectorAnalysis = skillSpectorAnalysis{
		Status:         "stale-target-analysis",
		Score:          1,
		Recommendation: "INSTALL",
		IssueCount:     0,
		CheckedAt:      1,
	}
	prompt, err := Build("SYSTEM", job, nil, skillSpectorAnalysis{
		Status:         "fresh-runtime-analysis",
		Score:          88,
		Recommendation: "DO_NOT_INSTALL",
		IssueCount:     1,
		CheckedAt:      456,
		Issues: []skillSpectorIssue{{
			IssueID:     "RUNTIME-SDI",
			Severity:    "CRITICAL",
			Explanation: "Fresh analyzer result",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "fresh-runtime-analysis") || !strings.Contains(prompt, "RUNTIME-SDI") {
		t.Fatalf("prompt did not include explicit SkillSpector analysis:\n%s", prompt)
	}
	if strings.Contains(prompt, "stale-target-analysis") {
		t.Fatalf("prompt used target SkillSpector analysis instead of explicit runtime analysis:\n%s", prompt)
	}
}

func TestBuildPreservesRawJSONEvidenceOrder(t *testing.T) {
	job := fixtureJob()
	job.Target.Version.VTAnalysis = RawJSON("{\"z\":1,\"a\":2}\n")
	prompt, err := Build("SYSTEM", job, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	zIndex := strings.Index(prompt, `"z": 1`)
	aIndex := strings.Index(prompt, `"a": 2`)
	if zIndex < 0 || aIndex < 0 {
		t.Fatalf("prompt missing raw JSON fields:\n%s", prompt)
	}
	if zIndex > aIndex {
		t.Fatalf("raw JSON key order was not preserved:\n%s", prompt)
	}
	if strings.Contains(prompt, "\"a\": 2\n\n```") {
		t.Fatalf("raw JSON trailing newline leaked into prompt:\n%s", prompt)
	}
}

func TestBuildFormatsEmptyRawJSONAsNull(t *testing.T) {
	job := fixtureJob()
	job.Target.Version.VTAnalysis = RawJSON(nil)
	prompt, err := Build("SYSTEM", job, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "VirusTotal telemetry supplied to Codex:\n```json\nnull\n```") {
		t.Fatalf("prompt did not render empty raw JSON as null:\n%s", prompt)
	}
}

func fixtureJob() Job {
	return Job{
		Job: JobMetadata{
			TargetKind:         "skillVersion",
			Source:             "publish",
			HasMaliciousSignal: true,
		},
		Target: Target{
			TrustedOpenClawPlugin: true,
			Version: &Version{
				VTAnalysis: vtAnalysis{
					Status: "suspicious",
					Source: "engines",
					Metadata: vtMetadata{Stats: vtStats{
						Malicious:  1,
						Suspicious: 0,
						Harmless:   12,
					}},
				},
				SkillSpectorAnalysis: skillSpectorAnalysis{
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
				},
			},
		},
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
