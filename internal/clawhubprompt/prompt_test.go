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
