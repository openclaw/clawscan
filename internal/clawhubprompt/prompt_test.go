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
	if strings.Contains(prompt, "VirusTotal") || strings.Contains(prompt, `"malicious": 1`) {
		t.Fatalf("prompt included legacy VirusTotal context:\n%s", prompt)
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

func TestBuildDoesNotMentionVirusTotal(t *testing.T) {
	job := fixtureJob()
	prompt, err := Build("SYSTEM", job, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "VirusTotal") || strings.Contains(prompt, `"z": 1`) {
		t.Fatalf("prompt included legacy VirusTotal context:\n%s", prompt)
	}
}

func TestBuildIncludesSupplementalScannerEvidence(t *testing.T) {
	prompt, err := Build("SYSTEM", fixtureJob(), nil, nil, ScannerEvidence{
		Label: "A.I.G SARIF evidence supplied to Codex",
		Value: RawJSON(`{"version":"2.1.0","runs":[{"results":[{"ruleId":"T04"}]}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"A.I.G SARIF evidence supplied to Codex:",
		`"ruleId": "T04"`,
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
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
