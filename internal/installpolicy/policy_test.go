package installpolicy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/openclaw/clawscan/internal/runner"
)

func TestDecodeRequestAcceptsSkillAndPluginPayloads(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		request    string
		wantKind   string
	}{
		{
			name:       "skill",
			targetType: "skill",
			wantKind:   "skill-install",
			request: `{
				"protocolVersion": 1,
				"openclawVersion": "2026.7.2",
				"targetType": "skill",
				"targetName": "weather",
				"sourcePath": "/tmp/staged/weather",
				"sourcePathKind": "directory",
				"source": {"kind":"clawhub","authority":"third-party","mutable":false,"network":true},
				"origin": {"type":"clawhub","slug":"weather","version":"1.0.0"},
				"request": {"kind":"skill-install","mode":"install","requestedSpecifier":"clawhub:weather@1.0.0"},
				"skill": {"installId":"clawhub"}
			}`,
		},
		{
			name:       "plugin",
			targetType: "plugin",
			wantKind:   "plugin-git",
			request: `{
				"protocolVersion": 1,
				"openclawVersion": "2026.7.2",
				"targetType": "plugin",
				"targetName": "example",
				"sourcePath": "/tmp/staged/example",
				"sourcePathKind": "directory",
				"source": {"kind":"git","authority":"third-party","mutable":true,"network":true},
				"origin": {"type":"git","url":"https://example.invalid/plugin.git","commit":"abc123"},
				"request": {"kind":"plugin-git","mode":"update","requestedSpecifier":"git:https://example.invalid/plugin.git"},
				"plugin": {"pluginId":"example","contentType":"bundle","manifestId":"example","version":"2.0.0"}
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := DecodeRequest(strings.NewReader(test.request))
			if err != nil {
				t.Fatal(err)
			}
			if request.TargetType != test.targetType {
				t.Fatalf("targetType = %q, want %q", request.TargetType, test.targetType)
			}
			if request.Request.Kind != test.wantKind {
				t.Fatalf("request.kind = %q, want %q", request.Request.Kind, test.wantKind)
			}
			if request.Origin["type"] == nil || request.Source == nil {
				t.Fatalf("source/origin metadata was not preserved: %#v", request)
			}
			if request.TargetType == "plugin" &&
				(request.Plugin == nil || request.Plugin.ContentType != "bundle") {
				t.Fatalf("plugin metadata was not preserved: %#v", request.Plugin)
			}
		})
	}
}

func TestDecodeRequestRejectsInvalidOrOversizedPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "malformed", payload: `{`, want: "invalid JSON"},
		{name: "protocol", payload: `{"protocolVersion":2}`, want: "protocolVersion must be 1"},
		{
			name: "target",
			payload: `{
				"protocolVersion":1,
				"targetType":"channel",
				"targetName":"demo",
				"sourcePath":"/tmp/demo",
				"sourcePathKind":"directory",
				"origin":{"type":"test"},
				"request":{"kind":"skill-install","mode":"install"}
			}`,
			want: `targetType must be "skill" or "plugin"`,
		},
		{
			name:    "oversized",
			payload: `{"protocolVersion":1,"padding":"` + strings.Repeat("x", maxRequestBytes) + `"}`,
			want:    "exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRequest(strings.NewReader(test.payload)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestResponseFromArtifactMapsGateAndScannerState(t *testing.T) {
	exitCode := 3
	tests := []struct {
		name     string
		artifact runner.Artifact
		decision string
		reason   bool
		findings int
	}{
		{
			name: "pass",
			artifact: runner.Artifact{
				Gate: "pass",
				Scanners: map[string]runner.ScannerResult{"static": {
					Status: "completed",
					Raw:    json.RawMessage(`{"findings":[]}`),
				}},
			},
			decision: "allow",
		},
		{
			name: "warn",
			artifact: runner.Artifact{
				Gate: "warn",
				Scanners: map[string]runner.ScannerResult{"static": {
					Status: "completed",
					Raw:    json.RawMessage(`{"findings":[]}`),
				}},
				GateRules: []runner.FiredGateRule{{
					Scanner: "static",
					Rule:    "finding",
					Path:    "findings[]",
					Action:  "warn",
				}},
			},
			decision: "warn",
			reason:   true,
			findings: 1,
		},
		{
			name: "block",
			artifact: runner.Artifact{
				Gate: "block",
				Scanners: map[string]runner.ScannerResult{"static": {
					Status: "completed",
					Raw:    json.RawMessage(`{"findings":[]}`),
				}},
				GateRules: []runner.FiredGateRule{{
					Scanner:  "static",
					Rule:     "exit-code",
					ExitCode: &exitCode,
					Action:   "block",
				}},
			},
			decision: "block",
			reason:   true,
			findings: 1,
		},
		{
			name: "unusable completed evidence",
			artifact: runner.Artifact{
				Gate: "pass",
				Scanners: map[string]runner.ScannerResult{
					"skillspector": {Status: "completed", Raw: json.RawMessage(`{}`)},
				},
			},
			decision: "block",
			reason:   true,
		},
		{
			name: "scanner failure",
			artifact: runner.Artifact{
				Gate:     "pass",
				Scanners: map[string]runner.ScannerResult{"static": {Status: "failed", Error: "boom"}},
			},
			decision: "block",
			reason:   true,
		},
		{
			name: "scanner skipped",
			artifact: runner.Artifact{
				Gate:     "pass",
				Scanners: map[string]runner.ScannerResult{"static": {Status: "skipped"}},
			},
			decision: "block",
			reason:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := ResponseFromArtifact(test.artifact)
			if response.Decision != test.decision ||
				(strings.TrimSpace(response.Reason) != "") != test.reason {
				t.Fatalf("response = %#v", response)
			}
			if len(response.Findings) != test.findings {
				t.Fatalf("findings = %#v, want %d", response.Findings, test.findings)
			}
		})
	}
}

func TestFailureResponseAndWriteResponseUsePolicyProtocol(t *testing.T) {
	response := FailureResponse("scanner exploded")
	var output bytes.Buffer
	if err := WriteResponse(&output, response); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["protocolVersion"] != float64(1) ||
		decoded["decision"] != "block" ||
		strings.TrimSpace(decoded["reason"].(string)) == "" {
		t.Fatalf("response = %#v", decoded)
	}
	if _, exists := decoded["code"]; exists {
		t.Fatalf("response contains non-contract code field: %#v", decoded)
	}
}

func TestWriteResponseSanitizesControlCharactersInAllDiagnosticText(t *testing.T) {
	response := Response{
		ProtocolVersion: 1,
		Decision:        "block",
		Reason:          "first line\nforged line\tend",
		Findings: []Finding{{
			RuleID:   "scanner.\x00rule",
			Severity: "critical",
			Message:  "message\r\nnext",
			Evidence: "path=\x1b[2J/tmp/demo",
		}},
	}
	var output bytes.Buffer
	if err := WriteResponse(&output, response); err != nil {
		t.Fatal(err)
	}
	var decoded Response
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"reason":   decoded.Reason,
		"ruleId":   decoded.Findings[0].RuleID,
		"message":  decoded.Findings[0].Message,
		"evidence": decoded.Findings[0].Evidence,
	} {
		for _, character := range value {
			if unicode.IsControl(character) {
				t.Fatalf("%s retained control character in %q", name, value)
			}
		}
	}
	if decoded.Reason != "first line forged line end" {
		t.Fatalf("reason = %q", decoded.Reason)
	}
}

func TestWriteResponseRequiresReasonsForWarnAndBlock(t *testing.T) {
	for _, decision := range []string{"warn", "block"} {
		t.Run(decision, func(t *testing.T) {
			var output bytes.Buffer
			err := WriteResponse(&output, Response{
				ProtocolVersion: 1,
				Decision:        decision,
				Reason:          "\n\t",
			})
			if err == nil || !strings.Contains(err.Error(), "requires a non-empty reason") {
				t.Fatalf("error = %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("invalid response reached stdout: %q", output.String())
			}
		})
	}
}

func TestWriteResponseRejectsUnsupportedDecision(t *testing.T) {
	var output bytes.Buffer
	err := WriteResponse(&output, Response{ProtocolVersion: 1, Decision: "confirm"})
	if err == nil || !strings.Contains(err.Error(), `"allow", "warn", or "block"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestResponseFromArtifactBoundsUntrustedFindingOutput(t *testing.T) {
	rules := make([]runner.FiredGateRule, maxFindings)
	for index := range rules {
		rules[index] = runner.FiredGateRule{
			Scanner: "static",
			Rule:    strings.Repeat("r", maxTextRunes+20),
			Path:    strings.Repeat("p", maxTextRunes+20),
			Action:  "warn",
		}
	}
	response := ResponseFromArtifact(runner.Artifact{
		Gate:      "warn",
		GateRules: rules,
		Scanners: map[string]runner.ScannerResult{"static": {
			Status: "completed",
			Raw:    json.RawMessage(`{"findings":[]}`),
		}},
	})
	if len(response.Findings) != maxFindings {
		t.Fatalf("findings = %d, want %d", len(response.Findings), maxFindings)
	}
	if len([]rune(response.Findings[0].RuleID)) > maxTextRunes+3 ||
		len([]rune(response.Findings[0].Evidence)) > maxTextRunes+3 {
		t.Fatalf("finding was not bounded: %#v", response.Findings[0])
	}
}

func TestAddFindingPreservesProtocolFindingBound(t *testing.T) {
	response := Response{
		ProtocolVersion: 1,
		Decision:        "allow",
		Findings:        make([]Finding, maxFindings),
	}
	AddFinding(&response, Finding{RuleID: "info", Severity: "info"})
	if len(response.Findings) != maxFindings {
		t.Fatalf("findings = %d", len(response.Findings))
	}
	AddFinding(&response, Finding{RuleID: "fallback", Severity: "warn"})
	if response.Findings[maxFindings-1].RuleID != "fallback" {
		t.Fatalf("visible warning was not retained: %#v", response.Findings[maxFindings-1])
	}
}

func TestResponseFromArtifactValidatesBuiltInEvidenceSchemas(t *testing.T) {
	tests := []struct {
		name      string
		scannerID string
		raw       string
		decision  string
	}{
		{
			name:      "static valid",
			scannerID: "clawscan-static",
			raw:       `{"schemaVersion":"clawscan-static-v1","findings":[]}`,
			decision:  "allow",
		},
		{
			name:      "static missing schema",
			scannerID: "clawscan-static",
			raw:       `{"findings":[]}`,
			decision:  "block",
		},
		{
			name:      "skillspector valid clean",
			scannerID: "skillspector",
			raw:       `{"status":"clean","findings":[]}`,
			decision:  "allow",
		},
		{
			name:      "skillspector error shaped",
			scannerID: "skillspector",
			raw:       `{"error":"scan failed"}`,
			decision:  "block",
		},
		{
			name:      "skillspector empty recommendation",
			scannerID: "skillspector",
			raw:       `{"recommendation":""}`,
			decision:  "block",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := ResponseFromArtifact(runner.Artifact{
				Gate: "pass",
				Scanners: map[string]runner.ScannerResult{
					test.scannerID: {Status: "completed", Raw: json.RawMessage(test.raw)},
				},
			})
			if response.Decision != test.decision {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}
