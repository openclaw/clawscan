package installpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/openclaw/clawscan/internal/runner"
)

const (
	maxRequestBytes = 256 * 1024
	maxFindings     = 100
	maxTextRunes    = 1000
)

type Source struct {
	Kind      string `json:"kind"`
	Authority string `json:"authority"`
	Mutable   bool   `json:"mutable"`
	Network   bool   `json:"network"`
}

type RequestMetadata struct {
	Kind               string `json:"kind"`
	Mode               string `json:"mode"`
	RequestedSpecifier string `json:"requestedSpecifier,omitempty"`
}

type PluginMetadata struct {
	PluginID    string   `json:"pluginId"`
	ContentType string   `json:"contentType"`
	PackageName string   `json:"packageName,omitempty"`
	ManifestID  string   `json:"manifestId,omitempty"`
	Version     string   `json:"version,omitempty"`
	Extensions  []string `json:"extensions,omitempty"`
}

type Request struct {
	ProtocolVersion int             `json:"protocolVersion"`
	OpenClawVersion string          `json:"openclawVersion,omitempty"`
	TargetType      string          `json:"targetType"`
	TargetName      string          `json:"targetName"`
	SourcePath      string          `json:"sourcePath"`
	SourcePathKind  string          `json:"sourcePathKind"`
	Source          *Source         `json:"source,omitempty"`
	Origin          map[string]any  `json:"origin"`
	Request         RequestMetadata `json:"request"`
	Skill           json.RawMessage `json:"skill,omitempty"`
	Plugin          *PluginMetadata `json:"plugin,omitempty"`
}

type Finding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

type Response struct {
	ProtocolVersion int       `json:"protocolVersion"`
	Decision        string    `json:"decision"`
	Code            string    `json:"code,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	Findings        []Finding `json:"findings,omitempty"`
}

func AddFinding(response *Response, finding Finding) {
	if len(response.Findings) < maxFindings {
		response.Findings = append(response.Findings, finding)
		return
	}
	if response.Decision == "allow" && finding.Severity == "warn" {
		response.Findings[len(response.Findings)-1] = finding
	}
}

func DecodeRequest(input io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("read policy request: %w", err)
	}
	if len(data) > maxRequestBytes {
		return Request{}, fmt.Errorf("policy request exceeds %d bytes", maxRequestBytes)
	}
	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		return Request{}, fmt.Errorf("policy request contains invalid JSON: %w", err)
	}
	if err := validateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func validateRequest(request Request) error {
	if request.ProtocolVersion != 1 {
		return errors.New("policy request protocolVersion must be 1")
	}
	if request.TargetType != "skill" && request.TargetType != "plugin" {
		return errors.New(`policy request targetType must be "skill" or "plugin"`)
	}
	if strings.TrimSpace(request.TargetName) == "" {
		return errors.New("policy request targetName must not be empty")
	}
	if strings.TrimSpace(request.SourcePath) == "" {
		return errors.New("policy request sourcePath must not be empty")
	}
	if request.SourcePathKind != "file" && request.SourcePathKind != "directory" {
		return errors.New(`policy request sourcePathKind must be "file" or "directory"`)
	}
	originType, ok := request.Origin["type"].(string)
	if !ok || strings.TrimSpace(originType) == "" {
		return errors.New("policy request origin.type must not be empty")
	}
	if request.Request.Mode != "install" && request.Request.Mode != "update" {
		return errors.New(`policy request request.mode must be "install" or "update"`)
	}
	if request.TargetType == "skill" && request.Request.Kind != "skill-install" {
		return errors.New(`skill policy request kind must be "skill-install"`)
	}
	if request.TargetType == "plugin" && !validPluginRequestKind(request.Request.Kind) {
		return errors.New("plugin policy request kind is not supported")
	}
	if request.TargetType == "plugin" {
		if request.Plugin == nil {
			return errors.New("plugin policy request plugin metadata must be present")
		}
		if strings.TrimSpace(request.Plugin.PluginID) == "" {
			return errors.New("plugin policy request plugin.pluginId must not be empty")
		}
		if request.Plugin.PluginID != request.TargetName {
			return errors.New("plugin policy request plugin.pluginId must match targetName")
		}
		switch request.Plugin.ContentType {
		case "bundle", "package", "file", "dependency-tree":
		default:
			return errors.New("plugin policy request plugin.contentType is not supported")
		}
		originType, _ := request.Origin["type"].(string)
		if request.Plugin.ContentType == "dependency-tree" &&
			(originType != "plugin-dependency-tree" || request.SourcePathKind != "directory") {
			return errors.New("dependency-tree policy request metadata is inconsistent")
		}
		if originType == "plugin-dependency-tree" &&
			request.Plugin.ContentType != "dependency-tree" {
			return errors.New("dependency-tree policy request content role is inconsistent")
		}
	}
	return nil
}

func validPluginRequestKind(kind string) bool {
	switch kind {
	case "plugin-dir", "plugin-archive", "plugin-file", "plugin-npm", "plugin-git":
		return true
	default:
		return false
	}
}

func (request Request) IsNPMMetadataPreflight() bool {
	if request.TargetType != "plugin" ||
		request.Request.Kind != "plugin-npm" ||
		request.SourcePathKind != "file" ||
		filepath.Base(filepath.Clean(request.SourcePath)) != "npm-package-metadata.json" ||
		request.Plugin == nil ||
		request.Plugin.ContentType != "package" ||
		strings.TrimSpace(request.Plugin.PackageName) == "" ||
		request.Source == nil ||
		request.Source.Kind != "npm" ||
		request.Source.Mutable ||
		!request.Source.Network ||
		(request.Source.Authority != "official" && request.Source.Authority != "third-party") {
		return false
	}
	originType, _ := request.Origin["type"].(string)
	originPackageName, _ := request.Origin["packageName"].(string)
	return originType == "plugin-npm" && originPackageName == request.Plugin.PackageName
}

func (request Request) IsDependencyTree() bool {
	if request.TargetType != "plugin" ||
		request.SourcePathKind != "directory" ||
		request.Plugin == nil ||
		request.Plugin.ContentType != "dependency-tree" {
		return false
	}
	originType, _ := request.Origin["type"].(string)
	return originType == "plugin-dependency-tree"
}

func (request Request) AllowsManagedNPMRootPeerLinks() bool {
	return request.IsDependencyTree() &&
		request.Request.Kind == "plugin-npm" &&
		request.Source != nil &&
		request.Source.Kind == "npm" &&
		!request.Source.Mutable &&
		request.Source.Network &&
		(request.Source.Authority == "official" || request.Source.Authority == "third-party")
}

func ResponseFromArtifact(artifact runner.Artifact) Response {
	scannerIDs := make([]string, 0, len(artifact.Scanners))
	for scannerID := range artifact.Scanners {
		scannerIDs = append(scannerIDs, scannerID)
	}
	sort.Strings(scannerIDs)
	for _, scannerID := range scannerIDs {
		result := artifact.Scanners[scannerID]
		if result.Status != "completed" {
			return FailureResponse(fmt.Sprintf(
				"required scanner %s did not complete (status %s)",
				scannerID,
				result.Status,
			))
		}
		if !scannerEvidenceUsable(scannerID, result.Raw) {
			return FailureResponse(fmt.Sprintf(
				"required scanner %s returned unusable evidence",
				scannerID,
			))
		}
	}
	if len(scannerIDs) == 0 {
		return FailureResponse("scan produced no scanner results")
	}

	if len(artifact.GateRules) > maxFindings {
		return FailureResponse("scan returned too many fired gate rules")
	}
	for _, rule := range artifact.GateRules {
		if _, ok := artifact.Scanners[rule.Scanner]; !ok {
			return FailureResponse("fired gate rule referenced an unavailable scanner")
		}
		if rule.Action != "warn" && rule.Action != "block" {
			return FailureResponse("scan returned a fired gate rule with an unknown action")
		}
	}
	findings := findingsFromRules(artifact.GateRules)
	switch artifact.Gate {
	case "pass":
		if len(artifact.GateRules) != 0 {
			return FailureResponse("pass verdict unexpectedly contained fired gate rules")
		}
		return Response{ProtocolVersion: 1, Decision: "allow"}
	case "warn":
		if len(findings) == 0 {
			return FailureResponse("warn verdict did not contain a fired warning rule")
		}
		for _, finding := range findings {
			if finding.Severity != "warn" {
				return FailureResponse("warn verdict contained a blocking gate rule")
			}
		}
		return Response{ProtocolVersion: 1, Decision: "allow", Findings: findings}
	case "block":
		hasBlockingFinding := false
		for _, finding := range findings {
			if finding.Severity == "critical" {
				hasBlockingFinding = true
				break
			}
		}
		if !hasBlockingFinding {
			return FailureResponse("block verdict did not contain a fired blocking rule")
		}
		return Response{
			ProtocolVersion: 1,
			Decision:        "block",
			Code:            "clawscan_gate_blocked",
			Reason:          "ClawScan gate blocked the staged installation",
			Findings:        findings,
		}
	default:
		return FailureResponse(fmt.Sprintf("scan returned unknown gate verdict %q", artifact.Gate))
	}
}

func scannerEvidenceUsable(scannerID string, raw json.RawMessage) bool {
	var decoded any
	if len(raw) == 0 || json.Unmarshal(raw, &decoded) != nil {
		return false
	}
	record, isRecord := decoded.(map[string]any)
	switch scannerID {
	case "clawscan-static":
		if !isRecord || record["schemaVersion"] != "clawscan-static-v1" {
			return false
		}
		_, ok := record["findings"].([]any)
		return ok
	case "skillspector":
		return isRecord && skillSpectorEvidenceUsable(record)
	default:
		switch decoded.(type) {
		case map[string]any, []any:
			return true
		default:
			return false
		}
	}
}

func skillSpectorEvidenceUsable(record map[string]any) bool {
	if record["execution_successful"] == false || record["executionSuccessful"] == false {
		return false
	}
	if value, ok := record["error"].(string); ok && strings.TrimSpace(value) != "" {
		return false
	}
	if status, ok := record["status"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(status)) {
		case "benign", "safe", "clean", "suspicious", "malicious":
			return true
		}
	}
	if recommendation, ok := record["recommendation"].(string); ok &&
		strings.TrimSpace(recommendation) != "" {
		return true
	}
	if _, ok := record["score"].(float64); ok {
		return true
	}
	for _, key := range []string{"risk_assessment", "riskAssessment"} {
		if assessment, ok := record[key].(map[string]any); ok {
			if recommendation, exists := assessment["recommendation"].(string); exists &&
				strings.TrimSpace(recommendation) != "" {
				return true
			}
			if _, exists := assessment["score"].(float64); exists {
				return true
			}
		}
	}
	for _, key := range []string{
		"filtered_findings",
		"filteredFindings",
		"findings",
		"issues",
		"vulnerabilities",
	} {
		if _, ok := record[key].([]any); ok {
			return true
		}
	}
	return false
}

func findingsFromRules(rules []runner.FiredGateRule) []Finding {
	findings := make([]Finding, 0, len(rules))
	for _, rule := range rules {
		if len(findings) == maxFindings {
			break
		}
		severity := "warn"
		if rule.Action == "block" {
			severity = "critical"
		}
		message := fmt.Sprintf("%s fired rule %s", rule.Scanner, rule.Rule)
		evidence := ""
		switch {
		case rule.ExitCode != nil:
			evidence = fmt.Sprintf("exitCode=%d", *rule.ExitCode)
		case rule.Path != "" && len(rule.Value) > 0:
			evidence = fmt.Sprintf("%s=%s", rule.Path, string(rule.Value))
		case rule.Path != "":
			evidence = rule.Path
		}
		findings = append(findings, Finding{
			RuleID:   truncateText(rule.Scanner + "." + rule.Rule),
			Severity: severity,
			Message:  truncateText(message),
			Evidence: truncateText(evidence),
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}

func FailureResponse(reason string) Response {
	return Response{
		ProtocolVersion: 1,
		Decision:        "block",
		Code:            "clawscan_scan_failed",
		Reason:          truncateText("ClawScan install policy failed closed: " + reason),
	}
}

func truncateText(value string) string {
	cleaned := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	runes := []rune(strings.Join(strings.Fields(cleaned), " "))
	if len(runes) <= maxTextRunes {
		return string(runes)
	}
	return string(runes[:maxTextRunes]) + "..."
}

func WriteResponse(output io.Writer, response Response) error {
	response.Code = truncateText(response.Code)
	response.Reason = truncateText(response.Reason)
	for index := range response.Findings {
		response.Findings[index].RuleID = truncateText(response.Findings[index].RuleID)
		response.Findings[index].Message = truncateText(response.Findings[index].Message)
		response.Findings[index].Evidence = truncateText(response.Findings[index].Evidence)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
