package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func clawHubSkillSpectorSeverityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "NONE":
		return 0
	case "LOW":
		return 2
	case "MEDIUM":
		return 3
	case "HIGH":
		return 4
	case "CRITICAL":
		return 5
	default:
		return 1
	}
}

func clawHubBundleFindingPath(root, file string) string {
	file = strings.ReplaceAll(strings.TrimSpace(file), "\\", "/")
	if strings.HasPrefix(file, "./") {
		file = strings.TrimLeft(file[1:], "/")
	}
	if file == root || strings.HasPrefix(file, root+"/") {
		return file
	}
	if index := strings.LastIndex(file, "/"+root+"/"); index >= 0 {
		return file[index+1:]
	}
	segments := []string{}
	for _, segment := range strings.Split(file, "/") {
		if segment != "" && segment != "." && segment != ".." {
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return root
	}
	return root + "/" + strings.Join(segments, "/")
}

// Only the fully attested complete-bundle contract uses this derivation. The
// original reports remain unchanged; display aliases cannot hide their issues.
func deriveClawHubCompleteBundleEvidence(raw json.RawMessage, record map[string]any, checkedAt int64) (clawHubNormalizedSkillSpectorAnalysis, bool) {
	if !skillSpectorHasBundle(record) || !skillSpectorUsableBundledComplete(raw) {
		return clawHubNormalizedSkillSpectorAnalysis{}, false
	}
	entries := record["bundled_reports"].([]any)
	issues := []clawHubSkillSpectorIssue{}
	var score *float64
	severity := ""
	malicious, suspicious := false, false
	versions := map[string]bool{}
	observeRisk := func(source map[string]any) {
		malicious = malicious || strings.EqualFold(readMapString(source, "status"), "malicious")
		suspicious = suspicious || strings.EqualFold(readMapString(source, "status"), "suspicious")
		observe := func(source map[string]any, scoreKeys, severityKeys []string) {
			for _, key := range scoreKeys {
				if value := readMapNumber(source, key); value != nil && (score == nil || *value > *score) {
					score = value
				}
			}
			for _, key := range severityKeys {
				value := strings.ToUpper(readMapString(source, key))
				if value != "" && (severity == "" || clawHubSkillSpectorSeverityRank(value) > clawHubSkillSpectorSeverityRank(severity)) {
					severity = value
				}
			}
		}
		observe(source, []string{"risk_score", "riskScore", "score"}, []string{"risk_severity", "riskSeverity", "severity"})
		for _, key := range []string{"risk_assessment", "riskAssessment"} {
			observe(asStringMap(source[key]), []string{"score"}, []string{"severity"})
		}
	}
	observeRisk(record)
	for _, value := range entries {
		entry := asStringMap(value)
		child := asStringMap(entry["report"])
		root := entry["rootPath"].(string)
		observeRisk(child)
		version := firstNonEmpty(readMapString(child, "scanner_version", "scannerVersion", "version"), readNestedMapString(child, []string{"metadata"}, "skillspector_version", "skillspectorVersion", "version"))
		if version != "" {
			versions[version] = true
		}
		for _, value := range child["issues"].([]any) {
			issue := normalizeClawHubSkillSpectorIssue(value, len(issues))
			if issue.File != "" {
				issue.File = truncateClawHubText(clawHubBundleFindingPath(root, issue.File), maxClawHubSkillSpectorShortTextChars)
			}
			if severity == "" || clawHubSkillSpectorSeverityRank(issue.Severity) > clawHubSkillSpectorSeverityRank(severity) {
				severity = issue.Severity
			}
			issues = append(issues, *issue)
		}
	}
	// Consider all children before capping; a later HIGH must outrank earlier LOWs.
	sort.SliceStable(issues, func(i, j int) bool {
		return clawHubSkillSpectorSeverityRank(issues[i].Severity) > clawHubSkillSpectorSeverityRank(issues[j].Severity)
	})
	issueCount := len(issues)
	status, recommendation := "clean", "SAFE"
	if malicious {
		status, recommendation = "malicious", "UNSAFE"
	} else if suspicious || issueCount > 0 || score != nil && *score > 20 || clawHubSkillSpectorSeverityRank(severity) >= 2 {
		status, recommendation = "suspicious", "REVIEW"
	}
	versionList := make([]string, 0, len(versions))
	for version := range versions {
		versionList = append(versionList, version)
	}
	sort.Strings(versionList)
	return clawHubNormalizedSkillSpectorAnalysis{
		Status: status, Score: score, Severity: severity, Recommendation: recommendation,
		IssueCount: issueCount, Issues: issues, CheckedAt: checkedAt,
		ScannerVersion:    truncateClawHubText(strings.Join(versionList, ", "), maxClawHubSkillSpectorShortTextChars),
		Summary:           fmt.Sprintf("Scanned %d bundled skills.", len(entries)),
		InspectionCaveats: normalizeClawHubReportInspectionCaveats(record),
	}, true
}

// JSON gates receive the same derived evidence as the judge, without the
// judge's presentation cap. This private evaluation view never replaces Raw.
func clawHubCompleteBundleGateEvidence(raw json.RawMessage) json.RawMessage {
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		return raw
	}
	analysis, complete := deriveClawHubCompleteBundleEvidence(raw, record, 0)
	if !complete {
		return raw
	}
	record["status"] = analysis.Status
	record["issue_count"] = analysis.IssueCount
	record["filtered_findings"] = analysis.Issues
	record["risk_assessment"] = map[string]any{"score": analysis.Score, "severity": analysis.Severity, "recommendation": analysis.Recommendation}
	view, err := json.Marshal(record)
	if err != nil {
		return raw
	}
	return view
}

func evaluateClawHubCompleteBundleGateRules(artifact *Artifact, scanner string, raw json.RawMessage, rules []JSONGateRule) {
	// Keep every existing raw-evidence match, then let child-derived evidence
	// trigger remaining rules. Each configured rule is recorded at most once.
	start := len(artifact.GateRules)
	evaluateJSONGateRules(artifact, scanner, raw, rules)
	view := clawHubCompleteBundleGateEvidence(raw)
	if bytes.Equal(view, raw) {
		return
	}
	matched := map[string]bool{}
	for _, fired := range artifact.GateRules[start:] {
		matched[fired.Rule] = true
	}
	remaining := make([]JSONGateRule, 0, len(rules))
	for _, rule := range rules {
		if !matched[rule.ID] {
			remaining = append(remaining, rule)
		}
	}
	evaluateJSONGateRules(artifact, scanner, view, remaining)
}
