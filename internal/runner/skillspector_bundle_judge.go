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

func clawHubBundleComponentPaths(child map[string]any) map[string]bool {
	paths := map[string]bool{}
	for _, value := range child["components"].([]any) {
		component := asStringMap(value)
		paths[component["path"].(string)] = true
	}
	return paths
}

func clawHubBundleFindingPath(root, file string, components map[string]bool) string {
	file = strings.ReplaceAll(strings.TrimSpace(file), "\\", "/")
	if strings.HasPrefix(file, "./") {
		file = strings.TrimLeft(file[1:], "/")
	}
	// Native findings name child components. Prefer an exact inventory match
	// before recognizing a path that only happens to start with the bundle root.
	if components[file] {
		return root + "/" + file
	}
	if file == root || strings.HasPrefix(file, root+"/") {
		return file
	}
	// Only absolute paths can carry an external staging prefix. A relative
	// assets/<root>/file path names a real child file and must keep that prefix.
	absolute := strings.HasPrefix(file, "/") || len(file) >= 3 && ((file[0] >= 'A' && file[0] <= 'Z') || (file[0] >= 'a' && file[0] <= 'z')) && file[1:3] == ":/"
	if absolute {
		if index := strings.Index(file, "/"+root+"/"); index >= 0 {
			return file[index+1:]
		}
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

func clawHubSkillSpectorRecommendationRank(recommendation string) int {
	switch strings.ToUpper(strings.TrimSpace(recommendation)) {
	case "UNSAFE", "DO_NOT_INSTALL":
		return 3
	case "REVIEW", "CAUTION":
		return 2
	case "SAFE":
		return 1
	default:
		return 0
	}
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
	recommendation := "SAFE"
	malicious, suspicious := false, false
	versions := map[string]bool{}
	observeRisk := func(source map[string]any) {
		malicious = malicious || strings.EqualFold(readMapString(source, "status"), "malicious")
		suspicious = suspicious || strings.EqualFold(readMapString(source, "status"), "suspicious")
		observe := func(source map[string]any, scoreKeys, severityKeys []string) {
			for _, key := range []string{"recommendation", "risk_recommendation", "riskRecommendation"} {
				value := strings.ToUpper(strings.TrimSpace(readMapString(source, key)))
				if clawHubSkillSpectorRecommendationRank(value) > clawHubSkillSpectorRecommendationRank(recommendation) {
					recommendation = value
				}
			}
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
		components := clawHubBundleComponentPaths(child)
		observeRisk(child)
		version := firstNonEmpty(readMapString(child, "scanner_version", "scannerVersion", "version"), readNestedMapString(child, []string{"metadata"}, "skillspector_version", "skillspectorVersion", "version"))
		if version != "" {
			versions[version] = true
		}
		for _, value := range child["issues"].([]any) {
			issue := normalizeClawHubSkillSpectorIssue(value, len(issues))
			source := asStringMap(value)
			file := firstNonEmpty(readMapString(source, "file", "file_path", "filePath", "path"), readNestedMapString(source, []string{"location"}, "file", "path"))
			if file != "" {
				issue.File = truncateClawHubText(clawHubBundleFindingPath(root, file, components), maxClawHubSkillSpectorShortTextChars)
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
	status := "clean"
	if malicious || clawHubSkillSpectorRecommendationRank(recommendation) == 3 {
		status = "malicious"
		if clawHubSkillSpectorRecommendationRank(recommendation) < 3 {
			recommendation = "UNSAFE"
		}
	} else if suspicious || clawHubSkillSpectorRecommendationRank(recommendation) == 2 || issueCount > 0 || score != nil && *score > 20 || clawHubSkillSpectorSeverityRank(severity) >= 2 {
		status = "suspicious"
		if clawHubSkillSpectorRecommendationRank(recommendation) < 2 {
			recommendation = "REVIEW"
		}
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

// JSON gates need native findings, not the judge's renamed and bounded display
// summary. Copy every field while rooting only known file-location fields.
func clawHubBundleChildGateFindings(root string, child map[string]any) []any {
	findings := []any{}
	components := clawHubBundleComponentPaths(child)
	for _, value := range child["issues"].([]any) {
		original := asStringMap(value)
		finding := make(map[string]any, len(original))
		for key, value := range original {
			finding[key] = value
		}
		rootPaths := func(fields map[string]any, keys []string) {
			for _, key := range keys {
				if path, ok := fields[key].(string); ok && path != "" {
					fields[key] = clawHubBundleFindingPath(root, path, components)
				}
			}
		}
		rootPaths(finding, []string{"file", "file_path", "filePath", "path"})
		if location := asStringMap(original["location"]); location != nil {
			copy := make(map[string]any, len(location))
			for key, value := range location {
				copy[key] = value
			}
			rootPaths(copy, []string{"file", "path"})
			finding["location"] = copy
		}
		findings = append(findings, finding)
	}
	return findings
}

// Private views never replace Raw or apply presentation caps. Each attested
// child retains its scalar dispositions, which a single aggregate cannot hold.
func clawHubCompleteBundleGateViews(raw json.RawMessage) []json.RawMessage {
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		return nil
	}
	analysis, complete := deriveClawHubCompleteBundleEvidence(raw, record, 0)
	if !complete {
		return nil
	}
	// Parse the gate projection independently so arbitrary native numeric fields
	// retain their exact JSON value instead of passing through float64.
	var nativeRecord map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&nativeRecord) != nil {
		return nil
	}
	record = nativeRecord
	findings := []any{}
	childViews := []json.RawMessage{}
	for _, value := range record["bundled_reports"].([]any) {
		entry := asStringMap(value)
		child := asStringMap(entry["report"])
		// Preserve native child aliases and scalar fields before adding rooted
		// finding projections. Neither view may hide a match in the other.
		nativeView, err := json.Marshal(child)
		if err != nil {
			return nil
		}
		childViews = append(childViews, nativeView)
		childFindings := clawHubBundleChildGateFindings(entry["rootPath"].(string), child)
		findings = append(findings, childFindings...)
		childView := make(map[string]any, len(child))
		for key, value := range child {
			childView[key] = value
		}
		for _, key := range []string{"filtered_findings", "findings", "issues"} {
			childView[key] = childFindings
		}
		view, err := json.Marshal(childView)
		if err != nil {
			return nil
		}
		childViews = append(childViews, view)
	}
	record["status"] = analysis.Status
	record["issue_count"] = analysis.IssueCount
	for _, key := range []string{"filtered_findings", "findings", "issues"} {
		record[key] = findings
	}
	record["risk_assessment"] = map[string]any{"score": analysis.Score, "severity": analysis.Severity, "recommendation": analysis.Recommendation}
	view, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	return append([]json.RawMessage{view}, childViews...)
}

func evaluateClawHubCompleteBundleGateRules(artifact *Artifact, scanner string, raw json.RawMessage, rules []JSONGateRule) {
	// Keep every existing raw-evidence match, then let child-derived evidence
	// trigger remaining rules. Each configured rule is recorded at most once.
	start := len(artifact.GateRules)
	evaluateJSONGateRules(artifact, scanner, raw, rules)
	views := clawHubCompleteBundleGateViews(raw)
	matched := map[string]bool{}
	for _, fired := range artifact.GateRules[start:] {
		matched[fired.Rule] = true
	}
	for _, view := range views {
		remaining := make([]JSONGateRule, 0, len(rules))
		for _, rule := range rules {
			if !matched[rule.ID] {
				remaining = append(remaining, rule)
			}
		}
		if len(remaining) == 0 {
			return
		}
		before := len(artifact.GateRules)
		evaluateJSONGateRules(artifact, scanner, view, remaining)
		for _, fired := range artifact.GateRules[before:] {
			matched[fired.Rule] = true
		}
	}
}
