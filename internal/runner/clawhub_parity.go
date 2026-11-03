package runner

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	maxClawHubSkillSpectorIssues         = 25
	maxClawHubSkillSpectorTextChars      = 2_000
	maxClawHubSkillSpectorShortTextChars = 512
	maxClawHubSkillSpectorCaveats        = 10
	maxClawHubSkillSpectorTags           = 8
)

type clawHubContext struct {
	TargetKind            string          `json:"targetKind"`
	Source                string          `json:"source"`
	HasMaliciousSignal    *bool           `json:"hasMaliciousSignal"`
	TrustedOpenClawPlugin bool            `json:"trustedOpenClawPlugin"`
	InjectionSignals      []string        `json:"injectionSignals"`
	SkillSpectorCheckedAt *int64          `json:"skillSpectorCheckedAt"`
	Metadata              json.RawMessage `json:"metadata"`
}

type clawHubNormalizedSkillSpectorAnalysis struct {
	Status               string                     `json:"status"`
	Score                *float64                   `json:"score,omitempty"`
	Severity             string                     `json:"severity,omitempty"`
	Recommendation       string                     `json:"recommendation,omitempty"`
	IssueCount           int                        `json:"issueCount"`
	Issues               []clawHubSkillSpectorIssue `json:"issues"`
	ScannerVersion       string                     `json:"scannerVersion,omitempty"`
	Summary              string                     `json:"summary,omitempty"`
	Error                string                     `json:"error,omitempty"`
	CheckedAt            int64                      `json:"checkedAt"`
	AnalysisCompleteness map[string]any             `json:"analysisCompleteness,omitempty"`
	InspectionCaveats    *clawHubInspectionCaveats  `json:"inspectionCaveats,omitempty"`
}

type clawHubInspectionCaveats struct {
	Status           string           `json:"status"`
	ReferenceCount   int              `json:"referenceCount"`
	References       []map[string]any `json:"references"`
	ExceptionCount   int              `json:"exceptionCount"`
	LedgerExceptions []map[string]any `json:"ledgerExceptions"`
}

type clawHubSkillSpectorIssue struct {
	IssueID          string   `json:"issueId"`
	Category         string   `json:"category,omitempty"`
	Pattern          string   `json:"pattern,omitempty"`
	Severity         string   `json:"severity"`
	Confidence       *float64 `json:"confidence,omitempty"`
	File             string   `json:"file,omitempty"`
	StartLine        *float64 `json:"startLine,omitempty"`
	EndLine          *float64 `json:"endLine,omitempty"`
	Explanation      string   `json:"explanation"`
	Remediation      string   `json:"remediation,omitempty"`
	Finding          string   `json:"finding,omitempty"`
	CodeSnippet      string   `json:"codeSnippet,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	ReviewOutcome    string   `json:"reviewOutcome,omitempty"`
	ReviewConfidence *float64 `json:"reviewConfidence,omitempty"`
}

func parseClawHubContext(raw json.RawMessage) (clawHubContext, error) {
	if len(raw) == 0 {
		return clawHubContext{}, nil
	}
	var context clawHubContext
	if err := json.Unmarshal(raw, &context); err != nil {
		return clawHubContext{}, fmt.Errorf("parse clawhub run context: %w", err)
	}
	return context, nil
}

func clawHubSkillSpectorAnalysis(artifact Artifact, checkedAtOverride *int64) (any, error) {
	result, ok := artifact.Scanners["skillspector"]
	if !ok || len(result.Raw) == 0 {
		return nil, nil
	}
	checkedAt := time.Now().UnixMilli()
	if completedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt); err == nil {
		checkedAt = completedAt.UnixMilli()
	}
	if checkedAtOverride != nil {
		checkedAt = *checkedAtOverride
	}
	normalized, err := normalizeClawHubSkillSpector(result.Raw, checkedAt)
	if result.Status == "failed" {
		normalized.Status = "error"
		normalized.Error = "SkillSpector command did not complete successfully."
	} else if usablePartialScanner(artifact.Profile, "skillspector", result) {
		normalized.Status = "partial"
		normalized.Error = ""
	}
	return normalized, err
}

func normalizeClawHubSkillSpector(raw json.RawMessage, checkedAt int64) (clawHubNormalizedSkillSpectorAnalysis, error) {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return clawHubNormalizedSkillSpectorAnalysis{}, fmt.Errorf("parse SkillSpector JSON: %w", err)
	}
	record := asStringMap(parsed)
	if record == nil {
		return clawHubNormalizedSkillSpectorAnalysis{
			Status:     "error",
			IssueCount: 0,
			Issues:     []clawHubSkillSpectorIssue{},
			Error:      "SkillSpector returned a non-object JSON report.",
			CheckedAt:  checkedAt,
		}, nil
	}
	if analysis, completeBundle := deriveClawHubCompleteBundleEvidence(raw, record, checkedAt); completeBundle {
		if len(analysis.Issues) > maxClawHubSkillSpectorIssues {
			analysis.Issues = analysis.Issues[:maxClawHubSkillSpectorIssues]
		}
		return analysis, nil
	}
	rawIssues := readMapValue(record, "filtered_findings", "filteredFindings", "findings", "issues", "vulnerabilities")
	issueValues, _ := rawIssues.([]any)
	issueCount := len(issueValues)
	if value := readMapNumber(record, "issue_count", "issueCount", "finding_count", "findingCount"); value != nil {
		issueCount = int(*value)
	}
	issues := make([]clawHubSkillSpectorIssue, 0, min(len(issueValues), maxClawHubSkillSpectorIssues))
	for index, value := range issueValues {
		if len(issues) >= maxClawHubSkillSpectorIssues {
			break
		}
		if issue := normalizeClawHubSkillSpectorIssue(value, index); issue != nil {
			issues = append(issues, *issue)
		}
	}
	score := firstMapNumber(
		readMapNumber(record, "risk_score", "riskScore", "score"),
		readNestedMapNumber(record, []string{"risk_assessment", "riskAssessment"}, "score"),
	)
	severity := firstNonEmpty(
		readMapString(record, "risk_severity", "riskSeverity", "severity"),
		readNestedMapString(record, []string{"risk_assessment", "riskAssessment"}, "severity"),
	)
	recommendation := firstNonEmpty(
		readMapString(record, "risk_recommendation", "riskRecommendation", "recommendation"),
		readNestedMapString(record, []string{"risk_assessment", "riskAssessment"}, "recommendation", "risk_recommendation", "riskRecommendation"),
	)
	scannerVersion := firstNonEmpty(
		readMapString(record, "scanner_version", "scannerVersion", "version"),
		readNestedMapString(record, []string{"metadata"}, "skillspector_version", "skillspectorVersion", "version"),
	)
	status := normalizeClawHubSkillSpectorStatus(readMapString(record, "status"), recommendation, score, issueCount)
	reportError := skillSpectorReportError(record)
	var analysisCompleteness map[string]any
	if reportError != "" {
		status = "error"
		analysisCompleteness = asStringMap(record["analysis_completeness"])
	}
	return clawHubNormalizedSkillSpectorAnalysis{
		Status:               status,
		Score:                score,
		Severity:             severity,
		Recommendation:       recommendation,
		IssueCount:           issueCount,
		Issues:               issues,
		ScannerVersion:       truncateClawHubText(scannerVersion, maxClawHubSkillSpectorShortTextChars),
		Summary:              truncateClawHubText(readMapString(record, "summary", "analysis"), maxClawHubSkillSpectorTextChars),
		Error:                reportError,
		CheckedAt:            checkedAt,
		AnalysisCompleteness: analysisCompleteness,
		InspectionCaveats:    normalizeClawHubReportInspectionCaveats(record),
	}, nil
}

func normalizeClawHubSkillSpectorIssue(value any, index int) *clawHubSkillSpectorIssue {
	record := asStringMap(value)
	if record == nil {
		return nil
	}
	issueID := firstNonEmpty(
		readMapString(record, "rule_id", "ruleId", "issue_id", "issueId", "id", "pattern_id"),
		fmt.Sprintf("skillspector-%d", index+1),
	)
	pattern := readMapString(record, "pattern", "rule_name", "ruleName", "name", "title", "message")
	severity := strings.ToUpper(firstNonEmpty(readMapString(record, "severity", "risk_severity", "level"), "UNKNOWN"))
	explanation := firstNonEmpty(
		readMapString(record, "explanation", "message", "description", "reason", "details"),
		pattern,
		issueID,
	)
	confidence := normalizeClawHubConfidence(readMapNumber(record, "confidence", "score"))
	file := clawHubSkillSpectorFindingFile(record)
	startLine := firstMapNumber(
		readMapNumber(record, "line", "line_number", "lineNumber", "start_line", "startLine"),
		readNestedMapNumber(record, []string{"location"}, "line", "start_line", "startLine"),
	)
	endLine := firstMapNumber(
		readMapNumber(record, "end_line", "endLine"),
		readNestedMapNumber(record, []string{"location"}, "end_line", "endLine"),
	)
	return &clawHubSkillSpectorIssue{
		IssueID:          firstNonEmpty(truncateClawHubText(issueID, maxClawHubSkillSpectorShortTextChars), "skillspector-issue"),
		Category:         truncateClawHubText(readMapString(record, "category", "analyzer", "type"), maxClawHubSkillSpectorShortTextChars),
		Pattern:          truncateClawHubText(pattern, maxClawHubSkillSpectorShortTextChars),
		Severity:         firstNonEmpty(truncateClawHubText(severity, maxClawHubSkillSpectorShortTextChars), "UNKNOWN"),
		Confidence:       confidence,
		File:             truncateClawHubText(file, maxClawHubSkillSpectorShortTextChars),
		StartLine:        startLine,
		EndLine:          endLine,
		Explanation:      firstNonEmpty(truncateClawHubText(explanation, maxClawHubSkillSpectorTextChars), "SkillSpector reported this issue without additional explanation."),
		Remediation:      truncateClawHubText(readMapString(record, "remediation", "recommendation", "fix", "mitigation"), maxClawHubSkillSpectorTextChars),
		Finding:          truncateClawHubText(readMapString(record, "finding", "match", "evidence"), maxClawHubSkillSpectorTextChars),
		CodeSnippet:      truncateClawHubText(readMapString(record, "code_snippet", "codeSnippet", "snippet"), maxClawHubSkillSpectorTextChars),
		Tags:             clawHubSkillSpectorTags(record["tags"]),
		ReviewOutcome:    truncateClawHubText(firstNonEmpty(readMapString(record, "reviewOutcome"), readNestedMapString(record, []string{"evidence"}, "llm_review_outcome")), maxClawHubSkillSpectorShortTextChars),
		ReviewConfidence: normalizeClawHubConfidence(firstMapNumber(readMapNumber(record, "reviewConfidence"), readNestedMapNumber(record, []string{"evidence"}, "llm_review_confidence"))),
	}
}

// Paths carry file identity: display-text whitespace normalization can name a
// different inventoried file. Preserve strings while keeping legacy coercions.
func clawHubSkillSpectorFindingFile(record map[string]any) string {
	readPath := func(source map[string]any, names ...string) string {
		if value, ok := readMapValue(source, names...).(string); ok {
			return value
		}
		return readMapString(source, names...)
	}
	return firstNonEmpty(
		readPath(record, "file", "file_path", "filePath", "path"),
		readPath(asStringMap(record["location"]), "file", "path"),
	)
}

func clawHubSkillSpectorTags(value any) []string {
	values, _ := value.([]any)
	var tags []string
	for _, value := range values {
		if tag, ok := value.(string); ok && strings.TrimSpace(tag) != "" {
			tags = append(tags, truncateClawHubText(strings.TrimSpace(tag), 128))
			if len(tags) == maxClawHubSkillSpectorTags {
				break
			}
		}
	}
	return tags
}

// Keep the bounded summary separate from risk; complete caveats never clear findings.
// Full references and exceptions remain in the immutable raw scanner report.
func normalizeClawHubInspectionCaveats(accounting map[string]any) *clawHubInspectionCaveats {
	if accounting == nil || accounting["status"] != "complete_with_caveats" || accounting["is_complete"] != true {
		return nil
	}
	references, _ := accounting["references"].([]any)
	exceptions, _ := accounting["ledger_exceptions"].([]any)
	result := &clawHubInspectionCaveats{
		Status: "complete_with_caveats", ReferenceCount: len(references), ExceptionCount: len(exceptions),
		References: []map[string]any{}, LedgerExceptions: []map[string]any{},
	}
	for _, value := range references[:min(len(references), maxClawHubSkillSpectorCaveats)] {
		row := asStringMap(value)
		if row == nil {
			continue
		}
		normalized := map[string]any{}
		for key, source := range map[string]string{"sourcePath": "source_path", "evidence": "evidence", "targetPath": "target_path", "status": "status", "disposition": "disposition", "referenceKind": "reference_kind"} {
			if text := readMapString(row, source); text != "" {
				normalized[key] = truncateClawHubText(text, maxClawHubSkillSpectorShortTextChars)
			}
		}
		for _, key := range []string{"line", "column"} {
			if number := readMapNumber(row, key); number != nil {
				normalized[key] = *number
			}
		}
		result.References = append(result.References, normalized)
	}
	for _, value := range exceptions[:min(len(exceptions), maxClawHubSkillSpectorCaveats)] {
		row := asStringMap(value)
		if row == nil {
			continue
		}
		normalized := map[string]any{}
		for key, source := range map[string]string{"phase": "phase", "reasonCode": "reason_code", "path": "path", "message": "message"} {
			if text := readMapString(row, source); text != "" {
				normalized[key] = truncateClawHubText(text, maxClawHubSkillSpectorShortTextChars)
			}
		}
		result.LedgerExceptions = append(result.LedgerExceptions, normalized)
	}
	return result
}

func normalizeClawHubReportInspectionCaveats(record map[string]any) *clawHubInspectionCaveats {
	accounting := asStringMap(record["analysis_completeness"])
	if accounting["status"] != "complete_with_caveats" || accounting["is_complete"] != true {
		return nil
	}
	entries, bundled := record["bundled_reports"].([]any)
	if !bundled {
		return normalizeClawHubInspectionCaveats(accounting)
	}
	references, exceptions := []any{}, []any{}
	for _, value := range entries {
		entry := asStringMap(value)
		root, ok := entry["rootPath"].(string)
		if !ok {
			continue
		}
		child := asStringMap(entry["report"])
		caveats := asStringMap(child["analysis_completeness"])
		if caveats["status"] != "complete_with_caveats" || caveats["is_complete"] != true {
			continue
		}
		for field, paths := range map[string][]string{"references": {"source_path", "target_path"}, "ledger_exceptions": {"path"}} {
			rows, _ := caveats[field].([]any)
			for _, value := range rows {
				row := map[string]any{}
				for key, value := range asStringMap(value) {
					row[key] = value
				}
				for _, key := range paths {
					if path, ok := row[key].(string); ok && path != "" {
						row[key] = root + "/" + path
					}
				}
				if field == "references" {
					references = append(references, row)
				} else {
					exceptions = append(exceptions, row)
				}
			}
		}
	}
	return normalizeClawHubInspectionCaveats(map[string]any{"status": "complete_with_caveats", "is_complete": true, "references": references, "ledger_exceptions": exceptions})
}

func normalizeClawHubSkillSpectorStatus(rawStatus string, recommendation string, score *float64, issueCount int) string {
	switch strings.ToLower(strings.TrimSpace(rawStatus)) {
	case "benign", "safe":
		return "clean"
	case "clean", "suspicious", "malicious", "error", "failed":
		return strings.ToLower(strings.TrimSpace(rawStatus))
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(recommendation)), "safe") {
		return "clean"
	}
	if issueCount > 0 || (score != nil && *score > 20) {
		return "suspicious"
	}
	return "clean"
}

func normalizeClawHubConfidence(value *float64) *float64 {
	if value == nil {
		return nil
	}
	normalized := *value
	if normalized > 1 {
		normalized /= 100
	}
	normalized = max(0, min(1, normalized))
	return &normalized
}

func truncateClawHubText(value string, maxChars int) string {
	if value == "" {
		return value
	}
	units := utf16.Encode([]rune(value))
	if len(units) <= maxChars {
		return value
	}
	return fmt.Sprintf(
		"%s\n...[truncated %d chars]",
		string(utf16.Decode(units[:maxChars])),
		len(units)-maxChars,
	)
}

func asStringMap(value any) map[string]any {
	record, _ := value.(map[string]any)
	return record
}

func readMapValue(record map[string]any, names ...string) any {
	for _, name := range names {
		if value, ok := record[name]; ok && value != nil {
			return value
		}
	}
	return nil
}

func readMapString(record map[string]any, names ...string) string {
	switch value := readMapValue(record, names...).(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func readMapNumber(record map[string]any, names ...string) *float64 {
	switch value := readMapValue(record, names...).(type) {
	case float64:
		if value == value {
			return &value
		}
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(value), "%"), 64)
		if err == nil {
			return &parsed
		}
	}
	return nil
}

func readNestedMapString(record map[string]any, nestedNames []string, names ...string) string {
	nested := asStringMap(readMapValue(record, nestedNames...))
	if nested == nil {
		return ""
	}
	return readMapString(nested, names...)
}

func readNestedMapNumber(record map[string]any, nestedNames []string, names ...string) *float64 {
	nested := asStringMap(readMapValue(record, nestedNames...))
	if nested == nil {
		return nil
	}
	return readMapNumber(nested, names...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstMapNumber(values ...*float64) *float64 {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
