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
	// Large partial plugin scans can record thousands of ledger exceptions.
	// The judge workspace keeps the complete raw report, so the prompt carries
	// only a bounded sample per list plus totals and reason counts.
	maxClawHubCompletenessRows = 25
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
}

type clawHubSkillSpectorIssue struct {
	IssueID     string   `json:"issueId"`
	Category    string   `json:"category,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Severity    string   `json:"severity"`
	Confidence  *float64 `json:"confidence,omitempty"`
	File        string   `json:"file,omitempty"`
	StartLine   *float64 `json:"startLine,omitempty"`
	EndLine     *float64 `json:"endLine,omitempty"`
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation,omitempty"`
	Finding     string   `json:"finding,omitempty"`
	CodeSnippet string   `json:"codeSnippet,omitempty"`
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
		analysisCompleteness = boundClawHubAnalysisCompleteness(asStringMap(record["analysis_completeness"]))
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
	}, nil
}

// boundClawHubAnalysisCompleteness keeps scalar coverage fields verbatim and
// samples long lists. Ledger exceptions are sampled round-robin by reason code
// so rare reasons stay visible next to bulk exclusions; every list reports its
// total, and the ledger reports its full reason distribution.
func boundClawHubAnalysisCompleteness(completeness map[string]any) map[string]any {
	if completeness == nil {
		return nil
	}
	bounded := make(map[string]any, len(completeness))
	var omitted map[string]any
	for key, value := range completeness {
		rows, ok := value.([]any)
		if !ok || len(rows) <= maxClawHubCompletenessRows {
			bounded[key] = value
			continue
		}
		if key == "ledger_exceptions" {
			bounded[key], bounded["ledger_exception_reason_counts"] = sampleClawHubLedgerExceptions(rows)
		} else {
			bounded[key] = rows[:maxClawHubCompletenessRows]
		}
		if omitted == nil {
			omitted = map[string]any{}
		}
		omitted[key] = map[string]int{"total": len(rows), "omitted": len(rows) - maxClawHubCompletenessRows}
	}
	if omitted != nil {
		bounded["prompt_truncation"] = map[string]any{
			"lists":       omitted,
			"full_report": "skillspector-report-0.json",
		}
	}
	return bounded
}

func sampleClawHubLedgerExceptions(rows []any) ([]any, map[string]int) {
	var reasons []string
	byReason := map[string][]int{}
	for index, value := range rows {
		reason, _ := asStringMap(value)["reason_code"].(string)
		if reason == "" {
			reason = "unknown"
		}
		if byReason[reason] == nil {
			reasons = append(reasons, reason)
		}
		byReason[reason] = append(byReason[reason], index)
	}
	selected := make([]bool, len(rows))
	for taken, depth := 0, 0; taken < maxClawHubCompletenessRows; depth++ {
		for _, reason := range reasons {
			if depth < len(byReason[reason]) && taken < maxClawHubCompletenessRows {
				selected[byReason[reason][depth]] = true
				taken++
			}
		}
	}
	sample := make([]any, 0, maxClawHubCompletenessRows)
	for index, value := range rows {
		if selected[index] {
			sample = append(sample, value)
		}
	}
	counts := make(map[string]int, len(reasons))
	for _, reason := range reasons {
		counts[reason] = len(byReason[reason])
	}
	return sample, counts
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
	file := firstNonEmpty(
		readMapString(record, "file", "file_path", "filePath", "path"),
		readNestedMapString(record, []string{"location"}, "file", "path"),
	)
	startLine := firstMapNumber(
		readMapNumber(record, "line", "line_number", "lineNumber", "start_line", "startLine"),
		readNestedMapNumber(record, []string{"location"}, "line", "start_line", "startLine"),
	)
	endLine := firstMapNumber(
		readMapNumber(record, "end_line", "endLine"),
		readNestedMapNumber(record, []string{"location"}, "end_line", "endLine"),
	)
	return &clawHubSkillSpectorIssue{
		IssueID:     firstNonEmpty(truncateClawHubText(issueID, maxClawHubSkillSpectorShortTextChars), "skillspector-issue"),
		Category:    truncateClawHubText(readMapString(record, "category", "analyzer", "type"), maxClawHubSkillSpectorShortTextChars),
		Pattern:     truncateClawHubText(pattern, maxClawHubSkillSpectorShortTextChars),
		Severity:    firstNonEmpty(truncateClawHubText(severity, maxClawHubSkillSpectorShortTextChars), "UNKNOWN"),
		Confidence:  confidence,
		File:        truncateClawHubText(file, maxClawHubSkillSpectorShortTextChars),
		StartLine:   startLine,
		EndLine:     endLine,
		Explanation: firstNonEmpty(truncateClawHubText(explanation, maxClawHubSkillSpectorTextChars), "SkillSpector reported this issue without additional explanation."),
		Remediation: truncateClawHubText(readMapString(record, "remediation", "recommendation", "fix", "mitigation"), maxClawHubSkillSpectorTextChars),
		Finding:     truncateClawHubText(readMapString(record, "finding", "match", "evidence"), maxClawHubSkillSpectorTextChars),
		CodeSnippet: truncateClawHubText(readMapString(record, "code_snippet", "codeSnippet", "snippet"), maxClawHubSkillSpectorTextChars),
	}
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
