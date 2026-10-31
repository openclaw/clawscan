package runner

import (
	"bytes"
	"encoding/json"
	"strings"
)

type skillSpectorBundledReport struct {
	Applicable     *bool  `json:"applicable"`
	Status         string `json:"status"`
	RiskAssessment *struct {
		Score          *float64 `json:"score"`
		Severity       string   `json:"severity"`
		Recommendation string   `json:"recommendation"`
	} `json:"risk_assessment"`
	IssueCount       *int             `json:"issue_count"`
	FilteredFindings []map[string]any `json:"filtered_findings"`
	Metadata         *struct {
		Version string `json:"skillspector_version"`
	} `json:"metadata"`
	Summary    *string `json:"summary"`
	Error      *string `json:"error"`
	Successful bool    `json:"execution_successful"`
	Accounting struct {
		Successful bool   `json:"execution_successful"`
		Complete   *bool  `json:"is_complete"`
		Status     string `json:"status"`
	} `json:"analysis_completeness"`
	Reports []struct {
		Root   string          `json:"rootPath"`
		Report json.RawMessage `json:"report"`
	} `json:"bundled_reports"`
}

func skillSpectorHasBundle(record map[string]any) bool {
	for key := range record {
		if strings.EqualFold(strings.ReplaceAll(key, "_", ""), "bundledreports") {
			return true
		}
	}
	return false
}

// Bundles retain original reports, not synthetic coverage. Validation is one
// level only: every child must stand on its own and at least one is partial.
func skillSpectorUsableBundledPartial(raw json.RawMessage) bool {
	if !skillSpectorUnambiguousJSON(raw) {
		return false
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil || !skillSpectorKnownFields(record, "applicable status risk_assessment issue_count filtered_findings metadata summary error execution_successful analysis_completeness bundled_reports") {
		return false
	}
	accounting, ok := record["analysis_completeness"].(map[string]any)
	if !ok || !skillSpectorKnownFields(accounting, "execution_successful is_complete status") {
		return false
	}
	var bundle skillSpectorBundledReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&bundle) != nil || !bundle.Successful || !bundle.Accounting.Successful || bundle.Accounting.Complete == nil || *bundle.Accounting.Complete || bundle.Accounting.Status != "partial" || len(bundle.Reports) == 0 || bundle.FilteredFindings == nil {
		return false
	}
	switch bundle.Status {
	case "clean", "suspicious", "malicious", "partial":
	default:
		return false
	}
	if bundle.Applicable != nil && !*bundle.Applicable || bundle.Error != nil && *bundle.Error != "" || bundle.IssueCount != nil && *bundle.IssueCount < 0 {
		return false
	}
	for _, key := range []string{"applicable", "risk_assessment", "issue_count", "metadata", "summary"} {
		if value, exists := record[key]; exists && value == nil {
			return false
		}
	}
	for _, finding := range bundle.FilteredFindings {
		if len(finding) == 0 {
			return false
		}
	}
	roots := make(map[string]bool, len(bundle.Reports))
	partial := false
	entries := record["bundled_reports"].([]any)
	for index, entry := range bundle.Reports {
		fields, ok := entries[index].(map[string]any)
		if !ok || len(fields) != 2 || !skillSpectorKnownFields(fields, "rootPath report") {
			return false
		}
		if !skillSpectorComponentPath(entry.Root) || roots[entry.Root] {
			return false
		}
		roots[entry.Root] = true
		var child map[string]any
		if json.Unmarshal(entry.Report, &child) != nil || len(child) == 0 || skillSpectorHasBundle(child) || !skillSpectorBundledChildIntegrity(child) {
			return false
		}
		if skillSpectorUsablePartial(entry.Report) {
			partial = true
		} else {
			accounting, ok := child["analysis_completeness"].(map[string]any)
			if child["execution_successful"] != true || !ok || accounting["execution_successful"] != true || accounting["is_complete"] != true {
				return false
			}
			if skillSpectorReportError(child) != "" || validateSkillSpectorReport(ScannerResult{Status: "completed", Raw: entry.Report}).Status != "completed" {
				return false
			}
		}
	}
	return partial
}

// Bundled children must contain typed findings and cannot conceal errors, fatal
// exceptions or case-conflicting control fields behind a display summary.
func skillSpectorBundledChildIntegrity(child map[string]any) bool {
	issues, ok := readMapValue(child, "filtered_findings", "filteredFindings", "findings", "issues", "vulnerabilities").([]any)
	if !ok {
		return false
	}
	for _, value := range issues {
		if issue, ok := value.(map[string]any); !ok || len(issue) == 0 {
			return false
		}
	}
	if value, exists := child["metadata"]; exists {
		if _, ok := value.(map[string]any); !ok {
			return false
		}
	}
	if value, exists := child["components"]; exists {
		components, ok := value.([]any)
		if !ok {
			return false
		}
		for _, value := range components {
			component, ok := value.(map[string]any)
			if !ok {
				return false
			}
			name, _ := component["path"].(string)
			kind, _ := component["type"].(string)
			if !skillSpectorComponentPath(name) || kind == "" {
				return false
			}
		}
	}
	records := []map[string]any{child}
	for _, key := range []string{"analysis_completeness", "analysisCompleteness"} {
		if value, exists := child[key]; exists {
			accounting, ok := value.(map[string]any)
			if !ok {
				return false
			}
			encoded, err := json.Marshal(accounting)
			var typed skillSpectorCaveatAccounting
			if err != nil || json.Unmarshal(encoded, &typed) != nil {
				return false
			}
			records = append(records, accounting)
			if value, exists := accounting["ledger_exceptions"]; exists {
				exceptions, ok := value.([]any)
				if !ok {
					return false
				}
				for _, value := range exceptions {
					exception, ok := value.(map[string]any)
					if !ok || exception["fatal"] != false {
						return false
					}
					for key := range exception {
						if key != "fatal" && strings.EqualFold(key, "fatal") {
							return false
						}
					}
				}
			}
		}
	}
	for _, current := range records {
		for key := range current {
			for _, canonical := range []string{"execution_successful", "executionSuccessful", "is_complete", "isComplete", "analysis_completeness", "analysisCompleteness", "status", "error"} {
				if key != canonical && strings.EqualFold(key, canonical) {
					return false
				}
			}
		}
		if value, exists := current["error"]; exists && value != nil && value != "" {
			return false
		}
		if value, exists := current["status"]; exists {
			if _, ok := value.(string); !ok {
				return false
			}
		}
	}
	return true
}
