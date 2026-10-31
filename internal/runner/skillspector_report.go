package runner

import (
	"encoding/json"
	"strings"
)

const judgeGapsReportPolicy = "judge-gaps"

func validateSkillSpectorReportForProfile(result ScannerResult, profile string) ScannerResult {
	if isClawHubParityProfile(profile) && result.Status == "completed" {
		var record map[string]any
		if json.Unmarshal(result.Raw, &record) != nil || len(record) == 0 {
			result.Status = "failed"
			result.Error = "SkillSpector report must be a nonempty JSON object."
			return result
		}
		if skillSpectorHasBundle(record) {
			if (result.ExitCode == nil || *result.ExitCode == 0 || *result.ExitCode == 1) && skillSpectorUsableBundledPartial(result.Raw) {
				result.Status, result.ReportPolicy = "partial", judgeGapsReportPolicy
				result.Error = ""
			} else {
				result.Status = "failed"
				result.Error = "SkillSpector bundled report contains unusable or ambiguous child evidence."
			}
			return result
		}
	}
	if isClawHubParityProfile(profile) && result.Status == "completed" &&
		(result.ExitCode == nil || *result.ExitCode == 0 || *result.ExitCode == 1) &&
		skillSpectorUsablePartial(result.Raw) {
		result.Status = "partial"
		result.ReportPolicy = judgeGapsReportPolicy
		result.Error = ""
		return result
	}
	return validateSkillSpectorReport(result)
}

// Partial evidence is usable for independent adjudication, not a claim that
// scanner coverage completed. Validate the report envelope without imposing a
// coverage threshold or requiring every analyzer to succeed.
func skillSpectorUsablePartial(raw json.RawMessage) bool {
	if !skillSpectorUnambiguousJSON(raw) {
		return false
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil || record["execution_successful"] != true {
		return false
	}
	accounting, ok := record["analysis_completeness"].(map[string]any)
	if !ok || accounting["execution_successful"] != true || accounting["is_complete"] != false || accounting["status"] != "partial" {
		return false
	}
	metadata, ok := record["metadata"].(map[string]any)
	if !ok {
		return false
	}
	version, _ := metadata["skillspector_version"].(string)
	if strings.TrimSpace(version) == "" {
		return false
	}
	encoded, err := json.Marshal(accounting)
	var typed skillSpectorCaveatAccounting
	if err != nil || json.Unmarshal(encoded, &typed) != nil {
		return false
	}
	if typed.Coverage == nil || *typed.Coverage < 0 || *typed.Coverage > 100 {
		return false
	}
	for _, current := range []map[string]any{record, accounting} {
		for key := range current {
			for _, canonical := range []string{"execution_successful", "is_complete", "analysis_completeness", "status", "error"} {
				if key != canonical && strings.EqualFold(key, canonical) {
					return false
				}
			}
		}
		for _, alias := range []string{"executionSuccessful", "isComplete", "analysisCompleteness"} {
			if _, exists := current[alias]; exists {
				return false
			}
		}
		if value, exists := current["error"]; exists && value != "" && value != nil {
			return false
		}
	}
	if value, exists := record["is_complete"]; exists && value != false {
		return false
	}
	if status, exists := record["status"]; exists && status != "partial" {
		return false
	}
	components, ok := record["components"].([]any)
	if !ok || len(components) == 0 {
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
	issues, ok := record["issues"].([]any)
	if !ok {
		return false
	}
	for _, value := range issues {
		if issue, ok := value.(map[string]any); !ok || len(issue) == 0 {
			return false
		}
	}
	var counts [4]int
	for i, field := range []string{"total_components", "fully_inspected_files", "partially_inspected_files", "entirely_uninspected_files"} {
		count, ok := skillSpectorReportCount(accounting[field])
		if !ok {
			return false
		}
		counts[i] = count
	}
	if counts[0] == 0 || counts[1] > counts[0] || counts[2] > counts[0]-counts[1] || counts[3] != counts[0]-counts[1]-counts[2] {
		return false
	}
	// These are evidence records, not coverage gates. A fatal exception still
	// contradicts successful execution and cannot qualify as usable output.
	for _, field := range []string{"ledger_exceptions", "analyzer_statuses"} {
		rows, ok := accounting[field].([]any)
		if !ok {
			return false
		}
		for _, value := range rows {
			row, ok := value.(map[string]any)
			if !ok || len(row) == 0 {
				return false
			}
			if field == "ledger_exceptions" {
				if row["fatal"] != false {
					return false
				}
				for key := range row {
					if key != "fatal" && strings.EqualFold(key, "fatal") {
						return false
					}
				}
			}
		}
	}
	return true
}

func usablePartialScanner(profile, scanner string, result ScannerResult) bool {
	return isClawHubParityProfile(profile) && scanner == "skillspector" &&
		result.Status == "partial" && result.ReportPolicy == judgeGapsReportPolicy
}

func validateSkillSpectorReport(result ScannerResult) ScannerResult {
	if result.Status != "completed" || len(result.Raw) == 0 {
		return result
	}
	if result.ExitCode != nil && *result.ExitCode > 1 {
		result.Status = "failed"
		if result.Error == "" {
			result.Error = "SkillSpector command did not complete successfully."
		}
		return result
	}
	var record map[string]any
	if err := json.Unmarshal(result.Raw, &record); err != nil || record == nil {
		result.Status = "failed"
		result.Error = "SkillSpector report must be a JSON object."
		return result
	}
	if message := skillSpectorReportError(record); message != "" && (!skillSpectorReferenceCaveatsOnly(record) || !skillSpectorUnambiguousJSON(result.Raw)) {
		result.Status = "failed"
		if result.Error == "" {
			result.Error = message
		}
	}
	return result
}

func skillSpectorReportError(record map[string]any) string {
	const message = "SkillSpector report declares incomplete or unsuccessful inspection."
	records := []map[string]any{record}
	for _, key := range []string{"analysis_completeness", "analysisCompleteness"} {
		if value, exists := record[key]; exists {
			completeness, ok := value.(map[string]any)
			if !ok {
				return message
			}
			records = append(records, completeness)
		}
	}
	for _, current := range records {
		if value, ok := current["error"].(string); ok && strings.TrimSpace(value) != "" {
			return message
		}
		for _, key := range []string{"execution_successful", "executionSuccessful", "is_complete", "isComplete"} {
			if value, exists := current[key]; exists && value != true {
				return message
			}
		}
		if status, ok := current["status"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "failed", "error", "partial", "incomplete":
				return message
			}
		}
	}
	return ""
}
