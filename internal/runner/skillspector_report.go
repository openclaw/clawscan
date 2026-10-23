package runner

import (
	"encoding/json"
	"strings"
)

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
	if message := skillSpectorReportError(record); message != "" {
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
