package runner

import "strings"

func skillSpectorCaveatTelemetryKnown(metadata map[string]any) bool {
	usage, ok := metadata["inference_usage"].([]any)
	if !ok {
		return false
	}
	for _, value := range usage {
		record, ok := value.(map[string]any)
		if !ok || !skillSpectorKnownFields(record, "node request_kind provider model model_source usage_source prompt_tokens completion_tokens cached_tokens cache_write_tokens reasoning_tokens total_tokens") || record["usage_source"] != "provider_response" || (record["model_source"] != "requested_model" && record["model_source"] != "provider_response") {
			return false
		}
		for _, field := range []string{"node", "request_kind", "provider", "model"} {
			if label, valid := record[field].(string); !valid || strings.TrimSpace(label) == "" || len(label) > 256 {
				return false
			}
		}
		found := false
		for _, field := range []string{"prompt_tokens", "completion_tokens", "cached_tokens", "cache_write_tokens", "reasoning_tokens", "total_tokens"} {
			value, exists := record[field]
			if !exists {
				continue
			}
			count, valid := value.(float64)
			if !valid || count < 0 || count > 1<<53-1 || count != float64(int64(count)) {
				return false
			}
			found = true
		}
		if !found {
			return false
		}
	}
	if !skillSpectorMetadataShape(metadata["llm_provenance"], skillSpectorProvenanceShape) {
		return false
	}
	provenance := metadata["llm_provenance"].(map[string]any)
	switch provenance["determinism"].(map[string]any)["control_status"] {
	case "invalid_configuration", "configuration_unknown", "controls_not_observed", "provider_defaults", "best_effort_controls_forwarded", "controls_partially_forwarded":
	default:
		return false
	}
	remaining := make(map[string]bool)
	for _, analyzer := range strings.Fields("mcp_tool_poisoning semantic_developer_intent semantic_quality_policy semantic_security_discovery meta_analyzer") {
		remaining[analyzer] = true
	}
	for _, value := range provenance["analyzers"].([]any) {
		identifier := value.(map[string]any)["analyzer_id"].(string)
		if !remaining[identifier] {
			return false
		}
		delete(remaining, identifier)
	}
	return len(remaining) == 0
}

var skillSpectorProvenanceShape = map[string]any{
	"schema_version": float64(1),
	"provider": map[string]any{
		"configured_adapter": "text", "resolved_adapter": "text", "effective_adapter": "text",
		"effective_adapters": []any{"text"}, "service": "unknown",
		"routing": map[string]any{
			"deployment_override": "nullable_text", "deployment_source": "text",
			"api_version": "nullable_text", "api_version_source": "text",
		},
	},
	"analyzers": []any{map[string]any{
		"analyzer_id": "text", "model": "text", "model_source": "resolved_configuration",
		"analyzer_revision": map[string]any{
			"value": "text", "source": "skillspector_package",
			"source_revision": map[string]any{"value": "text", "source": "text"},
		},
	}},
	"sampling": map[string]any{
		"temperature":      skillSpectorSamplingShape("nullable_number"),
		"seed":             skillSpectorSamplingShape("nullable_number"),
		"reasoning_effort": skillSpectorSamplingShape("nullable_text"),
	},
	"determinism": map[string]any{
		"classification": "nondeterministic", "control_status": "text", "provider_guarantee": false, "reason": "text",
	},
}

func skillSpectorSamplingShape(setting string) map[string]any {
	return map[string]any{
		"requested": setting, "source": "text", "forwarded_to_client": setting,
		"adapter_support": "boolean", "provider_support": "unknown",
	}
}

func skillSpectorMetadataShape(value, shape any) bool {
	switch expected := shape.(type) {
	case map[string]any:
		record, ok := value.(map[string]any)
		if !ok || len(record) != len(expected) {
			return false
		}
		for field, child := range expected {
			value, exists := record[field]
			if !exists || !skillSpectorMetadataShape(value, child) {
				return false
			}
		}
		return true
	case []any:
		records, ok := value.([]any)
		if !ok {
			return false
		}
		for _, record := range records {
			if !skillSpectorMetadataShape(record, expected[0]) {
				return false
			}
		}
		return true
	case string:
		switch expected {
		case "nullable_text", "text":
			text, valid := value.(string)
			return (value == nil && expected == "nullable_text") || (valid && strings.TrimSpace(text) != "")
		case "nullable_number":
			_, valid := value.(float64)
			return value == nil || valid
		case "boolean":
			_, valid := value.(bool)
			return valid
		default:
			return value == expected
		}
	default:
		return value == expected
	}
}
