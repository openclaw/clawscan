package runner

import (
	"encoding/json"
	"path"
	"strings"
)

const skillSpectorStaticPatternAnalyzers = "static_patterns_agent_snooping static_patterns_anti_refusal static_patterns_data_exfiltration static_patterns_deserialization static_patterns_excessive_agency static_patterns_harmful_content static_patterns_memory_poisoning static_patterns_output_handling static_patterns_privilege_escalation static_patterns_prompt_injection static_patterns_rogue_agent static_patterns_ssrf static_patterns_supply_chain static_patterns_system_prompt_leakage static_patterns_tool_misuse"

type skillSpectorComponentScopes struct {
	inventory, coverage, staticPatterns, semantic int
	lines                                         map[string]int
}

// The pinned source inventories ZIP containers and their local-only members,
// but coverage excludes containers and external models receive neither. Passive
// binary exclusions omit static-pattern/semantic work, while integrity and YARA
// still inspect every inventoried component. Keep those denominators distinct.
func skillSpectorCaveatComponentScopes(components []any, exclusions []json.RawMessage) (skillSpectorComponentScopes, bool) {
	scopes := skillSpectorComponentScopes{inventory: len(components), lines: make(map[string]int, len(components))}
	records := make(map[string]map[string]any, len(components))
	for _, value := range components {
		component, ok := value.(map[string]any)
		if !ok || !skillSpectorKnownFields(component, "path type lines executable size_bytes source_url source_identity source_digest outer_path nested_path container_type container_depth container_ancestry passive_binary") {
			return scopes, false
		}
		if component["source_url"] != nil || component["source_identity"] != nil || component["source_digest"] != nil {
			return scopes, false
		}
		kind, kindOK := component["type"].(string)
		executable, executableOK := component["executable"].(bool)
		name, _ := component["path"].(string)
		lineCount, linesOK := skillSpectorReportCount(component["lines"])
		_, sizeOK := skillSpectorReportCount(component["size_bytes"])
		if !kindOK || kind == "" || !executableOK || !skillSpectorComponentPath(name) || !linesOK || !sizeOK {
			return scopes, false
		}
		if _, duplicate := records[name]; duplicate {
			return scopes, false
		}
		if kind == "zip" && (executable || lineCount != 0) {
			return scopes, false
		}
		records[name] = component
		scopes.lines[name] = lineCount
	}
	for name, component := range records {
		nested := strings.Contains(name, "!/")
		if nested {
			outer, outerOK := component["outer_path"].(string)
			member, memberOK := component["nested_path"].(string)
			ancestry, ancestryOK := component["container_ancestry"].([]any)
			parent, parentOK := records[outer]
			// This compatibility contract covers the observed, single ZIP boundary.
			// Deeper or ambiguous provenance continues to require explicit support.
			if !outerOK || !memberOK || !parentOK || parent["type"] != "zip" ||
				strings.Contains(outer, "!/") || !skillSpectorComponentPath(member) ||
				strings.Contains(member, "!/") || name != outer+"!/"+member ||
				component["container_type"] != "zip" || component["container_depth"] != float64(1) ||
				!ancestryOK || len(ancestry) != 1 || ancestry[0] != "zip" {
				return scopes, false
			}
		} else {
			for _, field := range strings.Fields("outer_path nested_path container_type container_depth container_ancestry") {
				if _, exists := component[field]; exists {
					return scopes, false
				}
			}
		}
	}
	excluded, valid := skillSpectorPassiveBinaryExclusions(records, exclusions)
	if !valid {
		return scopes, false
	}
	for name, component := range records {
		if _, hasEvidence := component["passive_binary"]; hasEvidence && (!excluded[name] || !skillSpectorPassiveWave(component)) {
			return scopes, false
		}
		if excluded[name] {
			delete(scopes.lines, name)
			continue
		}
		scopes.staticPatterns++
		if component["type"] == "zip" {
			delete(scopes.lines, name)
			continue
		}
		scopes.coverage++
		hidden := false
		for _, segment := range strings.Split(name, "/") {
			if strings.HasPrefix(segment, ".") {
				hidden = true
				break
			}
		}
		if !hidden && !strings.Contains(name, "!/") {
			scopes.semantic++
		}
	}
	return scopes, true
}

func skillSpectorComponentPath(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.HasPrefix(name, "../") && !path.IsAbs(name) && path.Clean(name) == name && !strings.Contains(name, "\\") && !strings.ContainsRune(name, 0)
}

func skillSpectorPassiveBinaryExclusions(components map[string]map[string]any, exclusions []json.RawMessage) (map[string]bool, bool) {
	excluded := make(map[string]bool, len(exclusions))
	if len(exclusions) > len(components) {
		return excluded, false
	}
	for _, raw := range exclusions {
		var row map[string]any
		if json.Unmarshal(raw, &row) != nil || len(row) != 9 ||
			!skillSpectorKnownFields(row, "outcome phase reason_code message path start_line end_line fatal analyzers") ||
			row["outcome"] != "out_of_scope" || row["phase"] != "static" ||
			row["reason_code"] != "binary_content" ||
			row["message"] != "Binary content is unsupported by this analyzer." ||
			row["start_line"] != nil || row["end_line"] != nil || row["fatal"] != false {
			return excluded, false
		}
		name, _ := row["path"].(string)
		component, exists := components[name]
		if !exists || excluded[name] || strings.Contains(name, "!/") || component["type"] != "other" || component["executable"] != false || component["size_bytes"] == float64(0) {
			return excluded, false
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico":
		case ".wav":
			if !skillSpectorPassiveWave(component) {
				return excluded, false
			}
		default:
			return excluded, false
		}
		analyzers, ok := row["analyzers"].([]any)
		remaining := make(map[string]bool)
		for _, id := range strings.Fields(skillSpectorStaticPatternAnalyzers) {
			remaining[id] = true
		}
		if !ok || len(analyzers) != len(remaining) {
			return excluded, false
		}
		for _, value := range analyzers {
			id, ok := value.(string)
			if !ok || !remaining[id] {
				return excluded, false
			}
			delete(remaining, id)
		}
		if len(remaining) != 0 {
			return excluded, false
		}
		excluded[name] = true
	}
	return excluded, true
}
