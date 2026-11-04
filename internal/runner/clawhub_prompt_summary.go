package runner

import (
	"encoding/json"
	"fmt"
	"sort"
)

// SkillSpector accounting lists carry one row per excluded, partially
// inspected, or referenced file, so they grow with package size. The judge
// workspace keeps the complete raw report at scanners/skillspector.json; the
// prompt carries counts plus a bounded, deterministic sample instead. Any
// input limit belongs to the judge command, not to ClawScan.
var clawHubCompletenessRecordLists = []struct {
	field   string
	groupBy string
}{
	{field: "ledger_exceptions", groupBy: "reason_code"},
	{field: "scope_exclusions", groupBy: "reason_code"},
	{field: "references", groupBy: "status"},
}

const (
	maxClawHubCompletenessSamplePerGroup = 3
	maxClawHubCompletenessSampleEntries  = 24
	maxClawHubCompletenessSampleChars    = 12_000
	maxClawHubCompletenessCountGroups    = 32
	maxClawHubCompletenessGroupKeyChars  = 128
	maxClawHubCompletenessEntryFields    = 16
	maxClawHubCompletenessEntryListItems = 16
	maxClawHubCompletenessEntryItemChars = 128
	clawHubCompletenessUngroupedKey      = "(none)"
	clawHubSkillSpectorWorkspaceReport   = "scanners/skillspector.json"
)

func summarizeClawHubAnalysisCompleteness(completeness map[string]any) map[string]any {
	if completeness == nil {
		return nil
	}
	summarized := make(map[string]any, len(completeness))
	for key, value := range completeness {
		summarized[key] = value
	}
	for _, list := range clawHubCompletenessRecordLists {
		if value, ok := completeness[list.field]; ok && value != nil {
			summarized[list.field] = summarizeClawHubCompletenessRecords(list.field, list.groupBy, value)
		}
	}
	return summarized
}

type clawHubCompletenessGroup struct {
	key  string
	rows []any
}

func summarizeClawHubCompletenessRecords(field string, groupBy string, value any) map[string]any {
	location := fmt.Sprintf("analysis_completeness.%s in %s", field, clawHubSkillSpectorWorkspaceReport)
	rows, ok := value.([]any)
	if !ok {
		return map[string]any{
			"summarized":      true,
			"unexpected_type": judgeJSONType(value),
			"note":            "Omitted from the prompt; read " + location + " in the judge workspace.",
		}
	}
	groups := map[string]*clawHubCompletenessGroup{}
	for _, row := range rows {
		key := clawHubCompletenessUngroupedKey
		if record := asStringMap(row); record != nil {
			if value := readMapString(record, groupBy); value != "" {
				key = truncateClawHubText(value, maxClawHubCompletenessGroupKeyChars)
			}
		}
		group := groups[key]
		if group == nil {
			group = &clawHubCompletenessGroup{key: key}
			groups[key] = group
		}
		group.rows = append(group.rows, row)
	}
	ordered := make([]*clawHubCompletenessGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].rows) != len(ordered[j].rows) {
			return len(ordered[i].rows) > len(ordered[j].rows)
		}
		return ordered[i].key < ordered[j].key
	})

	counts := map[string]int{}
	otherGroups, otherEntries := 0, 0
	for index, group := range ordered {
		if index < maxClawHubCompletenessCountGroups {
			counts[group.key] = len(group.rows)
		} else {
			otherGroups++
			otherEntries += len(group.rows)
		}
	}

	sample := []any{}
	sampleChars := 0
sampling:
	for _, group := range ordered {
		taken := 0
		for _, row := range group.rows {
			if taken >= maxClawHubCompletenessSamplePerGroup {
				break
			}
			if len(sample) >= maxClawHubCompletenessSampleEntries {
				break sampling
			}
			entry := boundedClawHubCompletenessEntry(row)
			encoded, err := json.Marshal(entry)
			if err != nil || sampleChars+len(encoded) > maxClawHubCompletenessSampleChars {
				continue
			}
			sample = append(sample, entry)
			sampleChars += len(encoded)
			taken++
		}
	}

	summary := map[string]any{
		"summarized":           true,
		"total":                len(rows),
		"counts_by_" + groupBy: counts,
		"sample":               sample,
		"sample_omitted":       len(rows) - len(sample),
		"note": fmt.Sprintf(
			"Summarized for the prompt: counts by %s plus up to %d sample entries per %s. Read %s in the judge workspace for every entry.",
			groupBy, maxClawHubCompletenessSamplePerGroup, groupBy, location,
		),
	}
	if otherGroups > 0 {
		summary["other_"+groupBy+"_groups"] = otherGroups
		summary["other_"+groupBy+"_entries"] = otherEntries
	}
	return summary
}

func boundedClawHubCompletenessEntry(value any) any {
	record := asStringMap(value)
	if record == nil {
		return boundedClawHubCompletenessScalar(value, maxClawHubSkillSpectorShortTextChars)
	}
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	bounded := map[string]any{}
	for index, key := range keys {
		if index >= maxClawHubCompletenessEntryFields {
			bounded["_omitted_fields"] = len(keys) - maxClawHubCompletenessEntryFields
			break
		}
		field := truncateClawHubText(key, maxClawHubCompletenessGroupKeyChars)
		switch typed := record[key].(type) {
		case []any:
			items := make([]any, 0, min(len(typed), maxClawHubCompletenessEntryListItems))
			for _, item := range typed[:min(len(typed), maxClawHubCompletenessEntryListItems)] {
				items = append(items, boundedClawHubCompletenessScalar(item, maxClawHubCompletenessEntryItemChars))
			}
			bounded[field] = items
			if omitted := len(typed) - len(items); omitted > 0 {
				bounded["_omitted_"+field] = omitted
			}
		default:
			bounded[field] = boundedClawHubCompletenessScalar(typed, maxClawHubSkillSpectorShortTextChars)
		}
	}
	return bounded
}

func boundedClawHubCompletenessScalar(value any, maxChars int) any {
	switch typed := value.(type) {
	case string:
		return truncateClawHubText(typed, maxChars)
	case float64, bool, nil:
		return typed
	default:
		return "[nested " + judgeJSONType(typed) + " omitted; see " + clawHubSkillSpectorWorkspaceReport + "]"
	}
}
