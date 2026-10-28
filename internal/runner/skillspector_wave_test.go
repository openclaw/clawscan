package runner

import (
	"encoding/json"
	"testing"
)

func waveScopeFixture(t *testing.T) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	report := caveatScopeFixture(t, false, true)
	components := report["components"].([]any)
	component := components[len(components)-1].(map[string]any)
	component["path"], component["size_bytes"] = "assets/bark.wav", float64(32678)
	proof := map[string]any{"format": "riff_wave_pcm_v1", "channels": float64(1), "sample_rate": float64(44100), "bits_per_sample": float64(16), "block_align": float64(2), "byte_rate": float64(88200), "data_bytes": float64(32634), "frames": float64(16317), "container_bytes": float64(32678)}
	component["passive_binary"] = proof
	exclusion := report["analysis_completeness"].(map[string]any)["scope_exclusions"].([]any)[0].(map[string]any)
	exclusion["path"] = component["path"]
	return report, component, proof
}

func TestSkillSpectorNativePCMExclusion(t *testing.T) {
	report, _, _ := waveScopeFixture(t)
	checkCaveatScope(t, report, true)
	// The original payload stays binary-excluded; it is never text-inspected.
	raw, _ := json.Marshal(report["analysis_completeness"].(map[string]any)["scope_exclusions"])
	var exclusions []json.RawMessage
	if err := json.Unmarshal(raw, &exclusions); err != nil {
		t.Fatal(err)
	}
	scopes, ok := skillSpectorCaveatComponentScopes(report["components"].([]any), exclusions)
	if !ok || scopes.inventory != 3 || scopes.coverage != 2 || scopes.staticPatterns != 2 || scopes.semantic != 2 {
		t.Fatalf("scope=%+v ok=%v", scopes, ok)
	}
}

func TestSkillSpectorNativePCMRejectsUnprovedClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any, map[string]any, map[string]any)
	}{
		{"missing proof", func(r, c, p map[string]any) { delete(c, "passive_binary") }},
		{"null proof", func(r, c, p map[string]any) { c["passive_binary"] = nil }},
		{"unknown format", func(r, c, p map[string]any) { p["format"] = "safe" }},
		{"extra proof field", func(r, c, p map[string]any) { p["extra"] = true }},
		{"missing field", func(r, c, p map[string]any) { delete(p, "frames") }},
		{"boolean count", func(r, c, p map[string]any) { p["channels"] = true }},
		{"fractional count", func(r, c, p map[string]any) { p["channels"] = 1.5 }},
		{"zero channels", func(r, c, p map[string]any) { p["channels"] = float64(0) }},
		{"unbounded channels", func(r, c, p map[string]any) { p["channels"] = float64(9) }},
		{"zero rate", func(r, c, p map[string]any) { p["sample_rate"] = float64(0) }},
		{"unbounded rate", func(r, c, p map[string]any) { p["sample_rate"] = float64(384001) }},
		{"unknown bits", func(r, c, p map[string]any) { p["bits_per_sample"] = float64(64) }},
		{"block mismatch", func(r, c, p map[string]any) { p["block_align"] = float64(1) }},
		{"byte rate mismatch", func(r, c, p map[string]any) { p["byte_rate"] = float64(1) }},
		{"frame mismatch", func(r, c, p map[string]any) { p["frames"] = float64(1) }},
		{"empty data", func(r, c, p map[string]any) { p["data_bytes"] = float64(0) }},
		{"unaligned data", func(r, c, p map[string]any) { p["data_bytes"] = float64(32633) }},
		{"container mismatch", func(r, c, p map[string]any) { p["container_bytes"] = float64(32679) }},
		{"component mismatch", func(r, c, p map[string]any) { c["size_bytes"] = float64(32679) }},
		{"trailer", func(r, c, p map[string]any) { c["size_bytes"], p["container_bytes"] = float64(32680), float64(32680) }},
		{"text lines", func(r, c, p map[string]any) { c["lines"] = float64(-1) }},
		{"executable", func(r, c, p map[string]any) { c["executable"] = true }},
		{"wrong kind", func(r, c, p map[string]any) { c["type"] = "python" }},
		{"image with wave claim", func(r, c, p map[string]any) {
			c["path"] = "assets/image.png"
			r["analysis_completeness"].(map[string]any)["scope_exclusions"].([]any)[0].(map[string]any)["path"] = c["path"]
		}},
		{"hidden wave", func(r, c, p map[string]any) {
			c["path"] = ".hidden/bark.wav"
			r["analysis_completeness"].(map[string]any)["scope_exclusions"].([]any)[0].(map[string]any)["path"] = c["path"]
		}},
		{"no exclusion", func(r, c, p map[string]any) {
			r["analysis_completeness"].(map[string]any)["scope_exclusions"] = []any{}
		}},
		{"unknown evidence", func(r, c, p map[string]any) { c["passive_binary"] = []any{p} }},
	} {
		t.Run(tc.name, func(t *testing.T) { r, c, p := waveScopeFixture(t); tc.change(r, c, p); checkCaveatScope(t, r, false) })
	}
	for _, field := range []string{"artifact_integrity", "static_yara"} {
		t.Run("missing "+field, func(t *testing.T) {
			r, _, _ := waveScopeFixture(t)
			for _, v := range r["analysis_completeness"].(map[string]any)["analyzer_statuses"].([]any) {
				a := v.(map[string]any)
				if a["analyzer_id"] == field {
					a["planned_work"], a["completed"] = float64(2), float64(2)
				}
			}
			checkCaveatScope(t, r, false)
		})
	}
}

func TestSkillSpectorNativePCMFormats(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		channels, bits, length int
	}{
		{"odd mono8", 1, 8, 3}, {"stereo24", 2, 24, 18}, {"multichannel32", 8, 32, 96},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c, p := waveScopeFixture(t)
			block := tc.channels * (tc.bits / 8)
			p["channels"], p["bits_per_sample"], p["block_align"] = float64(tc.channels), float64(tc.bits), float64(block)
			p["byte_rate"], p["data_bytes"], p["frames"] = float64(44100*block), float64(tc.length), float64(tc.length/block)
			p["container_bytes"] = float64(44 + tc.length + tc.length%2)
			c["size_bytes"] = p["container_bytes"]
			// The binary decoder's informational line count is not text inspection.
			c["lines"] = float64(686)
			checkCaveatScope(t, r, true)
		})
	}
}
