package runner

import (
	"path"
	"strings"
)

// A versioned producer proof admits only canonical fmt(PCM)+data WAVE assets.
// Binary exclusion remains explicit; integrity and YARA still cover the bytes.
func skillSpectorPassiveWave(component map[string]any) bool {
	name, _ := component["path"].(string)
	if !skillSpectorComponentPath(name) || strings.Contains(name, "!/") || strings.ToLower(path.Ext(name)) != ".wav" || component["type"] != "other" || component["executable"] != false {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if strings.HasPrefix(segment, ".") {
			return false
		}
	}
	for _, field := range strings.Fields("outer_path nested_path container_type container_depth container_ancestry") {
		if _, exists := component[field]; exists {
			return false
		}
	}
	proof, ok := component["passive_binary"].(map[string]any)
	if !ok || len(proof) != 9 || !skillSpectorKnownFields(proof, "format channels sample_rate bits_per_sample block_align byte_rate data_bytes frames container_bytes") || proof["format"] != "riff_wave_pcm_v1" {
		return false
	}
	counts := make(map[string]int, 8)
	for _, field := range strings.Fields("channels sample_rate bits_per_sample block_align byte_rate data_bytes frames container_bytes") {
		n, ok := skillSpectorReportCount(proof[field])
		if !ok || n == 0 {
			return false
		}
		counts[field] = n
	}
	channels, rate, bits := counts["channels"], counts["sample_rate"], counts["bits_per_sample"]
	if channels > 8 || rate > 384000 || (bits != 8 && bits != 16 && bits != 24 && bits != 32) {
		return false
	}
	block, length := channels*(bits/8), counts["data_bytes"]
	size, sizeOK := skillSpectorReportCount(component["size_bytes"])
	return sizeOK && counts["block_align"] == block && counts["byte_rate"] == rate*block && length%block == 0 && counts["frames"] == length/block && counts["container_bytes"] == size && size == 44+length+length%2
}
