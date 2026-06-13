package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const staticScannerVersion = "clawscan-static-v1"
const maxStaticEvidenceBytes = 180

type staticScannerReport struct {
	SchemaVersion string                `json:"schemaVersion"`
	Scanner       staticScannerMetadata `json:"scanner"`
	Files         staticScannerFiles    `json:"files"`
	Findings      []staticFinding       `json:"findings"`
}

type staticScannerMetadata struct {
	ID      string              `json:"id"`
	Name    string              `json:"name"`
	Version string              `json:"version"`
	Rules   []staticRuleSummary `json:"rules"`
}

type staticRuleSummary struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type staticScannerFiles struct {
	Scanned           []staticScannedFile       `json:"scanned"`
	Omitted           []TargetWorkspaceOmission `json:"omitted"`
	TotalScannedBytes int64                     `json:"totalScannedBytes"`
	TotalOmittedBytes int64                     `json:"totalOmittedBytes"`
	SuppressedScanned int                       `json:"suppressedScanned"`
	SuppressedOmitted int                       `json:"suppressedOmitted"`
}

type staticScannedFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type staticFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Evidence    string `json:"evidence"`
}

type staticRule struct {
	id          string
	title       string
	severity    string
	description string
	pattern     *regexp.Regexp
}

var staticRules = []staticRule{
	{
		id:          "static.prompt_injection",
		title:       "Prompt-injection style instruction override",
		severity:    "medium",
		description: "Looks for direct attempts to override prior instructions.",
		pattern:     regexp.MustCompile(`(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|earlier)\s+instructions?\b`),
	},
	{
		id:          "static.credential_exfiltration",
		title:       "Credential exfiltration language",
		severity:    "high",
		description: "Looks for language that asks an agent to leak or exfiltrate credentials.",
		pattern:     regexp.MustCompile(`(?i)\b(exfiltrate|steal|leak)\s+(credentials?|secrets?|tokens?|api\s*keys?)\b`),
	},
	{
		id:          "static.pipe_to_shell",
		title:       "Remote script piped to shell",
		severity:    "medium",
		description: "Looks for curl or wget output piped directly into a shell.",
		pattern:     regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b`),
	},
	{
		id:          "static.destructive_shell",
		title:       "Destructive shell command",
		severity:    "high",
		description: "Looks for destructive recursive removal of the filesystem root.",
		pattern:     regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*(?:r[a-z]*f|f[a-z]*r)[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)\s+/(?:\s|$)`),
	},
}

type staticFileCandidate struct {
	path string
	rel  string
	info os.FileInfo
}

func (runner ExternalScannerRunner) runStatic(target string, startedAt string) (ScannerResult, error) {
	command := []string{"static", target}
	if isURLTarget(target) {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Command:     command,
			Error:       "Static scanner supports local file or directory targets in v1; URL targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	report, err := buildStaticScannerReport(target)
	if err != nil {
		return ScannerResult{}, err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return ScannerResult{}, err
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Command:     command,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}, nil
}

func buildStaticScannerReport(target string) (staticScannerReport, error) {
	files, findings, err := scanStaticTarget(target)
	if err != nil {
		return staticScannerReport{}, err
	}
	return staticScannerReport{
		SchemaVersion: staticScannerVersion,
		Scanner: staticScannerMetadata{
			ID:      "static",
			Name:    "ClawScan built-in static scanner",
			Version: staticScannerVersion,
			Rules:   staticRuleSummaries(),
		},
		Files:    files,
		Findings: findings,
	}, nil
}

func staticRuleSummaries() []staticRuleSummary {
	summaries := make([]staticRuleSummary, 0, len(staticRules))
	for _, rule := range staticRules {
		summaries = append(summaries, staticRuleSummary{
			ID:          rule.id,
			Description: rule.description,
			Severity:    rule.severity,
		})
	}
	return summaries
}

func scanStaticTarget(target string) (staticScannerFiles, []staticFinding, error) {
	files := staticScannerFiles{
		Scanned: []staticScannedFile{},
		Omitted: []TargetWorkspaceOmission{},
	}
	info, err := os.Stat(target)
	if err != nil {
		return files, nil, err
	}
	var totalBytes int64
	findings := []staticFinding{}
	scanFile := func(path string, rel string, info os.FileInfo) error {
		if !info.Mode().IsRegular() {
			files.addOmitted(rel, "not regular file", 0)
			return nil
		}
		if info.Size() > maxTargetFileBytes {
			files.addOmitted(rel, "file exceeds size limit", info.Size())
			return nil
		}
		if totalBytes+info.Size() > maxTargetFilesBytes {
			files.addOmitted(rel, "total file budget exceeded", info.Size())
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			files.addOmitted(rel, "read failed", info.Size())
			return nil
		}
		if bytes.IndexByte(content, 0) >= 0 {
			files.addOmitted(rel, "binary file", info.Size())
			return nil
		}
		totalBytes += info.Size()
		rel = filepath.ToSlash(rel)
		files.addScanned(rel, info.Size(), sha256BytesHex(content))
		findings = append(findings, scanStaticContent(rel, string(content))...)
		return nil
	}
	if !info.IsDir() {
		if err := scanFile(target, filepath.Base(target), info); err != nil {
			return files, nil, err
		}
		return files, findings, nil
	}
	var candidates []staticFileCandidate
	err = filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return files.recordWalkError(target, path, entry)
		}
		if shouldSkipTargetPath(target, path) {
			rel := relativeManifestPath(target, path)
			if entry.IsDir() {
				files.addOmitted(rel, "skipped path", 0)
				return filepath.SkipDir
			}
			files.addOmitted(rel, "skipped path", 0)
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(target, path)
		if err != nil {
			return err
		}
		candidates = append(candidates, staticFileCandidate{
			path: path,
			rel:  rel,
			info: info,
		})
		return nil
	})
	if err != nil {
		return files, findings, err
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		leftPriority := staticFilePriority(candidates[i].rel)
		rightPriority := staticFilePriority(candidates[j].rel)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return filepath.ToSlash(candidates[i].rel) < filepath.ToSlash(candidates[j].rel)
	})
	for _, candidate := range candidates {
		if err := scanFile(candidate.path, candidate.rel, candidate.info); err != nil {
			return files, findings, err
		}
	}
	return files, findings, nil
}

func (files *staticScannerFiles) recordWalkError(root string, path string, entry os.DirEntry) error {
	rel := relativeManifestPath(root, path)
	files.addOmitted(rel, "read failed", 0)
	if entry != nil && entry.IsDir() {
		return filepath.SkipDir
	}
	return nil
}

func staticFilePriority(path string) int {
	if strings.EqualFold(filepath.ToSlash(path), "SKILL.md") {
		return 0
	}
	return 1
}

func (files *staticScannerFiles) addScanned(path string, bytes int64, digest string) {
	files.TotalScannedBytes += bytes
	if len(files.Scanned) >= maxOmittedTargetFileMarkers {
		files.SuppressedScanned++
		return
	}
	files.Scanned = append(files.Scanned, staticScannedFile{
		Path:   filepath.ToSlash(path),
		Bytes:  bytes,
		SHA256: digest,
	})
}

func (files *staticScannerFiles) addOmitted(path string, reason string, bytes int64) {
	files.TotalOmittedBytes += bytes
	if len(files.Omitted) >= maxOmittedTargetFileMarkers {
		files.SuppressedOmitted++
		return
	}
	files.Omitted = append(files.Omitted, TargetWorkspaceOmission{
		Path:   filepath.ToSlash(path),
		Reason: reason,
		Bytes:  bytes,
	})
}

func scanStaticContent(path string, content string) []staticFinding {
	var findings []staticFinding
	lines := strings.Split(content, "\n")
	for lineIndex, line := range lines {
		for _, rule := range staticRules {
			if !rule.pattern.MatchString(line) {
				continue
			}
			findings = append(findings, staticFinding{
				ID:          rule.id,
				Title:       rule.title,
				Severity:    rule.severity,
				Description: rule.description,
				Path:        path,
				Line:        lineIndex + 1,
				Evidence:    evidenceSnippet(line),
			})
		}
	}
	return findings
}

func evidenceSnippet(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Join(strings.Fields(line), " ")
	if len(line) <= maxStaticEvidenceBytes {
		return line
	}
	runes := []rune(line)
	if len(runes) <= maxStaticEvidenceBytes {
		return line
	}
	return string(runes[:maxStaticEvidenceBytes]) + "..."
}

func sha256BytesHex(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}
