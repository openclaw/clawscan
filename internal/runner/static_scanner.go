package runner

import (
	"bytes"
	"context"
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
	{
		id:          "static.python_process_execution",
		title:       "Python process execution",
		severity:    "high",
		description: "Looks for Python APIs that execute shell commands or child processes.",
		pattern:     regexp.MustCompile(`(?i)\b(?:os\s*\.\s*system|subprocess\s*\.\s*(?:call|check_call|check_output|popen|run))\s*\(`),
	},
	{
		id:          "static.python_bytecode",
		title:       "Packaged Python bytecode",
		severity:    "high",
		description: "Flags precompiled Python bytecode that can execute without reviewable source.",
	},
	{
		id:          "static.nul_byte_in_text",
		title:       "NUL bytes in inspectable content",
		severity:    "high",
		description: "Flags NUL bytes that can disguise executable or policy-relevant content as an opaque binary.",
	},
	{
		id:          "static.opaque_binary",
		title:       "Opaque binary content",
		severity:    "low",
		description: "Surfaces opaque binary content that cannot be inspected by text rules.",
	},
}

type staticFileCandidate struct {
	path string
	rel  string
	info os.FileInfo
}

func (runner ExternalScannerRunner) runStatic(target string, startedAt string) (ScannerResult, error) {
	command := []string{"clawscan-static", target}
	if isURLTarget(target) {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Command:     command,
			Error:       "ClawScan static scanner supports local file or directory targets in v1; URL targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	report, err := buildStaticScannerReportContext(workContext(runner.Context), target)
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
	return buildStaticScannerReportContext(context.Background(), target)
}

func buildStaticScannerReportContext(ctx context.Context, target string) (staticScannerReport, error) {
	files, findings, err := scanStaticTargetContext(ctx, target)
	if err != nil {
		return staticScannerReport{}, err
	}
	return staticScannerReport{
		SchemaVersion: staticScannerVersion,
		Scanner: staticScannerMetadata{
			ID:      "clawscan-static",
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
	return scanStaticTargetContext(context.Background(), target)
}

func scanStaticTargetContext(ctx context.Context, target string) (staticScannerFiles, []staticFinding, error) {
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
		if err := ctx.Err(); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			files.addOmitted(rel, "not regular file", 0)
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.EqualFold(filepath.Ext(rel), ".pyc") {
			findings = append(findings, staticFinding{
				ID:          "static.python_bytecode",
				Title:       "Packaged Python bytecode",
				Severity:    "high",
				Description: "Precompiled Python bytecode is executable and opaque to source-text review.",
				Path:        rel,
				Line:        1,
				Evidence:    "Precompiled Python bytecode is included in the scanned target.",
			})
		}
		if info.Size() > maxTargetFileBytes {
			files.addOmitted(rel, "file exceeds size limit", info.Size())
			return nil
		}
		if totalBytes+info.Size() > maxTargetFilesBytes {
			files.addOmitted(rel, "total file budget exceeded", info.Size())
			return nil
		}
		content, err := readContextFile(ctx, path)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			files.addOmitted(rel, "read failed", info.Size())
			return nil
		}
		contentFindings := scanStaticContent(rel, string(content))
		if bytes.IndexByte(content, 0) >= 0 {
			inspection, _ := inspectNULContent(rel, content)
			contentFindings = scanStaticInspection(rel, inspection)
			if !inspection.reviewable && len(contentFindings) == 0 {
				files.addOmitted(rel, "binary file", info.Size())
				if !strings.EqualFold(filepath.Ext(rel), ".pyc") {
					findings = append(findings, staticFinding{
						ID:          "static.opaque_binary",
						Title:       "Opaque binary content",
						Severity:    "low",
						Description: "Opaque binary content cannot be inspected by text rules and requires policy review.",
						Path:        rel,
						Line:        1,
						Evidence:    "Binary file was omitted from text inspection.",
					})
				}
				return nil
			}
			if inspection.obfuscated {
				nulOffset := bytes.IndexByte(content, 0)
				findings = append(findings, staticFinding{
					ID:          "static.nul_byte_in_text",
					Title:       "NUL bytes in inspectable content",
					Severity:    "high",
					Description: "NUL bytes can disguise policy-relevant content as an opaque binary; ClawScan removed them before applying static rules.",
					Path:        rel,
					Line:        bytes.Count(content[:nulOffset], []byte{'\n'}) + 1,
					Evidence:    fmt.Sprintf("Inspectable file contains %d NUL byte(s).", bytes.Count(content, []byte{0})),
				})
			}
		}
		totalBytes += info.Size()
		files.addScanned(rel, info.Size(), sha256BytesHex(content))
		findings = append(findings, contentFindings...)
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
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return files.recordWalkError(target, path, entry)
		}
		if entry.IsDir() {
			if shouldSkipTargetDirectory(target, path) {
				rel := relativeManifestPath(target, path)
				files.addOmitted(rel, "skipped path", 0)
				return filepath.SkipDir
			}
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
	normalized := filepath.ToSlash(path)
	if strings.EqualFold(normalized, "SKILL.md") || strings.EqualFold(normalized, "openclaw.plugin.json") {
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
			if rule.pattern == nil {
				continue
			}
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

func scanStaticInspection(path string, inspection nulContentInspection) []staticFinding {
	findings := scanStaticContent(path, string(inspection.content))
	if len(inspection.alternate) == 0 {
		return findings
	}
	seen := make(map[string]bool, len(findings))
	for _, finding := range findings {
		seen[fmt.Sprintf("%s\x00%d", finding.ID, finding.Line)] = true
	}
	for _, finding := range scanStaticContent(path, string(inspection.alternate)) {
		key := fmt.Sprintf("%s\x00%d", finding.ID, finding.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, finding)
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
