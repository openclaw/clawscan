package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// templateTarget recognizes only the canonical package selector. CLAW.md alone
// is not identity, and a nested selector never narrows the audited package root.
// This is scanner dispatch, not Template admission or publisher verification.
func templateTarget(directory string) (bool, string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return false, "", err
	}
	defer root.Close()
	before, err := root.Lstat("package.json")
	if os.IsNotExist(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	// Unrelated skill/plugin packages may use linked or larger package metadata.
	// Do not follow it or impose new admission rules on non-Template targets.
	if !before.Mode().IsRegular() {
		return false, "", nil
	}
	file, err := root.OpenFile("package.json", os.O_RDONLY|openNoFollowFlag, 0)
	if err != nil {
		return false, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return false, "", fmt.Errorf("package.json changed while being read")
	}
	if opened.Size() > maxPluginManifestBytes {
		return false, "", nil
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPluginManifestBytes+1))
	if err != nil {
		return false, "", err
	}
	if len(data) > maxPluginManifestBytes {
		return false, "", nil
	}
	var pkg struct {
		Name     string                     `json:"name"`
		OpenClaw map[string]json.RawMessage `json:"openclaw"`
	}
	// Other directory scanners historically accept non-JSON package manifests.
	// Only a successfully parsed canonical selector opts into Template dispatch.
	if !utf8.Valid(data) || json.Unmarshal(data, &pkg) != nil {
		return false, "", nil
	}
	if _, retired := pkg.OpenClaw["claw"]; retired {
		return false, "", fmt.Errorf("retired openclaw.claw selector is unsupported; use openclaw.template")
	}
	raw, present := pkg.OpenClaw["template"]
	if !present {
		return false, "", nil
	}
	var selector string
	if json.Unmarshal(raw, &selector) != nil || !safeTemplateSelector(selector) {
		return false, "", fmt.Errorf("openclaw.template must select a safe package-relative CLAW.md")
	}
	// Refuse links in every component, not just the final file. OpenRoot confines
	// reads too; no package-authored link can make classification read outside it.
	parts := strings.Split(strings.TrimPrefix(selector, "./"), "/")
	for i := range parts {
		info, err := root.Lstat(filepath.FromSlash(strings.Join(parts[:i+1], "/")))
		if err != nil {
			return false, "", fmt.Errorf("openclaw.template selector: %w", err)
		}
		if i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
			return false, "", fmt.Errorf("openclaw.template selector must name a regular file through real directories")
		}
	}
	// Identity is optional and descriptive; never confer trust from package text.
	id := strings.TrimSpace(pkg.Name)
	if !validPluginID(id) {
		id = ""
	}
	return true, id, nil
}

func safeTemplateSelector(selector string) bool {
	if selector == "" || strings.TrimSpace(selector) != selector || strings.ContainsAny(selector, `\:`) || path.IsAbs(selector) || path.Base(selector) != "CLAW.md" {
		return false
	}
	selector = strings.TrimPrefix(selector, "./")
	for _, part := range strings.Split(selector, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}
