package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alchemy/json5"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// skillManifestName and pluginManifestName are the manifest files that mark an
// OpenClaw skill and an OpenClaw plugin. Classification treats them as
// the single source of truth for target identity.
const (
	skillManifestName  = "SKILL.md"
	pluginManifestName = "openclaw.plugin.json"
)

// validPluginID ports OpenClaw's validatePluginId install-path rules: a bare
// name or an @scope/name pair, with no backslashes, empty segments, or
// reserved path segments, so the identity recorded in artifacts can never
// smuggle a host path and any id the host runtime accepts is accepted here.
// The only addition is rejecting control characters, which keeps recorded
// identities safe for artifacts and terminal output.
func validPluginID(id string) bool {
	if id == "" || strings.Contains(id, `\`) {
		return false
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	segments := strings.Split(id, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	switch len(segments) {
	case 1:
		return !strings.HasPrefix(id, "@")
	case 2:
		return strings.HasPrefix(segments[0], "@") && len(segments[0]) >= 2
	default:
		return false
	}
}

// Target kinds recorded in run artifacts and used for scanner compatibility.
// skill and url preserve the historical Clawscan behavior; plugin is the
// first-class OpenClaw plugin target added alongside them.
const (
	targetKindSkill  = "skill"
	targetKindPlugin = "plugin"
	targetKindURL    = "url"
)

// maxPluginManifestBytes matches OpenClaw's MAX_PLUGIN_MANIFEST_BYTES so a
// manifest the host runtime accepts is never rejected here for size.
const maxPluginManifestBytes = 256 * 1024

var bundleManifestDirectories = []string{".codex-plugin", ".claude-plugin", ".cursor-plugin"}
var bundleIDSeparators = regexp.MustCompile(`[^a-z0-9]+`)

func isBundleManifestDirectory(name string) bool {
	for _, directory := range bundleManifestDirectories {
		if name == directory {
			return true
		}
	}
	return false
}

func hasBundleManifest(directory string) bool {
	for _, parent := range bundleManifestDirectories {
		info, err := os.Lstat(filepath.Join(directory, parent))
		if err == nil && info.IsDir() && regularManifestExists(filepath.Join(directory, parent, "plugin.json")) {
			return true
		}
	}
	return false
}

func bundleManifestPaths(directory string) ([]string, error) {
	var manifests []string
	for _, parentName := range bundleManifestDirectories {
		parent, parentErr := os.Lstat(filepath.Join(directory, parentName))
		if os.IsNotExist(parentErr) {
			continue
		}
		if parentErr != nil || !parent.IsDir() {
			return nil, fmt.Errorf("unsafe bundle manifest directory %s", parentName)
		}
		manifest := filepath.Join(parentName, "plugin.json")
		if _, err := os.Lstat(filepath.Join(directory, manifest)); os.IsNotExist(err) {
			continue
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

// resolvedTarget is the small target abstraction the runner threads from the
// scan input through scanner dispatch and into the artifact. It carries enough
// to run scanners (resolvedPath), decide scanner compatibility (kind), and
// report a stable identity (id) without leaking that identity from a host path.
type resolvedTarget struct {
	kind         string
	input        string
	resolvedPath string
	// id is a stable, host-path-free identity. It is populated for plugin
	// targets from their manifest and empty for skills and URLs.
	id string
}

func resolveTargetForOptions(opts Options) (resolvedTarget, error) {
	if opts.TargetKind == "" {
		return resolveTarget(opts.Target)
	}
	if opts.TargetKind != targetKindSkill && opts.TargetKind != targetKindPlugin {
		return resolvedTarget{}, fmt.Errorf("unsupported target kind override: %s", opts.TargetKind)
	}
	if isURLTarget(opts.Target) {
		return resolvedTarget{}, errors.New("target kind override requires a local path")
	}
	resolved, err := filepath.Abs(opts.Target)
	if err != nil {
		return resolvedTarget{}, err
	}
	if info, err := os.Lstat(resolved); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if evaluated, evalErr := filepath.EvalSymlinks(resolved); evalErr == nil {
			resolved = evaluated
		}
	}
	return resolvedTarget{
		kind:         opts.TargetKind,
		input:        opts.Target,
		resolvedPath: resolved,
	}, nil
}

func resolveTarget(input string) (resolvedTarget, error) {
	if isURLTarget(input) {
		return resolvedTarget{kind: targetKindURL, input: input, resolvedPath: input}, nil
	}
	resolved, err := filepath.Abs(input)
	if err != nil {
		return resolvedTarget{}, err
	}
	// The top-level target path is operator input, so a symlink here is
	// resolved deliberately, matching how a shell would treat it. Manifests
	// found inside the target are untrusted content and never followed; see
	// regularManifestExists and readPluginID.
	if info, err := os.Lstat(resolved); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if isBundleManifestDirectory(filepath.Base(filepath.Dir(resolved))) && filepath.Base(resolved) == "plugin.json" {
			return failedLocalTarget(input, resolved), errors.New("bundle manifest must not be a symlink")
		}
		if evaluated, evalErr := filepath.EvalSymlinks(resolved); evalErr == nil {
			resolved = evaluated
		}
	}
	kind, id, err := classifyLocalTarget(resolved, input)
	if err != nil {
		return failedLocalTarget(input, resolved), err
	}
	// A plugin classified via its manifest file is scanned as its directory so
	// scanners see the plugin code, not just the manifest. In a dual-layout
	// package, an explicit SKILL.md similarly disambiguates the target without
	// narrowing the scan to that one file.
	if kind == targetKindPlugin ||
		(kind == targetKindSkill && sameManifestFile(resolved, skillManifestName) &&
			(regularManifestExists(filepath.Join(filepath.Dir(resolved), pluginManifestName)) || hasBundleManifest(filepath.Dir(resolved)))) {
		if info, err := os.Stat(resolved); err == nil && !info.IsDir() {
			bundleManifest := isBundleManifestDirectory(filepath.Base(filepath.Dir(resolved))) && sameManifestFile(resolved, "plugin.json")
			resolved = filepath.Dir(resolved)
			if kind == targetKindPlugin && bundleManifest {
				resolved = filepath.Dir(resolved)
			}
		}
	}
	return resolvedTarget{kind: kind, input: input, resolvedPath: resolved, id: id}, nil
}

func failedLocalTarget(input string, resolved string) resolvedTarget {
	root := resolved
	if sameManifestFile(resolved, pluginManifestName) {
		root = filepath.Dir(resolved)
	} else if isBundleManifestDirectory(filepath.Base(filepath.Dir(resolved))) {
		selected, selectedErr := os.Lstat(resolved)
		manifest, manifestErr := os.Lstat(filepath.Join(filepath.Dir(resolved), "plugin.json"))
		if selectedErr == nil && manifestErr == nil && os.SameFile(selected, manifest) && (manifest.Mode().IsRegular() || manifest.Mode()&os.ModeSymlink != 0) {
			root = filepath.Dir(filepath.Dir(resolved))
		}
	}
	return resolvedTarget{input: input, resolvedPath: root}
}

// classifyLocalTarget decides whether a resolved local path is a skill or an
// OpenClaw plugin. It defaults to skill so existing skill scans, single-file
// targets, and missing paths behave exactly as before; only an explicit plugin
// manifest promotes the target to a plugin. A directory carrying both manifests
// is rejected as ambiguous, but an explicitly selected manifest disambiguates
// the package without guessing.
func classifyLocalTarget(resolvedPath string, input string) (kind string, id string, err error) {
	info, statErr := os.Stat(resolvedPath)
	if statErr != nil {
		return targetKindSkill, "", nil
	}
	dir := resolvedPath
	explicitPluginManifest := false
	if !info.IsDir() {
		if sameManifestFile(resolvedPath, pluginManifestName) {
			dir = filepath.Dir(resolvedPath)
			explicitPluginManifest = true
		} else if isBundleManifestDirectory(filepath.Base(filepath.Dir(resolvedPath))) && sameManifestFile(resolvedPath, "plugin.json") {
			root := filepath.Dir(filepath.Dir(resolvedPath))
			manifests, err := bundleManifestPaths(root)
			if err != nil {
				return "", "", err
			}
			if len(manifests) != 1 {
				return "", "", fmt.Errorf("target %s has ambiguous bundle manifests", displayTargetInput(input))
			}
			id, err := readBundlePluginID(root, filepath.Join(filepath.Base(filepath.Dir(resolvedPath)), "plugin.json"))
			if err != nil {
				return "", "", fmt.Errorf("target %s is not a valid bundle plugin: %w", displayTargetInput(input), err)
			}
			return targetKindPlugin, id, nil
		} else if filepath.Base(resolvedPath) == "plugin.json" && strings.HasSuffix(filepath.Base(filepath.Dir(resolvedPath)), "-plugin") {
			return "", "", fmt.Errorf("unsupported bundle manifest format")
		} else {
			// SKILL.md or any other single file keeps the historical skill kind.
			return targetKindSkill, "", nil
		}
	}
	hasPlugin := regularManifestExists(filepath.Join(dir, pluginManifestName))
	hasSkill := regularManifestExists(filepath.Join(dir, skillManifestName))
	if !explicitPluginManifest {
		bundles, err := bundleManifestPaths(dir)
		if err != nil {
			return "", "", err
		}
		if len(bundles) > 1 || (len(bundles) > 0 && (hasPlugin || hasSkill)) {
			return "", "", fmt.Errorf("target %s has ambiguous plugin manifests; point Clawscan directly at the desired manifest", displayTargetInput(input))
		}
		if len(bundles) == 1 {
			id, err := readBundlePluginID(dir, bundles[0])
			if err != nil {
				return "", "", fmt.Errorf("target %s is not a valid bundle plugin: %w", displayTargetInput(input), err)
			}
			return targetKindPlugin, id, nil
		}
	}
	if !hasPlugin {
		return targetKindSkill, "", nil
	}
	if hasSkill && !explicitPluginManifest {
		return "", "", fmt.Errorf("target %s contains both %s and %s; point Clawscan directly at the desired manifest", displayTargetInput(input), skillManifestName, pluginManifestName)
	}
	id, err = readPluginID(filepath.Join(dir, pluginManifestName))
	if err != nil {
		return "", "", fmt.Errorf("target %s is not a valid plugin: %w", displayTargetInput(input), err)
	}
	return targetKindPlugin, id, nil
}

func readBundlePluginID(directory, manifest string) (string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	parent, err := root.Lstat(filepath.Dir(manifest))
	if err != nil || !parent.IsDir() {
		return "", fmt.Errorf("bundle manifest parent must be a real directory")
	}
	before, err := root.Lstat(manifest)
	if err != nil || !before.Mode().IsRegular() {
		return "", fmt.Errorf("bundle manifest must be a regular file")
	}
	file, err := root.OpenFile(manifest, os.O_RDONLY|openNoFollowFlag, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", fmt.Errorf("bundle manifest changed while being read")
	}
	if opened.Size() > maxPluginManifestBytes {
		return "", fmt.Errorf("bundle manifest exceeds the %d KiB manifest limit", maxPluginManifestBytes/1024)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPluginManifestBytes+1))
	if err != nil || int64(len(data)) > maxPluginManifestBytes {
		return "", fmt.Errorf("cannot read bounded bundle manifest")
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("bundle manifest must be valid UTF-8")
	}
	var raw map[string]any
	if err := json5.Unmarshal(data, &raw); err != nil || raw == nil {
		return "", fmt.Errorf("bundle manifest must be a JSON object")
	}
	name, ok := raw["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("bundle manifest must declare a name")
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsAny(name, "\x00\x7f") {
		return "", fmt.Errorf("bundle manifest has an unsafe name")
	}
	for _, character := range name {
		if character < 0x20 {
			return "", fmt.Errorf("bundle manifest has an unsafe name")
		}
	}
	name = strings.TrimSpace(name)
	if name == "." || name == ".." {
		return "", fmt.Errorf("bundle manifest has an unsafe name")
	}
	id := strings.Trim(bundleIDSeparators.ReplaceAllString(cases.Lower(language.Und).String(name), "-"), "-")
	if id == "" {
		return "", fmt.Errorf("bundle manifest name has no canonical identity")
	}
	return id, nil
}

// regularManifestExists reports whether path is an existing regular file
// without following symlinks. A target cannot present a symlinked or special
// manifest to be classified: an untrusted target could point its manifest at a
// host file outside the target, so only a real regular file counts here.
func regularManifestExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// sameManifestFile recognizes an explicitly selected manifest by filesystem
// identity, not spelling. This preserves manifest targeting on case-insensitive
// filesystems while still requiring the canonical in-directory manifest to be
// a real regular file.
func sameManifestFile(path string, manifestName string) bool {
	selected, err := os.Stat(path)
	if err != nil || selected.IsDir() {
		return false
	}
	canonical, err := os.Lstat(filepath.Join(filepath.Dir(path), manifestName))
	return err == nil && canonical.Mode().IsRegular() && os.SameFile(selected, canonical)
}

// readPluginID parses the stable plugin identity from a plugin manifest and
// validates it against the canonical OpenClaw plugin identifier grammar, so the
// identity recorded in artifacts is always well-formed.
//
// It never follows a symlink: the manifest is opened O_NOFOLLOW and re-checked
// against a leading lstat, so a target that swaps its regular manifest for an
// symlink (racing between classification and read) fails closed instead of
// exposing an outside host file. The lstat/fstat identity check backstops
// platforms without an O_NOFOLLOW equivalent.
func readPluginID(manifestPath string) (string, error) {
	before, err := os.Lstat(manifestPath)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file, not a symlink or special file", pluginManifestName)
	}
	file, err := os.OpenFile(manifestPath, os.O_RDONLY|openNoFollowFlag, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", fmt.Errorf("%s changed while it was being read", pluginManifestName)
	}
	if opened.Size() > maxPluginManifestBytes {
		return "", fmt.Errorf("%s exceeds the %d KiB manifest limit", pluginManifestName, maxPluginManifestBytes/1024)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPluginManifestBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxPluginManifestBytes {
		return "", fmt.Errorf("%s exceeds the %d KiB manifest limit", pluginManifestName, maxPluginManifestBytes/1024)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		manifest = nil
		if err := json5.Unmarshal(data, &manifest); err != nil {
			return "", fmt.Errorf("parse %s: %w", pluginManifestName, err)
		}
	}
	id, ok := manifest["id"].(string)
	if !ok {
		return "", fmt.Errorf("%s has an invalid plugin id", pluginManifestName)
	}
	id = strings.TrimSpace(id)
	if !validPluginID(id) {
		return "", fmt.Errorf("%s has an invalid plugin id %q", pluginManifestName, id)
	}
	return id, nil
}

// displayTargetInput echoes the operator-provided target back in errors. It is
// the input the caller typed, not a resolved host path, so classification
// failures stay legible without widening host-path exposure.
func displayTargetInput(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "the scan target"
	}
	return input
}

func isURLTarget(input string) bool {
	parsed, err := url.Parse(input)
	return err == nil && parsed.Scheme != "" && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

// runnableScanners filters the selected scanners down to those that will
// actually execute against this target kind, so requirement validation and
// sandbox gating never demand credentials or Docker for scanners that can only
// produce a skipped result. Pre-supplied scanner results are kept; they never
// execute anything.
func runnableScanners(opts Options, kind string) []string {
	var out []string
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] == "" && !scannerSupportsTargetKindInRegistry(registryForOptions(opts), scanner, kind) {
			continue
		}
		out = append(out, scanner)
	}
	return out
}

// scannerSupportsTargetKind reports whether a built-in scanner can run against a
// target of the given kind. Unknown scanner IDs are permitted here so the
// scanner runner can still emit its own skipped result for them.
func scannerSupportsTargetKind(scanner string, kind string) bool {
	return scannerSupportsTargetKindInRegistry(DefaultScannerRegistry(), scanner, kind)
}

func scannerSupportsTargetKindInRegistry(registry ScannerRegistry, scanner string, kind string) bool {
	adapter, ok := registry.Adapter(scanner)
	if !ok {
		return true
	}
	return adapter.SupportsTargetKind(kind)
}

// unsupportedTargetKindResult is the explicit skipped result a skill-only
// scanner returns for a target kind it cannot analyze.
func unsupportedTargetKindResult(scanner string, kind string, startedAt string) ScannerResult {
	return ScannerResult{
		Status:      "skipped",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Error:       fmt.Sprintf("Scanner %s does not support %s targets.", scanner, kind),
	}
}
