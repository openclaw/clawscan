package installpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxDependencyPackages   = 10_000
	maxDependencyEntries    = 100_000
	maxDependencyFileBytes  = 64 * 1024 * 1024
	maxDependencyTotalBytes = 512 * 1024 * 1024
)

type dependencyCopyBudget struct {
	entries    int
	totalBytes int64
}

type npmPreflightMetadata struct {
	PackageName        string `json:"packageName"`
	RequestedSpecifier string `json:"requestedSpecifier"`
	Resolution         struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"resolution"`
}

func ValidateNPMMetadataPreflight(request Request) error {
	if !request.IsNPMMetadataStage() {
		return errors.New("request is not an OpenClaw npm metadata stage")
	}
	if filepath.Base(filepath.Clean(request.SourcePath)) != "npm-package-metadata.json" {
		return errors.New("npm preflight sourcePath must name npm-package-metadata.json")
	}
	if request.Plugin == nil ||
		request.Plugin.ContentType != "package" ||
		strings.TrimSpace(request.Plugin.PackageName) == "" {
		return errors.New("npm preflight plugin metadata is inconsistent")
	}
	if request.Source == nil ||
		request.Source.Kind != "npm" ||
		request.Source.Mutable ||
		!request.Source.Network ||
		(request.Source.Authority != "official" && request.Source.Authority != "third-party") {
		return errors.New("npm preflight source provenance is inconsistent")
	}
	originType, _ := request.Origin["type"].(string)
	originPackageName, _ := request.Origin["packageName"].(string)
	if originType != "plugin-npm" || originPackageName != request.Plugin.PackageName {
		return errors.New("npm preflight origin provenance is inconsistent")
	}
	info, err := os.Lstat(request.SourcePath)
	if err != nil {
		return fmt.Errorf("inspect npm preflight metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("npm preflight metadata must be a regular file")
	}
	if info.Size() > maxRequestBytes {
		return fmt.Errorf("npm preflight metadata exceeds %d bytes", maxRequestBytes)
	}
	file, err := os.Open(request.SourcePath)
	if err != nil {
		return fmt.Errorf("open npm preflight metadata: %w", err)
	}
	defer file.Close()

	var metadata npmPreflightMetadata
	decoder := json.NewDecoder(io.LimitReader(file, maxRequestBytes+1))
	if err := decoder.Decode(&metadata); err != nil {
		return fmt.Errorf("parse npm preflight metadata: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return err
	}
	if metadata.PackageName != request.Plugin.PackageName {
		return errors.New("npm preflight metadata packageName does not match policy metadata")
	}
	if strings.TrimSpace(request.Request.RequestedSpecifier) == "" ||
		metadata.RequestedSpecifier != request.Request.RequestedSpecifier {
		return errors.New("npm preflight metadata requestedSpecifier does not match policy metadata")
	}
	if metadata.Resolution.Name != metadata.PackageName {
		return errors.New("npm preflight resolution name does not match packageName")
	}
	if strings.TrimSpace(metadata.Resolution.Version) == "" {
		return errors.New("npm preflight resolution version must not be empty")
	}
	return nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("npm preflight metadata contains multiple JSON values")
		}
		return fmt.Errorf("parse npm preflight metadata trailing data: %w", err)
	}
	return nil
}

// PrepareDependencyTreeScanTarget exposes each installed npm package in one
// temporary scan root without a node_modules path segment. ClawScan's normal
// source scanners intentionally skip node_modules for ordinary repository
// scans, so the install-policy adapter uses this view only for OpenClaw's
// explicit dependency-tree phase.
func PrepareDependencyTreeScanTarget(
	sourcePath string,
	allowManagedNPMRootPeerLinks bool,
) (string, func(), bool, error) {
	root, err := filepath.Abs(sourcePath)
	if err != nil {
		return "", nil, false, fmt.Errorf("resolve dependency-tree root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, false, fmt.Errorf("resolve dependency-tree root symlinks: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", nil, false, fmt.Errorf("inspect dependency-tree root: %w", err)
	}
	if !info.IsDir() {
		return "", nil, false, errors.New("dependency-tree sourcePath must be a directory")
	}

	packageDirs, err := collectDependencyPackageDirs(root, allowManagedNPMRootPeerLinks)
	if err != nil {
		return "", nil, false, err
	}
	if len(packageDirs) == 0 {
		return "", func() {}, true, nil
	}

	tempRoot, err := os.MkdirTemp("", "clawscan-openclaw-dependencies-*")
	if err != nil {
		return "", nil, false, fmt.Errorf("create dependency scan root: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempRoot)
	}
	scanRoot := filepath.Join(tempRoot, "packages")
	budget := dependencyCopyBudget{}
	for index, packageDir := range packageDirs {
		destination := filepath.Join(scanRoot, fmt.Sprintf("%05d", index+1))
		if err := copyDependencyPackage(root, packageDir, destination, &budget); err != nil {
			cleanup()
			return "", nil, false, err
		}
	}
	resolvedScanRoot, err := filepath.EvalSymlinks(scanRoot)
	if err != nil {
		cleanup()
		return "", nil, false, fmt.Errorf("resolve dependency scan root: %w", err)
	}
	return resolvedScanRoot, cleanup, false, nil
}

func collectDependencyPackageDirs(
	root string,
	allowManagedNPMRootPeerLinks bool,
) ([]string, error) {
	queue := []string{root}
	visitedParents := map[string]bool{}
	packageSet := map[string]bool{}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if visitedParents[parent] {
			continue
		}
		visitedParents[parent] = true
		nodeModules := filepath.Join(parent, "node_modules")
		info, err := os.Lstat(nodeModules)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect dependency directory %s: %w", nodeModules, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("dependency directory is not a directory: %s", nodeModules)
		}
		entries, err := os.ReadDir(nodeModules)
		if err != nil {
			return nil, fmt.Errorf("read dependency directory %s: %w", nodeModules, err)
		}
		for _, entry := range entries {
			if entry.Name() == ".bin" {
				continue
			}
			if strings.HasPrefix(entry.Name(), "@") {
				scopePath := filepath.Join(nodeModules, entry.Name())
				scopeEntries, err := os.ReadDir(scopePath)
				if err != nil {
					return nil, fmt.Errorf("read dependency scope %s: %w", scopePath, err)
				}
				for _, scopeEntry := range scopeEntries {
					if err := addDependencyPackage(
						root,
						parent,
						filepath.Join(scopePath, scopeEntry.Name()),
						allowManagedNPMRootPeerLinks,
						packageSet,
						&queue,
					); err != nil {
						return nil, err
					}
				}
				continue
			}
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			if err := addDependencyPackage(
				root,
				parent,
				filepath.Join(nodeModules, entry.Name()),
				allowManagedNPMRootPeerLinks,
				packageSet,
				&queue,
			); err != nil {
				return nil, err
			}
		}
	}
	if len(packageSet) > maxDependencyPackages {
		return nil, fmt.Errorf("dependency-tree contains more than %d packages", maxDependencyPackages)
	}
	packageDirs := make([]string, 0, len(packageSet))
	for packageDir := range packageSet {
		packageDirs = append(packageDirs, packageDir)
	}
	sort.Strings(packageDirs)
	return packageDirs, nil
}

func addDependencyPackage(
	root string,
	parentPackage string,
	candidate string,
	allowManagedNPMRootPeerLinks bool,
	packageSet map[string]bool,
	queue *[]string,
) error {
	candidateInfo, err := os.Lstat(candidate)
	if err != nil {
		return fmt.Errorf("inspect installed dependency %s: %w", candidate, err)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fmt.Errorf("resolve installed dependency %s: %w", candidate, err)
	}
	if !pathWithin(root, resolved) {
		if candidateInfo.Mode()&os.ModeSymlink != 0 &&
			filepath.Base(candidate) == "openclaw" &&
			(parentPackage == root || allowManagedNPMRootPeerLinks) {
			// OpenClaw validates this exact peer link against its trusted host
			// package before invoking the external policy. The host runtime is
			// not third-party dependency code, so it is deliberately omitted.
			return nil
		}
		return fmt.Errorf("installed dependency escapes dependency-tree root: %s", candidate)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("inspect installed dependency %s: %w", candidate, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("installed dependency is not a directory: %s", candidate)
	}
	manifestInfo, err := os.Lstat(filepath.Join(resolved, "package.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() {
		return fmt.Errorf("installed dependency has no regular package.json: %s", candidate)
	}
	if packageSet[resolved] {
		return nil
	}
	packageSet[resolved] = true
	if len(packageSet) > maxDependencyPackages {
		return fmt.Errorf("dependency-tree contains more than %d packages", maxDependencyPackages)
	}
	*queue = append(*queue, resolved)
	return nil
}

func copyDependencyPackage(
	dependencyRoot string,
	source string,
	destination string,
	budget *dependencyCopyBudget,
) error {
	return copyDependencyEntry(
		dependencyRoot,
		source,
		destination,
		budget,
		map[string]bool{},
		false,
	)
}

func copyDependencyEntry(
	dependencyRoot string,
	source string,
	destination string,
	budget *dependencyCopyBudget,
	directoryAncestors map[string]bool,
	countEntry bool,
) error {
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect installed dependency entry %s: %w", source, err)
	}
	if countEntry {
		budget.entries++
		if budget.entries > maxDependencyEntries {
			return fmt.Errorf(
				"dependency-tree scan view exceeds %d filesystem entries",
				maxDependencyEntries,
			)
		}
	}

	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			return fmt.Errorf("resolve installed dependency symlink %s: %w", source, err)
		}
		if !pathWithin(dependencyRoot, resolved) {
			return fmt.Errorf("installed dependency symlink escapes dependency-tree root: %s", source)
		}
		return copyDependencyEntry(
			dependencyRoot,
			resolved,
			destination,
			budget,
			directoryAncestors,
			false,
		)
	}

	if info.IsDir() {
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			return fmt.Errorf("resolve installed dependency directory %s: %w", source, err)
		}
		if !pathWithin(dependencyRoot, resolved) {
			return fmt.Errorf("installed dependency directory escapes dependency-tree root: %s", source)
		}
		if directoryAncestors[resolved] {
			return fmt.Errorf("installed dependency contains a symlink cycle: %s", source)
		}
		directoryAncestors[resolved] = true
		defer delete(directoryAncestors, resolved)
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(resolved)
		if err != nil {
			return fmt.Errorf("read installed dependency %s: %w", resolved, err)
		}
		for _, entry := range entries {
			if entry.Name() == "node_modules" || entry.Name() == ".git" {
				budget.entries++
				if budget.entries > maxDependencyEntries {
					return fmt.Errorf(
						"dependency-tree scan view exceeds %d filesystem entries",
						maxDependencyEntries,
					)
				}
				continue
			}
			if err := copyDependencyEntry(
				dependencyRoot,
				filepath.Join(resolved, entry.Name()),
				filepath.Join(destination, entry.Name()),
				budget,
				directoryAncestors,
				true,
			); err != nil {
				return err
			}
		}
		return nil
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("installed dependency contains a special file: %s", source)
	}
	if info.Size() > maxDependencyFileBytes {
		return fmt.Errorf(
			"dependency file exceeds %d bytes: %s",
			maxDependencyFileBytes,
			source,
		)
	}
	if budget.totalBytes > maxDependencyTotalBytes-info.Size() {
		return fmt.Errorf(
			"dependency-tree scan view exceeds %d total bytes",
			maxDependencyTotalBytes,
		)
	}
	budget.totalBytes += info.Size()
	return copyRegularFile(source, destination, info.Size())
}

func copyRegularFile(source string, destination string, expectedBytes int64) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	copiedBytes, copyErr := io.CopyN(output, input, expectedBytes)
	if errors.Is(copyErr, io.EOF) {
		copyErr = fmt.Errorf("dependency file changed while copying: %s", source)
	}
	if copyErr == nil && copiedBytes != expectedBytes {
		copyErr = fmt.Errorf("dependency file changed while copying: %s", source)
	}
	if copyErr == nil {
		var trailing [1]byte
		if trailingBytes, readErr := input.Read(trailing[:]); readErr != nil && !errors.Is(readErr, io.EOF) {
			copyErr = readErr
		} else if trailingBytes != 0 {
			copyErr = fmt.Errorf("dependency file changed while copying: %s", source)
		}
	}
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func pathWithin(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
