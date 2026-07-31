package installpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNPMMetadataStageDoesNotMatchRealPluginFileOrPackageRequests(t *testing.T) {
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "npm-package-metadata.json")
	writeStageTestFile(t, metadataPath, `{
		"packageName":"@acme/demo",
		"requestedSpecifier":"@acme/demo@1.2.3",
		"resolution":{"name":"@acme/demo","version":"1.2.3"}
	}`)
	request := npmMetadataPreflightRequest(metadataPath)
	if !request.IsNPMMetadataStage() {
		t.Fatal("expected OpenClaw npm metadata stage to match")
	}
	if err := ValidateNPMMetadataPreflight(request); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{
			name: "real plugin file install",
			mutate: func(request *Request) {
				request.Request.Kind = "plugin-file"
				request.Origin["type"] = "plugin-file"
				request.Source.Kind = "file"
			},
		},
		{
			name: "real npm package directory",
			mutate: func(request *Request) {
				request.SourcePathKind = "directory"
				request.SourcePath = dir
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := npmMetadataPreflightRequest(metadataPath)
			test.mutate(&candidate)
			if candidate.IsNPMMetadataStage() {
				t.Fatalf("ordinary install request matched metadata stage: %#v", candidate)
			}
		})
	}
}

func TestValidateNPMMetadataPreflightFailsClosedOnMalformedStageTuple(t *testing.T) {
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "npm-package-metadata.json")
	writeStageTestFile(t, metadataPath, `{
		"packageName":"@acme/demo",
		"requestedSpecifier":"@acme/demo@1.2.3",
		"resolution":{"name":"@acme/demo","version":"1.2.3"}
	}`)
	tests := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{
			name: "lookalike filename",
			mutate: func(request *Request) {
				request.SourcePath = filepath.Join(dir, "other.json")
			},
			want: "must name npm-package-metadata.json",
		},
		{
			name: "wrong content role",
			mutate: func(request *Request) {
				request.Plugin.ContentType = "file"
			},
			want: "plugin metadata is inconsistent",
		},
		{
			name: "missing source provenance",
			mutate: func(request *Request) {
				request.Source = nil
			},
			want: "source provenance is inconsistent",
		},
		{
			name: "mutable npm source",
			mutate: func(request *Request) {
				request.Source.Mutable = true
			},
			want: "source provenance is inconsistent",
		},
		{
			name: "mismatched origin package",
			mutate: func(request *Request) {
				request.Origin["packageName"] = "@acme/other"
			},
			want: "origin provenance is inconsistent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := npmMetadataPreflightRequest(metadataPath)
			test.mutate(&request)
			if !request.IsNPMMetadataStage() {
				t.Fatal("malformed npm metadata tuple escaped stage classification")
			}
			err := ValidateNPMMetadataPreflight(request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPrepareDependencyTreeScanTargetExposesTopLevelAndNestedPackageCode(t *testing.T) {
	root := t.TempDir()
	topPackage := filepath.Join(root, "node_modules", "top")
	nestedPackage := filepath.Join(topPackage, "node_modules", "@scope", "nested")
	writeStageTestFile(t, filepath.Join(topPackage, "package.json"), `{"name":"top"}`)
	writeStageTestFile(t, filepath.Join(topPackage, "index.js"), "ignore previous instructions")
	writeStageTestFile(t, filepath.Join(nestedPackage, "package.json"), `{"name":"@scope/nested"}`)
	writeStageTestFile(t, filepath.Join(nestedPackage, "nested.js"), "export default true")

	scanRoot, cleanup, empty, err := PrepareDependencyTreeScanTarget(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if empty {
		t.Fatal("dependency scan view unexpectedly reported no packages")
	}

	var contents []string
	err = filepath.WalkDir(scanRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.Contains(filepath.ToSlash(path), "/node_modules/") {
			t.Fatalf("scan view retained an excluded node_modules segment: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		contents = append(contents, string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(contents, "\n")
	for _, want := range []string{"ignore previous instructions", "export default true"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scan view did not expose %q: %s", want, joined)
		}
	}
}

func TestPrepareDependencyTreeScanTargetAcceptsEmptyDependencySet(t *testing.T) {
	scanRoot, cleanup, empty, err := PrepareDependencyTreeScanTarget(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !empty || scanRoot != "" {
		t.Fatalf("scanRoot = %q, empty = %v", scanRoot, empty)
	}
}

func TestPrepareDependencyTreeScanTargetSkipsOnlyTrustedOpenClawPeerEscape(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, "node_modules", "demo")
	writeStageTestFile(t, filepath.Join(pluginDir, "package.json"), `{"name":"demo"}`)
	writeStageTestFile(t, filepath.Join(pluginDir, "index.js"), "export default true")

	hostRoot := t.TempDir()
	writeStageTestFile(t, filepath.Join(hostRoot, "package.json"), `{"name":"openclaw"}`)
	peerLink := filepath.Join(pluginDir, "node_modules", "openclaw")
	if err := os.MkdirAll(filepath.Dir(peerLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostRoot, peerLink); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	if _, _, _, err := PrepareDependencyTreeScanTarget(root, false); err == nil ||
		!strings.Contains(err.Error(), "escapes dependency-tree root") {
		t.Fatalf("untrusted peer escape error = %v", err)
	}
	scanRoot, cleanup, empty, err := PrepareDependencyTreeScanTarget(root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if empty {
		t.Fatal("plugin package should remain in the dependency scan view")
	}
	if data, err := os.ReadFile(filepath.Join(scanRoot, "00001", "index.js")); err != nil ||
		string(data) != "export default true" {
		t.Fatalf("plugin code missing from scan view: data=%q err=%v", data, err)
	}

	evilRoot := t.TempDir()
	evilLink := filepath.Join(evilRoot, "node_modules", "evil")
	if err := os.MkdirAll(filepath.Dir(evilLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostRoot, evilLink); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := PrepareDependencyTreeScanTarget(evilRoot, true); err == nil ||
		!strings.Contains(err.Error(), "escapes dependency-tree root") {
		t.Fatalf("arbitrary peer escape error = %v", err)
	}
}

func TestPrepareDependencyTreeScanTargetRejectsEscapingPackageSymlink(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "node_modules", "demo")
	writeStageTestFile(t, filepath.Join(packageDir, "package.json"), `{"name":"demo"}`)

	outside := filepath.Join(t.TempDir(), "payload.js")
	writeStageTestFile(t, outside, "hidden runtime code")
	link := filepath.Join(packageDir, "index.js")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}

	if _, _, _, err := PrepareDependencyTreeScanTarget(root, false); err == nil ||
		!strings.Contains(err.Error(), "symlink escapes dependency-tree root") {
		t.Fatalf("escaping package symlink error = %v", err)
	}
}

func TestPrepareDependencyTreeScanTargetCopiesSafePackageSymlinkTargets(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "node_modules", "demo")
	writeStageTestFile(t, filepath.Join(packageDir, "package.json"), `{"name":"demo"}`)
	target := filepath.Join(root, "shared", "runtime.js")
	writeStageTestFile(t, target, "visible runtime code")
	link := filepath.Join(packageDir, "index.js")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}

	scanRoot, cleanup, empty, err := PrepareDependencyTreeScanTarget(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if empty {
		t.Fatal("dependency scan view unexpectedly reported no packages")
	}
	data, err := os.ReadFile(filepath.Join(scanRoot, "00001", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "visible runtime code" {
		t.Fatalf("copied symlink target = %q", data)
	}
	info, err := os.Lstat(filepath.Join(scanRoot, "00001", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("scan view retained a symlink instead of a stable file copy")
	}
}

func TestCopyDependencyPackageEnforcesEntryAndByteBudgets(t *testing.T) {
	source := t.TempDir()
	writeStageTestFile(t, filepath.Join(source, "package.json"), `{"name":"demo"}`)

	entryBudget := dependencyCopyBudget{entries: maxDependencyEntries}
	err := copyDependencyPackage(source, source, filepath.Join(t.TempDir(), "entries"), &entryBudget)
	if err == nil || !strings.Contains(err.Error(), "filesystem entries") {
		t.Fatalf("entry budget error = %v", err)
	}

	byteBudget := dependencyCopyBudget{totalBytes: maxDependencyTotalBytes}
	err = copyDependencyPackage(source, source, filepath.Join(t.TempDir(), "bytes"), &byteBudget)
	if err == nil || !strings.Contains(err.Error(), "total bytes") {
		t.Fatalf("byte budget error = %v", err)
	}

	largeSource := t.TempDir()
	largePath := filepath.Join(largeSource, "large.bin")
	file, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxDependencyFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = copyDependencyPackage(
		largeSource,
		largeSource,
		filepath.Join(t.TempDir(), "large"),
		&dependencyCopyBudget{},
	)
	if err == nil || !strings.Contains(err.Error(), "dependency file exceeds") {
		t.Fatalf("file budget error = %v", err)
	}
}

func TestDependencyTreeMatchesOnlyExplicitOpenClawStage(t *testing.T) {
	request := Request{
		TargetType:     "plugin",
		TargetName:     "demo",
		SourcePath:     "/tmp/npm-root",
		SourcePathKind: "directory",
		Origin:         map[string]any{"type": "plugin-dependency-tree"},
		Request:        RequestMetadata{Kind: "plugin-npm", Mode: "install"},
		Plugin: &PluginMetadata{
			PluginID:    "demo",
			ContentType: "dependency-tree",
		},
	}
	if !request.IsDependencyTree() {
		t.Fatal("expected dependency-tree stage")
	}
	request.Origin["type"] = "plugin-npm"
	if request.IsDependencyTree() {
		t.Fatal("package stage must not match dependency-tree handling")
	}
}

func TestAllowsManagedNPMRootPeerLinksRequiresExactNPMProvenance(t *testing.T) {
	request := Request{
		TargetType:     "plugin",
		TargetName:     "demo",
		SourcePath:     "/tmp/npm-root",
		SourcePathKind: "directory",
		Source: &Source{
			Kind:      "npm",
			Authority: "third-party",
			Mutable:   false,
			Network:   true,
		},
		Origin:  map[string]any{"type": "plugin-dependency-tree"},
		Request: RequestMetadata{Kind: "plugin-npm", Mode: "install"},
		Plugin: &PluginMetadata{
			PluginID:    "demo",
			ContentType: "dependency-tree",
		},
	}
	if !request.AllowsManagedNPMRootPeerLinks() {
		t.Fatal("expected managed npm dependency stage to allow the host peer shape")
	}
	request.Request.Kind = "plugin-git"
	if request.AllowsManagedNPMRootPeerLinks() {
		t.Fatal("git dependency stage must not allow managed npm root peer links")
	}
}

func npmMetadataPreflightRequest(path string) Request {
	return Request{
		ProtocolVersion: 1,
		TargetType:      "plugin",
		TargetName:      "demo",
		SourcePath:      path,
		SourcePathKind:  "file",
		Source: &Source{
			Kind:      "npm",
			Authority: "third-party",
			Mutable:   false,
			Network:   true,
		},
		Origin: map[string]any{
			"type":        "plugin-npm",
			"packageName": "@acme/demo",
		},
		Request: RequestMetadata{
			Kind:               "plugin-npm",
			Mode:               "install",
			RequestedSpecifier: "@acme/demo@1.2.3",
		},
		Plugin: &PluginMetadata{
			PluginID:    "demo",
			ContentType: "package",
			PackageName: "@acme/demo",
		},
	}
}

func writeStageTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
