package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMountInferenceArgsExcludesRenderedShellProgram(t *testing.T) {
	// A user-defined scanner reaches docker as: /bin/sh -c '<rendered program>'
	// clawscan-target <target>. The rendered program starts with an absolute
	// executable path but is not a mountable path; inferring a mount from it
	// would bind /usr/bin (or similar) writable into the container.
	program := `/usr/bin/scanner --json "$1"`
	target := t.TempDir()
	mounts := dockerMounts("", mountInferenceArgs("/bin/sh", []string{"-c", program, "clawscan-target", target}))
	for _, mount := range mounts {
		if strings.Contains(mount, "/usr/bin") {
			t.Fatalf("rendered shell program produced a host mount: %q", mount)
		}
	}
	found := false
	for _, mount := range mounts {
		if strings.Contains(mount, "source="+target+",") && strings.HasSuffix(mount, ",readonly") {
			found = true
		}
	}
	if !found {
		t.Fatalf("target %q should still be mounted readonly; mounts = %v", target, mounts)
	}
}

func TestMountInferenceArgsKeepsNonShellArgs(t *testing.T) {
	args := []string{"scan", "/data/skill", "--output", "/data/out.json"}
	got := mountInferenceArgs("cisco-skill-scanner", args)
	if strings.Join(got, " ") != strings.Join(args, " ") {
		t.Fatalf("non-shell args changed: %v", got)
	}
}

func TestDockerMountsNeverMountsParentOfMissingScanTarget(t *testing.T) {
	// TOCTOU guard: if the scan target vanishes between the scanner's own
	// existence check and mount time, the writable-parent fallback would
	// bind the surrounding host directory read-write into the container.
	// Scan targets must fail closed: missing means no mount at all.
	parent := t.TempDir()
	missing := filepath.Join(parent, "vanished-skill")
	mounts := dockerMounts("", nil, missing)
	if len(mounts) != 0 {
		t.Fatalf("missing scan target produced mounts: %v", mounts)
	}
}

func TestDockerMountsMountsExistingScanTargetReadonly(t *testing.T) {
	target := t.TempDir()
	mounts := dockerMounts("", nil, target)
	if len(mounts) != 1 || !strings.Contains(mounts[0], "source="+target+",") || !strings.HasSuffix(mounts[0], ",readonly") {
		t.Fatalf("existing scan target should mount readonly: %v", mounts)
	}
}

func TestDockerMountsQuotesCommaPaths(t *testing.T) {
	// Docker parses --mount as CSV: an unquoted comma in a path splits the
	// spec into a bogus extra field and Docker rejects the invocation.
	parent := t.TempDir()
	target := filepath.Join(parent, "skills, reviewed")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := dockerMounts("", nil, target)
	if len(mounts) != 1 {
		t.Fatalf("mounts = %v", mounts)
	}
	want := `type=bind,"source=` + target + `","target=` + target + `",readonly`
	if mounts[0] != want {
		t.Fatalf("mount = %q, want %q", mounts[0], want)
	}
}

func TestDockerMountFieldQuoting(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"source", "/skills/demo", "source=/skills/demo"},
		{"source", "/skills/a,b", `"source=/skills/a,b"`},
		{"source", `/skills/say "hi"`, `"source=/skills/say ""hi"""`},
		// CR and LF are valid in POSIX path components and terminate a CSV
		// record when unquoted, truncating the mount spec.
		{"source", "/skills/a\nb", "\"source=/skills/a\nb\""},
		{"source", "/skills/a\rb", "\"source=/skills/a\rb\""},
	} {
		if got := dockerMountField(test.key, test.value); got != test.want {
			t.Fatalf("dockerMountField(%q, %q) = %q, want %q", test.key, test.value, got, test.want)
		}
	}
}

func TestPositionalScannerTargetExtraction(t *testing.T) {
	target := "/skills/demo"
	if got := positionalScannerTarget("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", target}); got != target {
		t.Fatalf("got %q, want %q", got, target)
	}
	if got := positionalScannerTarget("/bin/sh", []string{"-c", "judge-prompt"}); got != "" {
		t.Fatalf("judge-style invocation must have no positional target, got %q", got)
	}
	if got := positionalScannerTarget("scanner", []string{"clawscan-target", target}); got != "" {
		t.Fatalf("non-shell command must have no positional target, got %q", got)
	}
}

func TestDockerRunFailsClosedWhenScannerTargetVanishes(t *testing.T) {
	// A target that vanished between the adapter's existence check and
	// sandbox start must abort before the container runs: with no mount,
	// image content at the same absolute path would be scanned and
	// reported as the host target.
	parent := t.TempDir()
	missing := filepath.Join(parent, "vanished-skill")
	host := &recordingCommandRunner{stdout: "{}"}
	runner := dockerCommandRunner{Host: host, Env: map[string]string{}, Image: DefaultSandboxImage}
	_, err := runner.Run("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", missing}, "", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "scan target vanished") {
		t.Fatalf("err = %v, want vanished-target refusal", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("container ran despite vanished target: %#v", host.calls)
	}
}

func TestDockerRunPinsSymlinkTargetToPhysicalPath(t *testing.T) {
	// A symlink target is resolved to its physical path before mounting,
	// so a link swapped after validation redirects nothing — the bind
	// source is already the real directory — and the scanner is handed the
	// resolved path.
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link-to-skill")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	host := &recordingCommandRunner{stdout: "{}"}
	runner := dockerCommandRunner{Host: host, Env: map[string]string{}, Image: DefaultSandboxImage}
	if _, err := runner.Run("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", link}, "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 {
		t.Fatalf("calls = %d", len(host.calls))
	}
	args := host.calls[0].args
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, "source="+link+",") {
		t.Fatalf("symlink spelling used as mount source: %#v", args)
	}
	if !strings.Contains(joined, "source="+real+",") {
		t.Fatalf("physical path not mounted: %#v", args)
	}
	if args[len(args)-1] != real {
		t.Fatalf("positional target not rewritten to physical path: %#v", args)
	}
}

func TestDockerRunTranslatesWindowsTargetToContainerPath(t *testing.T) {
	// A Windows host path is not absolute inside the Linux runtime image;
	// the target must be mounted at a stable POSIX path and the scanner
	// handed that path instead. Use a real (POSIX) path with GOOS forced to
	// windows so the stat succeeds while exercising the translation branch.
	// Pre-resolve symlinks (macOS /var -> /private/var) so the runner's
	// physical-path pinning does not change the spelling under test.
	target, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	host := &recordingCommandRunner{stdout: "{}"}
	runner := dockerCommandRunner{Host: host, Env: map[string]string{}, Image: DefaultSandboxImage, GOOS: "windows"}
	if _, err := runner.Run("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", target}, "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 {
		t.Fatalf("calls = %d", len(host.calls))
	}
	args := host.calls[0].args
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "type=bind,source="+target+",target="+windowsScanTargetContainerPath+",readonly") {
		t.Fatalf("windows target not mounted at container path: %#v", args)
	}
	if args[len(args)-1] != windowsScanTargetContainerPath {
		t.Fatalf("positional target not rewritten to container path: %#v", args)
	}
	if strings.Contains(joined, "target="+target+",") {
		t.Fatalf("host path leaked as a mount destination: %#v", args)
	}
}

func TestDockerRunWindowsMissingTargetFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "vanished-skill")
	host := &recordingCommandRunner{stdout: "{}"}
	runner := dockerCommandRunner{Host: host, Env: map[string]string{}, Image: DefaultSandboxImage, GOOS: "windows"}
	_, err := runner.Run("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", missing}, "", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "scan target vanished") {
		t.Fatalf("err = %v, want vanished-target refusal", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("container ran despite vanished target: %#v", host.calls)
	}
}

func TestDefaultCommandRunnerSuppressesExitCodeOnTimeout(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	// A timed-out process has no exit verdict. Windows TerminateProcess
	// reports exit code 1 — indistinguishable from findings-mean-nonzero —
	// so the runner must not record any code when the deadline fired.
	// exec so the sleep is the killed process itself; a forked child would
	// hold the stdout pipe open for the full 5s after the kill.
	output, err := defaultCommandRunner{}.Run("/bin/sh", []string{"-c", "echo '{}'; exec sleep 5"}, "", 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if output.ExitCode != nil {
		t.Fatalf("timed-out command recorded exit code %d; partial output could pass as a completed scan", *output.ExitCode)
	}
}

func TestDefaultCommandRunnerTimeoutKillsProcessTree(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	// A forked grandchild (`sleep 30 &`) inherits the stdout pipe. Killing
	// only the direct shell would leave the pipe open and block Run for
	// the grandchild's full lifetime; the process-group kill must reach it.
	start := time.Now()
	_, err := defaultCommandRunner{}.Run("/bin/sh", []string{"-c", "echo '{}'; sleep 30 & wait"}, "", 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	// Must beat the 10s WaitDelay backstop: a group kill that missed the
	// grandchild would only return once WaitDelay force-closes the pipes.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timed-out command with forked child blocked for %s; process tree was not killed", elapsed)
	}
}

func TestDefaultCommandRunnerRecordsNormalExitCodes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	output, err := defaultCommandRunner{}.Run("/bin/sh", []string{"-c", "exit 3"}, "", time.Minute)
	if err == nil {
		t.Fatal("expected exit error")
	}
	if output.ExitCode == nil || *output.ExitCode != 3 {
		t.Fatalf("exit code = %v, want 3", output.ExitCode)
	}
}

func TestDockerMountsStillMountsSpacedMissingOutputPaths(t *testing.T) {
	// A not-yet-created output file under a spaced TMPDIR must still get its
	// parent mounted writable, or Docker scanners cannot write their reports.
	parent := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(parent, "report.json")
	mounts := dockerMounts("", []string{missing})
	found := false
	for _, mount := range mounts {
		if strings.Contains(mount, "source="+parent+",") && !strings.HasSuffix(mount, ",readonly") {
			found = true
		}
	}
	if !found {
		t.Fatalf("spaced parent %q should be mounted writable; mounts = %v", parent, mounts)
	}
}
