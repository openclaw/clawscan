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
	// End-to-end through dockerCommandRunner: the vanished target neither
	// mounts itself nor its parent.
	parent := t.TempDir()
	missing := filepath.Join(parent, "vanished-skill")
	host := &recordingCommandRunner{stdout: "{}"}
	runner := dockerCommandRunner{Host: host, Env: map[string]string{}, Image: DefaultSandboxImage}
	if _, err := runner.Run("/bin/sh", []string{"-c", `scan "$1"`, "clawscan-target", missing}, "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 {
		t.Fatalf("calls = %d", len(host.calls))
	}
	joined := strings.Join(host.calls[0].args, "\x00")
	if strings.Contains(joined, "source="+parent) || strings.Contains(joined, "source="+missing) {
		t.Fatalf("vanished target leaked a host mount: %#v", host.calls[0].args)
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
