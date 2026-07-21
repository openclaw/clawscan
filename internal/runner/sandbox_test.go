package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
