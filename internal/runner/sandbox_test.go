package runner

import (
	"strings"
	"testing"
)

func TestDockerMountsSkipsRenderedShellPrograms(t *testing.T) {
	// A user-defined scanner reaches docker as: /bin/sh -c '<rendered program>'
	// clawscan-target <target>. The rendered program starts with an absolute
	// executable path but is not a mountable path; inferring a mount from it
	// would bind /usr/bin (or similar) writable into the container.
	program := `/usr/bin/scanner --json "$1"`
	target := t.TempDir()
	mounts := dockerMounts("", []string{"-c", program, "clawscan-target", target})
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

func TestDockerMountsSkipsQuotedAndSpacedArgs(t *testing.T) {
	for _, arg := range []string{
		`/opt/tool "$1"`,
		"/opt/tool\t--flag",
		`/opt/'tool'`,
		`/opt/"tool"`,
		"/opt/tool\n--flag",
	} {
		if mounts := dockerMounts("", []string{arg}); len(mounts) != 0 {
			t.Fatalf("arg %q produced mounts %v, want none", arg, mounts)
		}
	}
}
