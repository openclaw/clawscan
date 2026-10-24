package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunOutputRemainsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "SKILL.md")
			output := filepath.Join(root, "result.json")
			if err := os.WriteFile(target, []byte("# Private generated input\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.WriteFile(output, []byte("private previous result"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			artifact, err := Run(Options{Target: target, Scanners: []string{"clawscan-static"}, OutputPath: output}, RunContext{Env: map[string]string{}})
			if err != nil || !artifact.Complete {
				t.Fatalf("run: %+v %v", artifact, err)
			}
			for _, path := range []string{output, filepath.Join(root, filepath.FromSlash(artifact.Scanners["clawscan-static"].OutputPath))} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm()&0o077 != 0 {
					t.Errorf("raw evidence became public: %s mode=%o", path, info.Mode().Perm())
				}
			}
		})
	}
}
