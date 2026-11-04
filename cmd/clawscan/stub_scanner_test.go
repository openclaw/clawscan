package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// stubSkillSpectorScript is an inert stand-in for the SkillSpector CLI. It uses
// only shell builtins because ClawScan runs scanner commands with the run's
// explicit environment, which may have no PATH. It reads the copied artifact,
// records the files it saw, and reports an instruction-override phrase as a
// HIGH finding, so CLI tests exercise a real scanner subprocess at the
// `clawscan <target>` seam without network, credentials, or Docker.
const stubSkillSpectorScript = `#!/bin/sh
out=""
target=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    scan) target="$2"; shift 2 ;;
    --output) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
files=""
status="clean"
findings=""
scan_file() {
  rel="${1#"$target"/}"
  files="$files${files:+,}\"$rel\""
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *"gnore previous instructions"*)
        status="suspicious"
        findings="$findings${findings:+,}{\"id\":\"stub.prompt_injection\",\"severity\":\"HIGH\",\"file\":\"$rel\"}"
        ;;
    esac
  done < "$1"
}
for path in "$target" "$target"/* "$target"/*/* "$target"/*/*/* "$target"/.[!.]* "$target"/*/.[!.]*; do
  [ -f "$path" ] && scan_file "$path"
done
printf '{"status":"%s","files":[%s],"findings":[%s]}\n' "$status" "$files" "$findings" > "$out"
`

func TestMain(m *testing.M) {
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("", "clawscan-stub-scanners-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(dir, "skillspector"), []byte(stubSkillSpectorScript), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		code := m.Run()
		os.RemoveAll(dir)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
