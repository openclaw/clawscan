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

// stubCodexScript stands in for the Codex CLI used by profile overview
// commands. It fails unless a test opts in with CLAWSCAN_TEST_OVERVIEW_JSON, so
// no test can reach a real model through a built-in profile.
const stubCodexScript = `#!/bin/sh
out=""
workspace=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-last-message) out="$2"; shift 2 ;;
    --cd) workspace="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$CLAWSCAN_TEST_OVERVIEW_PROMPT" ]; then
  cat > "$CLAWSCAN_TEST_OVERVIEW_PROMPT"
else
  cat > /dev/null
fi
if [ -n "$CLAWSCAN_TEST_OVERVIEW_JUDGE" ] && [ -n "$workspace" ]; then
  cp "$workspace/judge.json" "$CLAWSCAN_TEST_OVERVIEW_JUDGE"
fi
if [ -n "$CLAWSCAN_TEST_OVERVIEW_JSON" ] && [ -n "$out" ]; then
  printf '%s\n' "$CLAWSCAN_TEST_OVERVIEW_JSON" > "$out"
  exit 0
fi
echo "stub codex: overview disabled in tests" >&2
exit 1
`

// installDecisionsJudgeShim puts the repository's Decisions judge on PATH as
// clawscan-decisions-judge, the name the runtime image installs.
func installDecisionsJudgeShim(dir string) error {
	source, err := filepath.Abs(filepath.Join("..", "..", "docker", "clawscan-runtime", "judges", "clawscan_decisions_judge.py"))
	if err != nil {
		return err
	}
	shim := "#!/bin/sh\nexec python3 '" + source + "' \"$@\"\n"
	return os.WriteFile(filepath.Join(dir, "clawscan-decisions-judge"), []byte(shim), 0o755)
}

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
		// Profile overview commands call codex; tests never reach a real model.
		if err := os.WriteFile(filepath.Join(dir, "codex"), []byte(stubCodexScript), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := installDecisionsJudgeShim(dir); err != nil {
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
