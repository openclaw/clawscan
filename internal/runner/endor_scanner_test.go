package runner

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const endorFindingsJSON = `{
  "all_findings": [{
    "spec": {
      "finding_tags": ["FINDING_TAGS_POTENTIALLY_REACHABLE_DEPENDENCY", "FINDING_TAGS_POTENTIALLY_REACHABLE_FUNCTION"]
    }
  }],
  "blocking_findings": [],
  "warning_findings": []
}
`

const endorLinuxMixedOwnerSetup = `set -eu
mkdir -p /tmp/source /tmp/plugin /tmp/unrelated /tmp/bin
printf '%s\n' '{"name":"demo"}' > /tmp/source/package.json
printf '%s\n' 'export const demo = true' > /tmp/source/index.ts
cp -R /tmp/source/. /tmp/plugin/
git -C /tmp/unrelated init -q -b main
chown -R 1000:1000 /tmp/source /tmp/plugin /tmp/unrelated
cat > /tmp/bin/endorctl <<'EOF'
#!/bin/sh
set -eu
test "$(id -u)" = 0
test "$(stat -c %u "$9")" = 1000
git -C "$9" status --short >/dev/null
if unrelated_error=$(git -C "$ENDOR_UNRELATED_REPO" status --short 2>&1); then
	echo "unrelated repository was unexpectedly trusted" >&2
	exit 1
fi
case "$unrelated_error" in
	*"dubious ownership"*) ;;
	*)
		echo "unrelated repository failed for the wrong reason: $unrelated_error" >&2
		exit 1
		;;
esac
test ! -e "$ENDOR_SOURCE_REPO/.git"
test "$(cat "$ENDOR_SOURCE_REPO/package.json")" = '{"name":"demo"}'
printf '%s\n' '{"all_findings":[],"blocking_findings":[],"warning_findings":[]}'
EOF
chmod 755 /tmp/bin/endorctl
export PATH="/tmp/bin:$PATH"
export ENDOR_SOURCE_REPO=/tmp/source
export ENDOR_UNRELATED_REPO=/tmp/unrelated
exec /bin/sh -c "$1" clawscan-endor /tmp/plugin
`

func TestEndorRequirementsAcceptTokenOrAPICredentials(t *testing.T) {
	opts, err := ParseArgs([]string{"./plugin", "--scanner", "endor"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		env  map[string]string
	}{
		{name: "token", env: map[string]string{"ENDOR_NAMESPACE": "demo", "ENDOR_TOKEN": "token"}},
		{name: "API credentials", env: map[string]string{
			"ENDOR_NAMESPACE":              "demo",
			"ENDOR_API_CREDENTIALS_KEY":    "key",
			"ENDOR_API_CREDENTIALS_SECRET": "secret",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRequirements(opts, test.env); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEndorRequirementsRejectMissingOrIncompleteCredentials(t *testing.T) {
	opts, err := ParseArgs([]string{"./plugin", "--scanner", "endor"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "namespace", env: map[string]string{"ENDOR_TOKEN": "token"}, want: "ENDOR_NAMESPACE"},
		{name: "credentials", env: map[string]string{"ENDOR_NAMESPACE": "demo"}, want: "ENDOR_TOKEN"},
		{name: "API secret", env: map[string]string{"ENDOR_NAMESPACE": "demo", "ENDOR_API_CREDENTIALS_KEY": "key"}, want: "ENDOR_API_CREDENTIALS_SECRET"},
		{name: "API key", env: map[string]string{"ENDOR_NAMESPACE": "demo", "ENDOR_API_CREDENTIALS_SECRET": "secret"}, want: "ENDOR_API_CREDENTIALS_KEY"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRequirements(opts, test.env)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want missing %s", err, test.want)
			}
		})
	}
}

func TestEndorScansPluginFromWritableScratchAndPreservesSource(t *testing.T) {
	target := createEndorTarget(t, true)
	commandRunner := &endorRecordingCommandRunner{
		stdout: endorFindingsJSON,
		inspect: func(call commandCall) {
			if call.command != "/bin/sh" {
				t.Fatalf("command = %q", call.command)
			}
			if call.cwd == target || !strings.HasSuffix(call.cwd, string(filepath.Separator)+"artifact") {
				t.Fatalf("cwd = %q, target = %q", call.cwd, target)
			}
			if len(call.args) != 4 || call.args[0] != "-c" || call.args[2] != "clawscan-endor" || call.args[3] != "." {
				t.Fatalf("args = %#v", call.args)
			}
			script := call.args[1]
			for _, fragment := range []string{
				"NPM_CONFIG_IGNORE_SCRIPTS=true",
				"core.hooksPath=/dev/null",
				"user.name=ClawScan",
				"user.email=clawscan@example.invalid",
				"endorctl scan --dry-run --dependencies",
				"--languages=javascript,typescript",
				"--call-graph-languages=javascript,typescript",
				"--build=false --output-type=json",
				`--path "$1"`,
			} {
				if !strings.Contains(script, fragment) {
					t.Fatalf("script missing %q:\n%s", fragment, script)
				}
			}
			for _, name := range []string{"package.json", "npm-shrinkwrap.json", pluginManifestName, "index.ts"} {
				if _, err := os.Stat(filepath.Join(call.cwd, name)); err != nil {
					t.Fatalf("scratch missing %s: %v", name, err)
				}
			}
			if err := os.WriteFile(filepath.Join(call.cwd, "endor-created.lock"), []byte("scratch"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	runner := ExternalScannerRunner{
		CommandRunner: commandRunner,
		Env: map[string]string{
			"ENDOR_NAMESPACE": "demo",
			"ENDOR_TOKEN":     "secret-token",
		},
		SandboxMode: SandboxModeDocker,
	}
	result, err := runner.runEndor(target, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	if !bytes.Equal(result.Raw, []byte(endorFindingsJSON)) {
		t.Fatalf("raw report changed:\n%s", result.Raw)
	}
	if bytes.Contains(result.Raw, []byte("secret-token")) {
		t.Fatalf("raw report leaked token: %s", result.Raw)
	}
	if _, err := os.Stat(filepath.Join(target, "endor-created.lock")); !os.IsNotExist(err) {
		t.Fatalf("source target was modified: %v", err)
	}
	if got := readTestFile(t, filepath.Join(target, "package.json")); got != "{\"name\":\"demo\"}\n" {
		t.Fatalf("source package.json changed: %q", got)
	}
	if got := readTestFile(t, filepath.Join(target, "npm-shrinkwrap.json")); got != "{\"lockfileVersion\":3}\n" {
		t.Fatalf("source npm-shrinkwrap.json changed: %q", got)
	}
}

func TestEndorShellBootstrapCreatesDetachedOrigin(t *testing.T) {
	target := createEndorTarget(t, true)
	binDir := t.TempDir()
	fakeEndor := filepath.Join(binDir, "endorctl")
	fakeScript := `#!/bin/sh
set -eu
test "$(git config --get remote.origin.url)" = "https://example.invalid/clawscan/scan-target.git"
test "$(git config --get core.hooksPath)" = "/dev/null"
test "$(git log -1 --pretty=%an)" = "ClawScan"
test "$(git log -1 --pretty=%ae)" = "clawscan@example.invalid"
test "$#" -eq 9
test "$1" = "scan"
test "$2" = "--dry-run"
test "$3" = "--dependencies"
test "$4" = "--languages=javascript,typescript"
test "$5" = "--call-graph-languages=javascript,typescript"
test "$6" = "--build=false"
test "$7" = "--output-type=json"
test "$8" = "--path"
test "$9" = "."
printf '%s\n' '{"all_findings":[],"blocking_findings":[],"warning_findings":[]}'
`
	if err := os.WriteFile(fakeEndor, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	env := EnvMap(os.Environ())
	env["PATH"] = binDir + string(os.PathListSeparator) + env["PATH"]
	result, err := (ExternalScannerRunner{
		CommandRunner: defaultCommandRunner{Env: env},
		Env:           env,
		SandboxMode:   SandboxModeDocker,
	}).runEndor(target, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(target, ".git")); !os.IsNotExist(err) {
		t.Fatalf("source target gained git metadata: %v", err)
	}
}

func TestEndorShellBootstrapTrustsOnlyMixedOwnerScratchOnLinux(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("CLAWSCAN_TEST_ENDOR_DOCKER_IMAGE"))
	if image == "" {
		t.Skip("set CLAWSCAN_TEST_ENDOR_DOCKER_IMAGE to a Linux Endor image")
	}
	if err := dockerAvailable(); err != nil {
		t.Fatal(err)
	}

	env := EnvMap(os.Environ())
	output, err := (defaultCommandRunner{Env: env}).Run("docker", []string{
		"run", "--rm",
		"--platform", "linux/amd64",
		"--network", "none",
		image,
		"/bin/sh", "-c", endorLinuxMixedOwnerSetup, "clawscan-endor-linux-test", endorScanScript,
	}, "", 2*time.Minute)
	if err != nil {
		t.Fatalf("Linux mixed-owner bootstrap failed: %v\nstderr:\n%s", err, output.Stderr)
	}
	if got := strings.TrimSpace(output.Stdout); got != `{"all_findings":[],"blocking_findings":[],"warning_findings":[]}` {
		t.Fatalf("stdout = %q, stderr = %q", output.Stdout, output.Stderr)
	}
}

func TestEndorDockerRunMountsOnlyWritableScratch(t *testing.T) {
	target := createEndorTarget(t, true)
	hostRunner := &endorRecordingCommandRunner{
		stdout: endorFindingsJSON,
		inspect: func(call commandCall) {
			if call.command != "docker" {
				t.Fatalf("command = %q", call.command)
			}
			var mounts []string
			var cwd string
			for index, arg := range call.args {
				switch arg {
				case "--mount":
					if index+1 < len(call.args) {
						mounts = append(mounts, call.args[index+1])
					}
				case "-w":
					if index+1 < len(call.args) {
						cwd = call.args[index+1]
					}
				}
			}
			if len(mounts) != 1 || strings.Contains(mounts[0], "readonly") {
				t.Fatalf("mounts = %#v", mounts)
			}
			if strings.Contains(mounts[0], target) {
				t.Fatalf("source target was mounted: %s", mounts[0])
			}
			if cwd == "" || !strings.Contains(mounts[0], "source="+cwd+",") || !strings.Contains(mounts[0], "target="+cwd) {
				t.Fatalf("cwd = %q mounts = %#v", cwd, mounts)
			}
			if call.args[len(call.args)-1] != "." {
				t.Fatalf("container target = %q", call.args[len(call.args)-1])
			}
		},
	}
	commandRunner := dockerCommandRunner{
		Host:  hostRunner,
		Env:   map[string]string{"ENDOR_NAMESPACE": "demo", "ENDOR_TOKEN": "token"},
		Image: "clawscan-endor:test",
		EnvNames: []string{
			"ENDOR_NAMESPACE",
			"ENDOR_TOKEN",
		},
	}
	result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeDocker}).runEndor(target, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
}

func TestEndorExplicitManifestScansItsDirectory(t *testing.T) {
	target := createEndorTarget(t, false)
	manifest := filepath.Join(target, skillManifestName)
	commandRunner := &endorRecordingCommandRunner{
		stdout: endorFindingsJSON,
		inspect: func(call commandCall) {
			if _, err := os.Stat(filepath.Join(call.cwd, skillManifestName)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(call.cwd, "package.json")); err != nil {
				t.Fatal(err)
			}
		},
	}
	result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeDocker}).runEndor(manifest, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
}

func TestEndorSkipsUnsupportedTargets(t *testing.T) {
	noPackage := t.TempDir()
	if err := os.WriteFile(filepath.Join(noPackage, "index.js"), []byte("export {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commandRunner := &endorRecordingCommandRunner{stdout: endorFindingsJSON}
	for _, test := range []struct {
		name   string
		target string
		want   string
	}{
		{name: "URL", target: "https://example.com/plugin", want: "URL targets are unsupported"},
		{name: "no root package", target: noPackage, want: "requires package.json at the target root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeDocker}).runEndor(test.target, "2026-09-15T00:00:00Z")
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "skipped" || !strings.Contains(result.Error, test.want) {
				t.Fatalf("result = %#v", result)
			}
		})
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("unexpected commands = %#v", commandRunner.calls)
	}
}

func TestEndorRequiresDockerBeforeRunningCommand(t *testing.T) {
	target := createEndorTarget(t, false)
	commandRunner := &endorRecordingCommandRunner{stdout: endorFindingsJSON}
	result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeOff}).runEndor(target, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "requires the Docker sandbox") {
		t.Fatalf("result = %#v", result)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("unexpected commands = %#v", commandRunner.calls)
	}
}

func TestEndorRejectsMalformedOrUnexpectedJSON(t *testing.T) {
	target := createEndorTarget(t, false)
	for _, output := range []string{
		`not json`,
		`{}`,
		`{"all_findings":[],"blocking_findings":[],"warning_findings":null}`,
		`{"all_findings":["finding"],"blocking_findings":[],"warning_findings":[]}`,
	} {
		commandRunner := &endorRecordingCommandRunner{stdout: output}
		result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeDocker}).runEndor(target, "2026-09-15T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "failed" || result.Error != errInvalidEndorJSON.Error() || result.Raw != nil {
			t.Fatalf("output %q result = %#v", output, result)
		}
	}
}

func TestEndorAcceptsEmptyFindingsReport(t *testing.T) {
	raw := []byte(`{"all_findings":[],"blocking_findings":[],"warning_findings":[]}`)
	if err := validateEndorFindingsReport(raw); err != nil {
		t.Fatal(err)
	}
}

func TestEndorFailsReportedScanErrorsAndRetainsRawReport(t *testing.T) {
	target := createEndorTarget(t, false)
	commandRunner := &endorRecordingCommandRunner{
		stdout: endorFindingsJSON,
		stderr: "INFO: Scanning target\nERROR dependency-scanning-error: unable to resolve dependencies\nINFO: 1 package version(s) discovered, 1 scan failure(s), 0 call graph error(s)\n",
	}
	result, err := (ExternalScannerRunner{CommandRunner: commandRunner, SandboxMode: SandboxModeDocker}).runEndor(target, "2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "dependency-scanning-error") || !strings.Contains(result.Error, "1 scan failure(s)") {
		t.Fatalf("result = %#v", result)
	}
	if !bytes.Equal(result.Raw, []byte(endorFindingsJSON)) {
		t.Fatalf("raw report changed:\n%s", result.Raw)
	}
}

func TestEndorFailsNonzeroCallGraphErrorSummary(t *testing.T) {
	message, failed := endorReportedAnalysisError(
		"INFO: 1 package version(s) discovered, 0 scan failure(s), 2 call graph error(s)",
		nil,
	)
	if !failed || !strings.Contains(message, "2 call graph error(s)") {
		t.Fatalf("failed = %v, message = %q", failed, message)
	}
}

func TestEndorFailsCommandErrorsAndRedactsCredentials(t *testing.T) {
	target := createEndorTarget(t, false)
	for _, test := range []struct {
		name     string
		exitCode *int
		err      error
	}{
		{name: "nonzero", exitCode: endorIntPointer(2), err: errors.New("exit status 2 for token-value")},
		{name: "timeout", err: errors.New("command timed out with key-value")},
	} {
		t.Run(test.name, func(t *testing.T) {
			commandRunner := &endorRecordingCommandRunner{
				stdout:   endorFindingsJSON,
				stderr:   "credentials secret-value token-value key-value",
				exitCode: test.exitCode,
				err:      test.err,
			}
			env := map[string]string{
				"ENDOR_NAMESPACE":              "demo",
				"ENDOR_TOKEN":                  "token-value",
				"ENDOR_API_CREDENTIALS_KEY":    "key-value",
				"ENDOR_API_CREDENTIALS_SECRET": "secret-value",
			}
			result, err := (ExternalScannerRunner{CommandRunner: commandRunner, Env: env, SandboxMode: SandboxModeDocker}).runEndor(target, "2026-09-15T00:00:00Z")
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "failed" || !strings.Contains(result.Error, "[redacted]") {
				t.Fatalf("result = %#v", result)
			}
			for _, secret := range []string{"token-value", "key-value", "secret-value"} {
				if strings.Contains(result.Error, secret) {
					t.Fatalf("error leaked %q: %s", secret, result.Error)
				}
			}
			if !bytes.Equal(result.Raw, []byte(endorFindingsJSON)) {
				t.Fatalf("raw report changed:\n%s", result.Raw)
			}
		})
	}
}

func createEndorTarget(t *testing.T, plugin bool) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"package.json":        "{\"name\":\"demo\"}\n",
		"npm-shrinkwrap.json": "{\"lockfileVersion\":3}\n",
		"index.ts":            "export const demo = true\n",
	}
	if plugin {
		files[pluginManifestName] = `{"id":"demo-plugin"}`
	} else {
		files[skillManifestName] = "# Demo\n"
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func endorIntPointer(value int) *int {
	return &value
}

type endorRecordingCommandRunner struct {
	calls    []commandCall
	stdout   string
	stderr   string
	exitCode *int
	err      error
	inspect  func(call commandCall)
}

func (runner *endorRecordingCommandRunner) Run(command string, args []string, cwd string, _ time.Duration) (CommandOutput, error) {
	call := commandCall{command: command, args: append([]string(nil), args...), cwd: cwd}
	runner.calls = append(runner.calls, call)
	if runner.inspect != nil {
		runner.inspect(call)
	}
	return CommandOutput{Stdout: runner.stdout, Stderr: runner.stderr, ExitCode: runner.exitCode}, runner.err
}
