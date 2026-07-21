package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	SandboxModeDocker = "docker"
	SandboxModeOff    = "off"

	DefaultSandboxImage = "ghcr.io/openclaw/clawscan-runtime:latest"
)

type SandboxOptions struct {
	Mode  string
	Image string
	Env   []string
}

type SandboxMetadata struct {
	Mode    string   `json:"mode"`
	Image   string   `json:"image,omitempty"`
	Network string   `json:"network,omitempty"`
	Env     []string `json:"env,omitempty"`
}

type resolvedSandbox struct {
	Mode  string
	Image string
}

type dockerCommandRunner struct {
	Host     CommandRunner
	Env      map[string]string
	Image    string
	EnvNames []string
	// GOOS overrides runtime.GOOS in tests; empty means the real host OS.
	GOOS string
}

func resolveSandbox(opts Options, env map[string]string) (resolvedSandbox, error) {
	mode := strings.TrimSpace(opts.Sandbox.Mode)
	if mode == "" {
		mode = strings.TrimSpace(env["CLAWSCAN_SANDBOX"])
	}
	if mode == "" {
		mode = SandboxModeDocker
	}
	mode = strings.ToLower(mode)
	if err := validateSandboxMode(mode, "CLAWSCAN_SANDBOX"); err != nil {
		return resolvedSandbox{}, err
	}

	image := strings.TrimSpace(opts.Sandbox.Image)
	if image == "" {
		image = strings.TrimSpace(env["CLAWSCAN_SANDBOX_IMAGE"])
	}
	if image == "" && mode == SandboxModeDocker {
		image = DefaultSandboxImage
	}
	return resolvedSandbox{Mode: mode, Image: image}, nil
}

func validateSandboxMode(mode string, source string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case SandboxModeDocker, SandboxModeOff:
		return nil
	default:
		return fmt.Errorf("Unsupported %s mode: %s (valid: docker, off)", source, mode)
	}
}

func sandboxMetadata(opts Options, env map[string]string) (SandboxMetadata, error) {
	sandbox, err := resolveSandbox(opts, env)
	if err != nil {
		return SandboxMetadata{}, err
	}
	metadata := SandboxMetadata{Mode: sandbox.Mode}
	if sandbox.Mode == SandboxModeDocker {
		metadata.Image = sandbox.Image
		metadata.Network = "on"
		metadata.Env = sandboxEnvNames(opts, env)
	}
	return metadata, nil
}

func mustSandboxMetadata(opts Options, env map[string]string) SandboxMetadata {
	metadata, err := sandboxMetadata(opts, env)
	if err != nil {
		return SandboxMetadata{Mode: SandboxModeDocker, Image: DefaultSandboxImage, Network: "on"}
	}
	return metadata
}

func sandboxMetadataForOptionList(optsList []Options, env map[string]string) SandboxMetadata {
	if len(optsList) == 0 {
		return SandboxMetadata{}
	}
	first := mustSandboxMetadata(optsList[0], env)
	for _, opts := range optsList[1:] {
		next := mustSandboxMetadata(opts, env)
		if next.Mode != first.Mode ||
			next.Image != first.Image ||
			next.Network != first.Network ||
			strings.Join(next.Env, "\x00") != strings.Join(first.Env, "\x00") {
			return SandboxMetadata{Mode: "mixed"}
		}
	}
	return first
}

func commandRunnerForOptions(opts Options, ctx RunContext, env map[string]string) (CommandRunner, SandboxMetadata, error) {
	metadata, err := sandboxMetadata(opts, env)
	if err != nil {
		return nil, SandboxMetadata{}, err
	}
	if ctx.CommandRunner != nil {
		return ctx.CommandRunner, metadata, nil
	}
	host := ctx.HostCommandRunner
	if host == nil {
		host = defaultCommandRunner{Env: env}
	}
	if metadata.Mode == SandboxModeOff {
		return host, metadata, nil
	}
	if requiresCommandExecution(opts) {
		availability := ctx.DockerAvailability
		if availability == nil {
			availability = dockerAvailable
		}
		if err := availability(); err != nil {
			return nil, metadata, fmt.Errorf("Docker sandbox is required for selected command-backed scanners or judge; install/start Docker or rerun with --sandbox off: %w", err)
		}
	}
	return dockerCommandRunner{
		Host:     host,
		Env:      env,
		Image:    metadata.Image,
		EnvNames: metadata.Env,
	}, metadata, nil
}

func dockerAvailable() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return err
	}
	return nil
}

func (runner dockerCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	dockerArgs := []string{"run", "--rm", "--network", "bridge"}
	for _, name := range runner.EnvNames {
		if strings.TrimSpace(runner.Env[name]) != "" {
			dockerArgs = append(dockerArgs, "-e", name)
		}
	}
	inference := mountInferenceArgs(command, args)
	// The scan target must never use the writable-parent fallback below:
	// if it disappears between the scanner's own existence check and this
	// stat (rename, deletion), falling back would bind the surrounding host
	// directory read-write into the container. Fail closed instead — the
	// scanner then fails on a missing path with no host exposure.
	target := positionalScannerTarget(command, args)
	if target != "" {
		filtered := inference[:0:0]
		for _, arg := range inference {
			if arg != target {
				filtered = append(filtered, arg)
			}
		}
		inference = filtered
	}
	// A Windows host path (C:\skills\demo) is not absolute inside the Linux
	// runtime image: Docker would reject it as a mount destination and the
	// scanner could never resolve it. Mount the host source at a stable
	// POSIX path and hand the scanner that path instead.
	goos := runner.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if target != "" && goos == "windows" {
		if _, err := os.Stat(target); err == nil {
			dockerArgs = append(dockerArgs, "--mount", "type=bind,"+dockerMountField("source", target)+",target="+windowsScanTargetContainerPath+",readonly")
			args = rewritePositionalScannerTarget(args, target, windowsScanTargetContainerPath)
		}
		target = ""
	}
	for _, mount := range dockerMounts(cwd, inference, target) {
		dockerArgs = append(dockerArgs, "--mount", mount)
	}
	if cwd != "" {
		dockerArgs = append(dockerArgs, "-w", cwd)
	}
	dockerArgs = append(dockerArgs, runner.Image, command)
	dockerArgs = append(dockerArgs, args...)
	return runner.Host.Run("docker", dockerArgs, "", timeout)
}

// mountInferenceArgs drops the rendered shell program from mount inference:
// for `/bin/sh -c '<program>' [positional args...]` the program is one
// absolute-looking string ("/usr/bin/scanner \"$1\"") that never stats, and
// inferring a parent from it would bind-mount /usr/bin writable into the
// container. Only the -c operand is excluded; every other arg (including
// not-yet-created output paths with spaces) keeps its mount.
func mountInferenceArgs(command string, args []string) []string {
	if command != "/bin/sh" {
		return args
	}
	for index, arg := range args {
		if arg == "-c" && index+1 < len(args) {
			filtered := append([]string(nil), args[:index+1]...)
			return append(filtered, args[index+2:]...)
		}
	}
	return args
}

// positionalScannerTarget extracts the scan target from a user-defined
// scanner invocation (`/bin/sh -c '<program>' clawscan-target <target>`).
// Empty for every other command shape.
func positionalScannerTarget(command string, args []string) string {
	if command != "/bin/sh" {
		return ""
	}
	for index, arg := range args {
		if arg == "clawscan-target" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

// windowsScanTargetContainerPath is where a Windows host scan target is
// bind-mounted inside the Linux runtime image.
const windowsScanTargetContainerPath = "/clawscan/target"

func rewritePositionalScannerTarget(args []string, from string, to string) []string {
	rewritten := append([]string(nil), args...)
	for index, arg := range rewritten {
		if arg == "clawscan-target" && index+1 < len(rewritten) && rewritten[index+1] == from {
			rewritten[index+1] = to
		}
	}
	return rewritten
}

// dockerMounts infers bind mounts from cwd and command args. Existing paths
// mount directly (readonly for args); a missing arg is assumed to be a
// not-yet-created output file, so its parent mounts writable. scanTargets
// are exempt from that fallback: a scan target that no longer exists must
// not expose its parent directory writable to the container.
func dockerMounts(cwd string, args []string, scanTargets ...string) []string {
	mounts := map[string]bool{}
	add := func(path string, readOnly bool) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if !filepath.IsAbs(clean) {
			return
		}
		if existing, err := os.Stat(clean); err == nil {
			mounts[clean] = readOnly || !existing.IsDir()
			return
		}
		parent := filepath.Dir(clean)
		if parent != "." && parent != clean {
			mounts[parent] = false
		}
	}
	add(cwd, false)
	for _, arg := range args {
		add(arg, true)
	}
	for _, target := range scanTargets {
		if target == "" {
			continue
		}
		clean := filepath.Clean(target)
		if !filepath.IsAbs(clean) {
			continue
		}
		// No writable-parent fallback: a missing scan target mounts nothing.
		if _, err := os.Stat(clean); err == nil {
			mounts[clean] = true
		}
	}
	sources := make([]string, 0, len(mounts))
	for source := range mounts {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		option := "type=bind," + dockerMountField("source", source) + "," + dockerMountField("target", source)
		if mounts[source] {
			option += ",readonly"
		}
		out = append(out, option)
	}
	return out
}

// dockerMountField renders one key=value field of a --mount spec. Docker
// parses the spec as CSV, so a path containing a comma, quote, or newline
// (all valid in POSIX path components) must be CSV-quoted or Docker reads
// the remainder as another field/record and rejects or truncates the
// mount.
func dockerMountField(key string, value string) string {
	field := key + "=" + value
	if strings.ContainsAny(field, ",\"\r\n") {
		return `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
	}
	return field
}

// sandboxEnvNames lists env vars passed through to the Docker sandbox.
// Fixture-satisfied scanners are skipped: they never execute, so their
// credentials must not enter the container.
func sandboxEnvNames(opts Options, env map[string]string) []string {
	return collectEnvNames(opts, env, false)
}

// redactionEnvNames lists env vars whose values must be scrubbed from
// anything persisted this run, scoped to what the run's commands can
// actually see. With --sandbox off every host command inherits the whole
// process environment, so the sweep covers every credential the resolved
// registry declares (selected or not, fixture or not) plus sibling batch
// profiles' declared credentials (BatchRedactEnvNames). Under Docker only
// the passthrough allowlist enters the container, so the sweep is that
// allowlist — including populated credential-classified OptionalEnv, which
// the container does receive — and nothing more: scrubbing a never-exposed
// sibling credential whose value coincides with legitimate output would
// corrupt evidence without preventing any leak.
func redactionEnvNames(opts Options, env map[string]string, sandboxMode string) []string {
	hostMode := sandboxMode != SandboxModeDocker
	collected := collectEnvNames(opts, env, hostMode)
	// Names mix credentials with ordinary configuration
	// (SKILLSPECTOR_PROVIDER=openai): scrubbing a common value like
	// "openai" would corrupt valid evidence. Keep only names classified as
	// credentials — except explicit user-defined env: declarations, which
	// are credentials whatever their name.
	declared := declaredCredentialEnvNames(opts)
	names := collected[:0]
	seen := map[string]bool{}
	for _, name := range collected {
		if declared[name] || CredentialEnvName(name) {
			names = append(names, name)
			seen[name] = true
		}
	}
	// BatchRedactEnvNames arrive pre-vetted by the resolver (sibling
	// profiles' env: declarations plus credential-classified sandbox
	// names), so they bypass the filter above. Host mode only: a sibling
	// profile's credential never enters this profile's container.
	if hostMode {
		for _, name := range opts.BatchRedactEnvNames {
			name = strings.TrimSpace(name)
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func declaredCredentialEnvNames(opts Options) map[string]bool {
	type credentialDeclarer interface {
		DeclaredCredentialEnv() []string
	}
	declared := map[string]bool{}
	registry := registryForOptions(opts)
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			continue
		}
		if declarer, ok := adapter.(credentialDeclarer); ok {
			for _, name := range declarer.DeclaredCredentialEnv() {
				name = strings.TrimSpace(name)
				if name != "" {
					declared[name] = true
				}
			}
		}
	}
	return declared
}

// collectEnvNames gathers env var names in scope for a run. wholeRegistry
// widens the sweep to every adapter's declared credentials for host-mode
// redaction; false yields the executing-scanner passthrough set used both
// for the Docker allowlist and Docker-scoped redaction.
func collectEnvNames(opts Options, env map[string]string, wholeRegistry bool) []string {
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" {
			seen[name] = true
		}
	}
	addInfo := func(info ScannerInfo) {
		for _, name := range info.RequiredEnv {
			add(name)
		}
		for _, name := range info.OptionalEnv {
			if strings.TrimSpace(env[name]) != "" {
				add(name)
			}
		}
	}
	for _, name := range opts.Sandbox.Env {
		add(name)
	}
	for _, req := range requirements(opts, env) {
		add(req.EnvVar)
	}
	if wholeRegistry {
		// Host-mode redaction must cover every credential the resolved
		// registry declares, not just selected scanners: with --sandbox off
		// the whole process env reaches every host command, so a blandly
		// named credential declared by an unselected profile scanner
		// (--scanner subset) is still reachable by the scanners and judge
		// that do run.
		// Only credentials-by-declaration feed this sweep — scanner
		// OptionalEnv is ordinary configuration (LOG_LEVEL, AWS_REGION)
		// whose common values (info, true) would corrupt valid evidence if
		// scrubbed. Built-in credentials are secret-named and caught by
		// isSecretEnvKey value scanning; user-defined scanners declare
		// theirs via env:, exposed here as DeclaredCredentialEnv.
		type credentialDeclarer interface {
			DeclaredCredentialEnv() []string
		}
		registry := registryForOptions(opts)
		for _, id := range registry.IDs() {
			adapter, ok := registry.Adapter(id)
			if !ok {
				continue
			}
			if declarer, ok := adapter.(credentialDeclarer); ok {
				for _, name := range declarer.DeclaredCredentialEnv() {
					add(name)
				}
			}
		}
	} else {
		// Sandbox passthrough stays a narrow allowlist: only scanners that
		// will actually execute; fixture-satisfied scanners never run, so
		// their credentials must not enter the container.
		for _, scanner := range opts.Scanners {
			if opts.ScannerResultPaths[scanner] != "" {
				continue
			}
			adapter, ok := registryForOptions(opts).Adapter(scanner)
			if !ok {
				continue
			}
			addInfo(adapter.Info())
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func requiresCommandExecution(opts Options) bool {
	if opts.Judge != nil {
		return true
	}
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] != "" {
			continue
		}
		adapter, ok := registryForOptions(opts).Adapter(scanner)
		if !ok {
			continue
		}
		if commandBackedScanner(adapter) {
			return true
		}
	}
	return false
}
