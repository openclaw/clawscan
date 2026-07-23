package runner

import (
	"crypto/rand"
	"encoding/hex"
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
	// Name the container so a timeout can kill it: process-group
	// cancellation only reaches the docker CLI client, while the container
	// itself is owned by the daemon and would keep running — with
	// allowlisted credentials and network access — after ClawScan reports
	// failure.
	containerName := clawscanContainerName()
	dockerArgs := []string{"run", "--rm", "--name", containerName, "--network", "bridge"}
	goos := runner.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	seenEnvKeys := map[string]bool{}
	for _, name := range runner.EnvNames {
		entries := envEntriesForNameOnGOOS(runner.Env, name, goos)
		keys := make([]string, 0, len(entries))
		for key := range entries {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if strings.TrimSpace(entries[key]) == "" || seenEnvKeys[key] {
				continue
			}
			seenEnvKeys[key] = true
			dockerArgs = append(dockerArgs, "-e", key)
		}
	}
	// The scan target must never use the writable-parent fallback below:
	// if it disappears between the scanner's own existence check and this
	// resolution (rename, deletion), falling back would bind the
	// surrounding host directory read-write into the container. Fail
	// closed instead — and refuse to start the container at all: with no
	// mount, image content at the same absolute path would be scanned and
	// reported as the host target, producing evidence for the wrong
	// subject.
	target := positionalScannerTarget(command, args)
	// Only absolute local paths participate in mount pinning and the vanished-
	// target post-condition: a URL (or other non-path) target gets no bind
	// mount by design, and dockerMounts only ever mounts absolute paths.
	if target != "" && !filepath.IsAbs(filepath.Clean(target)) {
		target = ""
	}
	if target != "" {
		clean := filepath.Clean(target)
		// EvalSymlinks pins the physical path: mounting the resolved
		// path means a symlink swapped in after this check redirects
		// nothing — the bind source is already the real directory. A
		// resolution failure is the vanished-target case.
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return CommandOutput{}, fmt.Errorf("scan target vanished before sandbox start: %s", target)
		}
		if resolved != target {
			args = rewritePositionalScannerTarget(args, target, resolved)
			target = resolved
		}
	}
	// Inference must run on the post-rewrite args: computing it earlier
	// would leave the pre-resolution target spelling in the list, where the
	// filter below cannot match it and it would gain its own mount.
	inference := mountInferenceArgs(command, args)
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
	if target != "" && goos == "windows" {
		if _, err := os.Stat(target); err != nil {
			return CommandOutput{}, fmt.Errorf("scan target vanished before sandbox start: %s", target)
		}
		dockerArgs = append(dockerArgs, "--mount", "type=bind,"+dockerMountField("source", target)+",target="+windowsScanTargetContainerPath+",readonly")
		args = rewritePositionalScannerTarget(args, target, windowsScanTargetContainerPath)
		target = ""
	}
	mounts := dockerMounts(cwd, inference, target)
	// dockerMounts stats again; if the target vanished in the window since
	// the resolution above, it silently omits the mount and the container
	// would scan image content at the same absolute path. Verify the
	// target's mount actually made it into the list.
	if target != "" {
		mounted := false
		for _, mount := range mounts {
			if strings.Contains(mount, dockerMountField("source", filepath.Clean(target))+",") {
				mounted = true
				break
			}
		}
		if !mounted {
			return CommandOutput{}, fmt.Errorf("scan target vanished before sandbox start: %s", target)
		}
	}
	for _, mount := range mounts {
		dockerArgs = append(dockerArgs, "--mount", mount)
	}
	if cwd != "" {
		dockerArgs = append(dockerArgs, "-w", cwd)
	}
	dockerArgs = append(dockerArgs, runner.Image, command)
	dockerArgs = append(dockerArgs, args...)
	output, err := runner.Host.Run("docker", dockerArgs, "", timeout)
	if err != nil {
		// The docker client died (timeout kill, crash) but the daemon may
		// still be running the container. Best-effort kill by name; if the
		// container already exited, `docker kill` is a harmless error.
		_, _ = runner.Host.Run("docker", []string{"kill", containerName}, "", 30*time.Second)
	}
	return output, err
}

// clawscanContainerName returns a unique name for a sandbox container so
// cleanup can address it through the daemon. Collisions only waste one run
// (docker refuses the duplicate name), never kill someone else's container:
// the random suffix makes reuse across concurrent runs vanishingly unlikely.
func clawscanContainerName() string {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Sprintf("clawscan-scan-%d", time.Now().UnixNano())
	}
	return "clawscan-scan-" + hex.EncodeToString(suffix)
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
	// Plain env: declarations are operator-chosen configuration, shown in
	// evidence. They reach the redaction sweep via the reachability set
	// (Requirements/RequiredEnv union env+secretEnv), so exempt them from the
	// fail-closed CredentialEnvName default below. A plain name that is also a
	// credential by declaration (declared) or by spelling (isSecretEnvKey) is
	// not exempt: it stays redacted as a backstop.
	plain := declaredNonCredentialEnvNames(opts)
	names := collected[:0]
	seen := map[string]bool{}
	for _, name := range collected {
		if plain[name] && !declared[name] && !isSecretEnvKey(name) {
			continue
		}
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

// declaredNonCredentialEnvNames collects plain env: declarations across the
// resolved registry. These names are exempt from redaction's fail-closed
// default so their values stay visible in evidence; see redactionEnvNames.
func declaredNonCredentialEnvNames(opts Options) map[string]bool {
	type nonCredentialDeclarer interface {
		DeclaredNonCredentialEnv() []string
	}
	plain := map[string]bool{}
	registry := registryForOptions(opts)
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			continue
		}
		if declarer, ok := adapter.(nonCredentialDeclarer); ok {
			for _, name := range declarer.DeclaredNonCredentialEnv() {
				name = strings.TrimSpace(name)
				if name != "" {
					plain[name] = true
				}
			}
		}
	}
	return plain
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
			if envValueForName(env, name) != "" {
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
