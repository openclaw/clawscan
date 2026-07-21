package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	for _, mount := range dockerMounts(cwd, args) {
		dockerArgs = append(dockerArgs, "--mount", mount)
	}
	if cwd != "" {
		dockerArgs = append(dockerArgs, "-w", cwd)
	}
	dockerArgs = append(dockerArgs, runner.Image, command)
	dockerArgs = append(dockerArgs, args...)
	return runner.Host.Run("docker", dockerArgs, "", timeout)
}

func dockerMounts(cwd string, args []string) []string {
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
	sources := make([]string, 0, len(mounts))
	for source := range mounts {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		option := "type=bind,source=" + source + ",target=" + source
		if mounts[source] {
			option += ",readonly"
		}
		out = append(out, option)
	}
	return out
}

func sandboxEnvNames(opts Options, env map[string]string) []string {
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" {
			seen[name] = true
		}
	}
	for _, name := range opts.Sandbox.Env {
		add(name)
	}
	for _, req := range requirements(opts, env) {
		add(req.EnvVar)
	}
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] != "" {
			continue
		}
		adapter, ok := registryForOptions(opts).Adapter(scanner)
		if !ok {
			continue
		}
		info := adapter.Info()
		for _, name := range info.RequiredEnv {
			add(name)
		}
		for _, name := range info.OptionalEnv {
			if strings.TrimSpace(env[name]) != "" {
				add(name)
			}
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
