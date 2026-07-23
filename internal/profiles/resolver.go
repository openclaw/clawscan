package profiles

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openclaw/clawscan/internal/runner"
	"gopkg.in/yaml.v3"
)

//go:embed clawhub/clawscan.yml clawhub/prompt.md clawhub/output.schema.json
var builtinFiles embed.FS

var builtinProfileConfigPaths = []string{
	"clawhub/clawscan.yml",
}

type Config struct {
	Version  int                `yaml:"version"`
	Sandbox  *Sandbox           `yaml:"sandbox,omitempty"`
	Profiles map[string]Profile `yaml:"profiles"`
}

type Profile struct {
	Scanners       []ProfileScanner  `yaml:"scanners"`
	ScannerResults map[string]string `yaml:"scannerResults,omitempty"`
	Output         string            `yaml:"output,omitempty"`
	JSON           bool              `yaml:"json,omitempty"`
	Sandbox        *Sandbox          `yaml:"sandbox,omitempty"`
	Judge          *Judge            `yaml:"judge,omitempty"`
}

func (profile Profile) ScannerIDs() []string {
	return profileScannerIDs(profile.Scanners)
}

type ProfileScanner struct {
	ID      string
	Command string
	Env     []string
	Targets []string
	Gate    *ProfileScannerGate
	custom  bool
}

type ProfileScannerGate struct {
	BlockOnExitCode *profileExitCodeRule `yaml:"blockOnExitCode,omitempty"`
	WarnOnExitCode  *profileExitCodeRule `yaml:"warnOnExitCode,omitempty"`
}

type profileExitCodeRule struct {
	Codes   []int
	Nonzero bool
}

func (rule *profileExitCodeRule) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!str" && node.Value == "nonzero" {
			rule.Nonzero = true
			return nil
		}
		if node.Tag == "!!int" {
			var code int
			if err := node.Decode(&code); err == nil && code >= 0 {
				rule.Codes = []int{code}
				return nil
			}
			return errors.New("exit-code gate rule must contain only non-negative integers")
		}
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return errors.New("exit-code gate rule must not be an empty list")
		}
		codes := make([]int, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != "!!int" {
				return errors.New("exit-code gate rule must contain only non-negative integers")
			}
			var code int
			if err := item.Decode(&code); err != nil || code < 0 {
				return errors.New("exit-code gate rule must contain only non-negative integers")
			}
			codes = append(codes, code)
		}
		rule.Codes = codes
		return nil
	}
	return errors.New(`exit-code gate rule must be a non-negative integer, a list of non-negative integers, or "nonzero"`)
}

func (rule profileExitCodeRule) MarshalYAML() (interface{}, error) {
	if rule.Nonzero {
		return "nonzero", nil
	}
	switch len(rule.Codes) {
	case 0:
		return nil, errors.New("exit-code gate rule must include at least one exit code")
	case 1:
		return rule.Codes[0], nil
	default:
		return append([]int(nil), rule.Codes...), nil
	}
}

func (gate *ProfileScannerGate) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("scanner gate must be an object")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "blockOnExitCode", "warnOnExitCode":
		default:
			return fmt.Errorf("field %s not found in type profiles.ProfileScannerGate", node.Content[index].Value)
		}
	}
	type plainGate ProfileScannerGate
	return node.Decode((*plainGate)(gate))
}

func (scanner *ProfileScanner) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if err := node.Decode(&scanner.ID); err != nil {
			return err
		}
		return nil
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			switch node.Content[index].Value {
			case "id", "command", "env", "targets", "gate":
			default:
				return fmt.Errorf("field %s not found in type profiles.ProfileScanner", node.Content[index].Value)
			}
		}
		var value struct {
			ID      string              `yaml:"id"`
			Command string              `yaml:"command"`
			Env     []string            `yaml:"env,omitempty"`
			Targets []string            `yaml:"targets,omitempty"`
			Gate    *ProfileScannerGate `yaml:"gate,omitempty"`
		}
		if err := node.Decode(&value); err != nil {
			return err
		}
		scanner.ID = value.ID
		scanner.Command = value.Command
		scanner.Env = value.Env
		scanner.Targets = value.Targets
		scanner.Gate = value.Gate
		scanner.custom = true
		return nil
	default:
		return fmt.Errorf("scanner entry must be a string or object")
	}
}

func (scanner ProfileScanner) MarshalYAML() (interface{}, error) {
	if !scanner.custom {
		return scanner.ID, nil
	}
	return struct {
		ID      string              `yaml:"id"`
		Command string              `yaml:"command"`
		Env     []string            `yaml:"env,omitempty"`
		Targets []string            `yaml:"targets,omitempty"`
		Gate    *ProfileScannerGate `yaml:"gate,omitempty"`
	}{scanner.ID, scanner.Command, scanner.Env, scanner.Targets, scanner.Gate}, nil
}

func profileScannerIDs(scanners []ProfileScanner) []string {
	ids := make([]string, 0, len(scanners))
	for _, scanner := range scanners {
		ids = append(ids, scanner.ID)
	}
	return ids
}

func profileScannerRegistry(scanners []ProfileScanner) (runner.ScannerRegistry, error) {
	registry := runner.DefaultScannerRegistry()
	for _, scanner := range scanners {
		if !scanner.custom {
			continue
		}
		targets := append([]string(nil), scanner.Targets...)
		if len(targets) == 0 {
			targets = []string{"skill", "url"}
		}
		adapter := runner.NewUserDefinedScanner(runner.UserDefinedScannerConfig{
			ID: scanner.ID, Command: scanner.Command, Env: scanner.Env, Targets: targets,
		})
		var err error
		registry, err = registry.WithAdapters(adapter)
		if err != nil {
			return runner.ScannerRegistry{}, err
		}
	}
	return registry, nil
}

func profileGateRules(scanners []ProfileScanner) map[string]runner.ScannerGatePolicy {
	rules := map[string]runner.ScannerGatePolicy{}
	for _, scanner := range scanners {
		if scanner.Gate == nil {
			continue
		}
		policy := runner.ScannerGatePolicy{}
		if scanner.Gate.BlockOnExitCode != nil {
			policy.BlockOnExitCode = &runner.ExitCodeRule{
				Codes: append([]int(nil), scanner.Gate.BlockOnExitCode.Codes...), Nonzero: scanner.Gate.BlockOnExitCode.Nonzero,
			}
		}
		if scanner.Gate.WarnOnExitCode != nil {
			policy.WarnOnExitCode = &runner.ExitCodeRule{
				Codes: append([]int(nil), scanner.Gate.WarnOnExitCode.Codes...), Nonzero: scanner.Gate.WarnOnExitCode.Nonzero,
			}
		}
		if policy.BlockOnExitCode == nil && policy.WarnOnExitCode == nil {
			continue
		}
		rules[scanner.ID] = policy
	}
	return rules
}

type Sandbox struct {
	Mode  string   `yaml:"mode,omitempty"`
	Image string   `yaml:"image,omitempty"`
	Env   []string `yaml:"env,omitempty"`
}

type Judge struct {
	Command string `yaml:"command"`
}

type resolvedProfile struct {
	profile   Profile
	sandbox   Sandbox
	configDir string
	source    string
	files     map[string][]byte
}

type cliIntent struct {
	target               string
	profile              string
	profileSet           bool
	configPath           string
	discoverConfig       bool
	contextPath          string
	scanners             []string
	scannerResultPaths   map[string]string
	outputPath           string
	outputSet            bool
	json                 bool
	judge                string
	judgeSet             bool
	sandbox              string
	sandboxSet           bool
	sandboxImage         string
	sandboxImageSet      bool
	sandboxEnv           []string
	benchmark            string
	benchmarkSet         bool
	split                string
	splitSet             bool
	limit                int
	limitSet             bool
	offset               int
	offsetSet            bool
	predictionsOutput    string
	predictionsOutputSet bool
	idsSource            string
	idsSourceSet         bool
}

var judgePathPlaceholderPattern = regexp.MustCompile(`\{\{\s*(prompt|output_schema):([^}]+)\}\}`)

// scannerIDPattern restricts user-defined scanner IDs to lowercase. IDs are
// lowercased when used as evidence file names, so allowing uppercase would let
// two case-distinct IDs (Foo and foo) collide on the same output file.
var scannerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
var scannerTargetPlaceholderPattern = regexp.MustCompile(`\{\{\s*target\s*\}\}`)

// envVarNamePattern matches a bare environment variable name. Declared scanner
// env entries must be names only; an inline value (API_TOKEN=secret) would leak
// into requirement diagnostics, the artifact env map, and the Docker sandbox.
var envVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxScannerIDLength bounds user-defined scanner IDs so <id>.json evidence file
// names stay within filesystem limits.
const maxScannerIDLength = 64

type ResolvedRunSet struct {
	Options     []runner.Options
	OutputPath  string
	JSON        bool
	AllProfiles bool
}

func ResolveArgs(args []string, cwd string) (runner.Options, error) {
	resolved, err := ResolveRunSet(args, cwd)
	if err != nil {
		return runner.Options{}, err
	}
	if resolved.AllProfiles {
		return runner.Options{}, errors.New("--config without --profile resolves multiple profiles")
	}
	return resolved.Options[0], nil
}

func ResolveRunSet(args []string, cwd string) (ResolvedRunSet, error) {
	intent, err := parseCLIIntent(args)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	return resolveRunSetIntent(intent, cwd)
}

func ResolveBenchmarkRunSet(benchmarkID string, args []string, cwd string) (ResolvedRunSet, error) {
	intent, err := parseCLIIntent(args)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	if intent.target != "" {
		return ResolvedRunSet{}, errors.New("clawscan benchmark does not accept a scan target")
	}
	intent.benchmark = benchmarkID
	intent.benchmarkSet = true
	return resolveRunSetIntent(intent, cwd)
}

func resolveRunSetIntent(intent cliIntent, cwd string) (ResolvedRunSet, error) {
	var err error
	if cwd == "" {
		cwd, err = os.Getwd()
		if err != nil {
			return ResolvedRunSet{}, err
		}
	}
	if !hasExplicitRunSelection(intent) {
		return ResolvedRunSet{}, explicitRunSelectionError()
	}
	if intent.configPath != "" && !intent.profileSet {
		return resolveAllConfigProfiles(intent, cwd)
	}
	// Discovery without a profile would record the discovered file as the
	// run's ConfigSource while applying none of its settings — a provenance
	// claim the run does not honor. Reject instead of misleading.
	if intent.discoverConfig && !intent.profileSet {
		return ResolvedRunSet{}, errors.New("--discover-config requires --profile; use --config <path> to run every profile in a config")
	}

	profileName := ""
	configSource := ""
	selected := resolvedProfile{profile: Profile{}}
	if intent.profileSet || intent.configPath != "" || intent.discoverConfig {
		registry, loadedConfig, err := loadConfigs(cwd, intent.configPath, intent.discoverConfig)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		if loadedConfig != "" {
			configSource = loadedConfig
		}
		if intent.profileSet {
			profileName = intent.profile
			var ok bool
			selected, ok = registry.Profile(profileName)
			if !ok {
				return ResolvedRunSet{}, unknownProfileError(profileName, registry.IDs())
			}
			// selected.source is authoritative: a profile served from
			// embedded YAML is "built-in" even when an unrelated project
			// config was loaded alongside it.
			if selected.source == "built-in" {
				configSource = "built-in"
			}
		}
	}

	finalArgs, files, err := buildRunnerArgs(intent, selected, profileName)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	scannerRegistry, err := profileScannerRegistry(selected.profile.Scanners)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	opts, err := runner.ParseArgsWithRegistry(finalArgs, scannerRegistry)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	opts.Profile = profileName
	opts.GateRules = profileGateRules(selected.profile.Scanners)
	opts.ConfigSource = configSource
	opts.DiscoverConfig = intent.discoverConfig
	if opts.Judge != nil {
		opts.Judge.Files = files
	}
	if intent.benchmarkSet {
		opts.Benchmark, err = runner.NewBenchmarkOptions(intent.benchmark, intent.split, intent.limit, intent.offset, intent.predictionsOutput, intent.idsSource)
		if err != nil {
			return ResolvedRunSet{}, err
		}
	}
	return ResolvedRunSet{
		Options:    []runner.Options{opts},
		OutputPath: opts.OutputPath,
		JSON:       opts.JSON,
	}, nil
}

func hasExplicitRunSelection(intent cliIntent) bool {
	return len(intent.scanners) > 0 || intent.profileSet || intent.configPath != "" || intent.benchmarkSet
}

func explicitRunSelectionError() error {
	return errors.New("No scanner, profile, or config selected. Pass --scanner, --profile, or --config. Use `clawscan benchmark <benchmark-id>` for benchmark runs.")
}

func loadConfigs(cwd string, explicitConfig string, discover bool) (ProfileRegistry, string, error) {
	registry := DefaultProfileRegistry()

	var projectPath string
	var err error
	if explicitConfig != "" {
		projectPath = explicitConfig
		if !filepath.IsAbs(projectPath) {
			projectPath = filepath.Join(cwd, projectPath)
		}
		projectPath = filepath.Clean(projectPath)
	} else if discover {
		projectPath, err = discoverConfig(cwd)
		if err != nil {
			return ProfileRegistry{}, "", err
		}
	}
	if projectPath == "" {
		return registry, "", nil
	}
	projectProfiles, err := loadProjectProfiles(projectPath)
	if err != nil {
		return ProfileRegistry{}, "", err
	}
	registry, err = registry.Merge(projectProfiles)
	if err != nil {
		return ProfileRegistry{}, "", err
	}
	return registry, projectPath, nil
}

func resolveAllConfigProfiles(intent cliIntent, cwd string) (ResolvedRunSet, error) {
	if intent.benchmarkSet {
		return ResolvedRunSet{}, errors.New("clawscan benchmark requires --profile when --config is passed")
	}
	projectPath := intent.configPath
	if !filepath.IsAbs(projectPath) {
		projectPath = filepath.Join(cwd, projectPath)
	}
	projectProfiles, err := loadProjectProfiles(projectPath)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	profileNames := sortedProfileNames(projectProfiles)
	if len(profileNames) == 0 {
		return ResolvedRunSet{}, fmt.Errorf("ClawScan config %s defines no profiles", projectPath)
	}
	registry, err := DefaultProfileRegistry().Merge(projectProfiles)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	resolved := ResolvedRunSet{
		Options:     []runner.Options{},
		OutputPath:  intent.outputPath,
		JSON:        intent.json,
		AllProfiles: true,
	}
	for _, profileName := range profileNames {
		selected, ok := registry.Profile(profileName)
		if !ok {
			return ResolvedRunSet{}, unknownProfileError(profileName, registry.IDs())
		}
		finalArgs, files, err := buildRunnerArgs(intent, selected, profileName)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		scannerRegistry, err := profileScannerRegistry(selected.profile.Scanners)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		opts, err := runner.ParseArgsWithRegistry(finalArgs, scannerRegistry)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		opts.Profile = profileName
		opts.GateRules = profileGateRules(selected.profile.Scanners)
		opts.ConfigSource = filepath.Clean(projectPath)
		opts.OutputPath = ""
		opts.JSON = false
		if opts.Judge != nil {
			opts.Judge.Files = files
		}
		resolved.JSON = resolved.JSON || selected.profile.JSON
		resolved.Options = append(resolved.Options, opts)
	}
	return resolved, nil
}

func loadProjectProfiles(projectPath string) (map[string]resolvedProfile, error) {
	projectConfig, err := readConfigFile(projectPath)
	if err != nil {
		return nil, err
	}
	projectProfiles := map[string]resolvedProfile{}
	mergeProfiles(projectProfiles, projectConfig, filepath.Dir(projectPath), projectPath, nil)
	return projectProfiles, nil
}

func loadBuiltinProfiles() (map[string]resolvedProfile, error) {
	files, err := loadBuiltinProfileFiles()
	if err != nil {
		return nil, err
	}
	profiles := map[string]resolvedProfile{}
	for _, path := range builtinProfileConfigPaths {
		configPath := path
		config, err := readConfigBytes("embedded built-in profile "+configPath, func() ([]byte, error) {
			return builtinFiles.ReadFile(configPath)
		})
		if err != nil {
			return nil, err
		}
		mergeProfiles(profiles, config, filepath.Dir(configPath), "built-in", files)
	}
	return profiles, nil
}

func loadBuiltinProfileFiles() (map[string][]byte, error) {
	paths := []string{
		"clawhub/prompt.md",
		"clawhub/output.schema.json",
	}
	files := map[string][]byte{}
	for _, path := range paths {
		content, err := builtinFiles.ReadFile(path)
		if err != nil {
			return nil, err
		}
		files[path] = content
	}
	return files, nil
}

func readConfigFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read ClawScan config %s: %w", path, err)
	}
	return readConfigBytes(path, func() ([]byte, error) {
		return data, nil
	})
}

func readConfigBytes(label string, read func() ([]byte, error)) (Config, error) {
	data, err := read()
	if err != nil {
		return Config{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse ClawScan config %s: %w", label, err)
	}
	if config.Version != 1 {
		return Config{}, fmt.Errorf("Unsupported ClawScan config version: %d", config.Version)
	}
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	return config, nil
}

func mergeProfiles(out map[string]resolvedProfile, config Config, configDir string, source string, files map[string][]byte) {
	for name, profile := range config.Profiles {
		out[name] = resolvedProfile{
			profile:   profile,
			sandbox:   mergeSandbox(config.Sandbox, profile.Sandbox),
			configDir: configDir,
			source:    source,
			files:     files,
		}
	}
}

func mergeSandbox(defaults *Sandbox, override *Sandbox) Sandbox {
	var out Sandbox
	if defaults != nil {
		out = *defaults
		out.Env = append([]string(nil), defaults.Env...)
	}
	if override != nil {
		if override.Mode != "" {
			out.Mode = override.Mode
		}
		if override.Image != "" {
			out.Image = override.Image
		}
		if len(override.Env) > 0 {
			out.Env = append(out.Env, override.Env...)
		}
	}
	out.Env = dedupeStrings(out.Env)
	return out
}

func discoverConfig(cwd string) (string, error) {
	current, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	for {
		yml := filepath.Join(current, ".clawscan.yml")
		yamlPath := filepath.Join(current, ".clawscan.yaml")
		ymlExists := fileExists(yml)
		yamlExists := fileExists(yamlPath)
		if ymlExists && yamlExists {
			return "", fmt.Errorf("Ambiguous ClawScan config files: %s and %s", yml, yamlPath)
		}
		if ymlExists {
			return yml, nil
		}
		if yamlExists {
			return yamlPath, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseCLIIntent(args []string) (cliIntent, error) {
	intent := cliIntent{scannerResultPaths: map[string]string{}}
	start := 0
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		intent.target = args[0]
		start = 1
	}
	for i := start; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--profile":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.profile = value
			intent.profileSet = true
			i = next
		case "--config":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.configPath = value
			i = next
		case "--discover-config":
			intent.discoverConfig = true
		case "--context":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.contextPath = value
			i = next
		case "--scanner":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.scanners = append(intent.scanners, value)
			i = next
		case "--scanner-result":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			scanner, path, ok := strings.Cut(value, "=")
			if !ok || scanner == "" || path == "" {
				return cliIntent{}, errors.New("Expected --scanner-result value as scanner=path")
			}
			intent.scannerResultPaths[scanner] = path
			i = next
		case "--output":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.outputPath = value
			intent.outputSet = true
			i = next
		case "--json":
			intent.json = true
		case "--judge":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.judge = value
			intent.judgeSet = true
			i = next
		case "--sandbox":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.sandbox = value
			intent.sandboxSet = true
			i = next
		case "--sandbox-image":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.sandboxImage = value
			intent.sandboxImageSet = true
			i = next
		case "--sandbox-env":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.sandboxEnv = append(intent.sandboxEnv, value)
			i = next
		case "--split":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.split = value
			intent.splitSet = true
			i = next
		case "--limit":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return cliIntent{}, errors.New("Expected --limit value as a non-negative integer")
			}
			intent.limit = parsed
			intent.limitSet = true
			i = next
		case "--offset":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return cliIntent{}, errors.New("Expected --offset value as a non-negative integer")
			}
			intent.offset = parsed
			intent.offsetSet = true
			i = next
		case "--predictions-output":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.predictionsOutput = value
			intent.predictionsOutputSet = true
			i = next
		case "--ids":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return cliIntent{}, err
			}
			intent.idsSource = value
			intent.idsSourceSet = true
			i = next
		default:
			return cliIntent{}, fmt.Errorf("Unknown argument: %s", arg)
		}
	}
	if intent.configPath != "" && intent.discoverConfig {
		return cliIntent{}, errors.New("--config and --discover-config are mutually exclusive")
	}
	return intent, nil
}

func buildRunnerArgs(intent cliIntent, selected resolvedProfile, profileName string) ([]string, map[string][]byte, error) {
	if !intent.benchmarkSet {
		if intent.splitSet {
			return nil, nil, errors.New("--split requires clawscan benchmark <benchmark-id>")
		}
		if intent.limitSet {
			return nil, nil, errors.New("--limit requires clawscan benchmark <benchmark-id>")
		}
		if intent.offsetSet {
			return nil, nil, errors.New("--offset requires clawscan benchmark <benchmark-id>")
		}
		if intent.predictionsOutputSet {
			return nil, nil, errors.New("--predictions-output requires clawscan benchmark <benchmark-id>")
		}
		if intent.idsSourceSet {
			return nil, nil, errors.New("--ids requires clawscan benchmark <benchmark-id>")
		}
	}
	if intent.idsSourceSet && (intent.limitSet || intent.offsetSet) {
		return nil, nil, errors.New("--ids is mutually exclusive with --limit and --offset")
	}

	profile := selected.profile
	scanners := profileScannerIDs(profile.Scanners)
	if len(intent.scanners) > 0 {
		scanners = append([]string{}, intent.scanners...)
	}
	if len(scanners) == 0 {
		if profileName == "" {
			return nil, nil, errors.New("At least one --scanner is required")
		}
		return nil, nil, fmt.Errorf("Profile %s must include at least one scanner or use --scanner", profileName)
	}

	scannerResults := map[string]string{}
	for scanner, path := range profile.ScannerResults {
		scannerResults[scanner] = resolveConfigPath(path, selected.configDir)
	}
	for scanner, path := range intent.scannerResultPaths {
		scannerResults[scanner] = path
	}

	var args []string
	target := intent.target
	if target != "" {
		args = append(args, target)
	}
	if intent.contextPath != "" {
		args = append(args, "--context", intent.contextPath)
	}
	for _, scanner := range scanners {
		args = append(args, "--scanner", scanner)
	}
	for _, scanner := range sortedKeys(scannerResults) {
		args = append(args, "--scanner-result", scanner+"="+scannerResults[scanner])
	}
	output := resolveConfigPath(profile.Output, selected.configDir)
	if intent.outputSet {
		output = intent.outputPath
	}
	if output != "" {
		args = append(args, "--output", output)
	}
	if profile.JSON || intent.json {
		args = append(args, "--json")
	}

	judgeCommand := ""
	if profile.Judge != nil && shouldUseProfileJudge(intent) {
		judgeCommand = resolveJudgePaths(profile.Judge.Command, selected.configDir)
	}
	if intent.judgeSet {
		judgeCommand = intent.judge
	}
	if judgeCommand != "" {
		args = append(args, "--judge", judgeCommand)
	}
	if selected.sandbox.Mode != "" {
		args = append(args, "--sandbox", selected.sandbox.Mode)
	}
	if selected.sandbox.Image != "" {
		args = append(args, "--sandbox-image", selected.sandbox.Image)
	}
	for _, envVar := range selected.sandbox.Env {
		args = append(args, "--sandbox-env", envVar)
	}
	if intent.sandboxSet {
		args = append(args, "--sandbox", intent.sandbox)
	}
	if intent.sandboxImageSet {
		args = append(args, "--sandbox-image", intent.sandboxImage)
	}
	for _, envVar := range intent.sandboxEnv {
		args = append(args, "--sandbox-env", envVar)
	}
	return args, selected.files, nil
}

func shouldUseProfileJudge(intent cliIntent) bool {
	if len(intent.scanners) == 0 {
		return true
	}
	return intent.profileSet || intent.configPath != ""
}

func resolveConfigPath(path string, configDir string) string {
	if path == "" || configDir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}

func resolveJudgePaths(command string, configDir string) string {
	if configDir == "" || command == "" {
		return command
	}
	return judgePathPlaceholderPattern.ReplaceAllStringFunc(command, func(match string) string {
		parts := judgePathPlaceholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		path := strings.TrimSpace(parts[2])
		return "{{ " + parts[1] + ":" + resolveConfigPath(path, configDir) + " }}"
	})
}

// invalidDeclaredEnvName returns the sanitized name of the first declared env
// entry that is not a bare, valid variable name, or "" if all entries are
// valid. It returns only the portion before any "=", never the value, so an
// inline secret (API_TOKEN=sk-live) is not echoed into diagnostics.
func invalidDeclaredEnvName(env []string) string {
	for _, entry := range env {
		if envVarNamePattern.MatchString(entry) {
			continue
		}
		name := entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			name = entry[:i]
		}
		name = strings.TrimSpace(name)
		if i := strings.IndexByte(name, ' '); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			return "(empty)"
		}
		return name
	}
	return ""
}

func validateProfile(name string, profile Profile) error {
	seen := map[string]bool{}
	for _, scanner := range profile.Scanners {
		if scanner.custom && strings.TrimSpace(scanner.ID) == "" {
			return fmt.Errorf("User-defined scanner in profile %s must include a non-empty id", name)
		}
		if scanner.custom && !scannerIDPattern.MatchString(scanner.ID) {
			return fmt.Errorf("User-defined scanner %s in profile %s has invalid id; use lowercase letters, digits, underscores, and hyphens, starting with a letter or digit", scanner.ID, name)
		}
		if scanner.custom && len(scanner.ID) > maxScannerIDLength {
			return fmt.Errorf("User-defined scanner id in profile %s is %d characters; scanner IDs are used as file names and must be at most %d characters", name, len(scanner.ID), maxScannerIDLength)
		}
		if scanner.custom && strings.TrimSpace(scanner.Command) == "" {
			return fmt.Errorf("User-defined scanner %s in profile %s must include a non-empty command", scanner.ID, name)
		}
		if scanner.custom {
			if bad := invalidDeclaredEnvName(scanner.Env); bad != "" {
				return fmt.Errorf("User-defined scanner %s in profile %s has an invalid env entry %q; declare bare variable names and set values in the environment, not inline", scanner.ID, name, bad)
			}
		}
		if scanner.custom {
			allUnquoted, activeCount := scannerTargetPlaceholderState(scanner.Command)
			if !allUnquoted {
				return fmt.Errorf("User-defined scanner %s in profile %s must use {{target}} outside shell quotes", scanner.ID, name)
			}
			if activeCount == 0 {
				return fmt.Errorf("User-defined scanner %s in profile %s must include an active {{target}} placeholder outside shell quotes and comments so the scanner receives the target", scanner.ID, name)
			}
		}
		if scanner.custom && runner.DefaultScannerRegistry().Contains(scanner.ID) {
			return fmt.Errorf("User-defined scanner %s collides with a built-in scanner ID", scanner.ID)
		}
		if scanner.Gate != nil {
			if code, overlaps := overlappingExitCodeRules(scanner.Gate.BlockOnExitCode, scanner.Gate.WarnOnExitCode); overlaps {
				return fmt.Errorf("User-defined scanner %s in profile %s gate blockOnExitCode and warnOnExitCode both claim exit code %d", scanner.ID, name, code)
			}
		}
		for _, target := range scanner.Targets {
			switch target {
			case "skill", "plugin", "url":
			default:
				return fmt.Errorf("User-defined scanner %s in profile %s has unsupported target kind: %s", scanner.ID, name, target)
			}
		}
		if seen[scanner.ID] {
			return fmt.Errorf("Duplicate scanner in profile %s: %s", name, scanner.ID)
		}
		seen[scanner.ID] = true
	}
	return nil
}

func overlappingExitCodeRules(block *profileExitCodeRule, warn *profileExitCodeRule) (int, bool) {
	if block == nil || warn == nil {
		return 0, false
	}
	if block.Nonzero && warn.Nonzero {
		return 1, true
	}
	if block.Nonzero {
		for _, code := range warn.Codes {
			if code != 0 {
				return code, true
			}
		}
		return 0, false
	}
	if warn.Nonzero {
		for _, code := range block.Codes {
			if code != 0 {
				return code, true
			}
		}
		return 0, false
	}
	warnCodes := make(map[int]bool, len(warn.Codes))
	for _, code := range warn.Codes {
		warnCodes[code] = true
	}
	for _, code := range block.Codes {
		if warnCodes[code] {
			return code, true
		}
	}
	return 0, false
}

// scannerTargetPlaceholderState reports whether every {{target}} placeholder in
// command sits outside shell quotes (allUnquoted), and how many placeholders are
// active — outside both quotes and comments (activeCount). A command with zero
// active placeholders can complete without ever receiving the target.
func scannerTargetPlaceholderState(command string) (allUnquoted bool, activeCount int) {
	allUnquoted = true
	matches := scannerTargetPlaceholderPattern.FindAllStringIndex(command, -1)
	matchIndex := 0
	quote := byte(0)
	escaped := false
	comment := false
	for index := 0; index < len(command); index++ {
		if matchIndex < len(matches) && index == matches[matchIndex][0] {
			if !comment {
				if quote != 0 {
					allUnquoted = false
				} else {
					activeCount++
				}
			}
			index = matches[matchIndex][1] - 1
			matchIndex++
			continue
		}
		character := command[index]
		if comment {
			if character == '\n' {
				comment = false
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote == 0 {
			if character == '#' && shellCommentCanStart(command, index) {
				comment = true
				continue
			}
			switch character {
			case '\'', '"', '`':
				quote = character
			}
		} else if character == quote {
			quote = 0
		}
	}
	return allUnquoted, activeCount
}

func shellCommentCanStart(command string, index int) bool {
	if index == 0 {
		return true
	}
	switch command[index-1] {
	case ' ', '\t', '\r', '\n', ';', '|', '&', '(', ')':
		return true
	default:
		return false
	}
}

func unknownProfileError(profile string, available []string) error {
	return fmt.Errorf("Unknown profile: %s (available: %s)", profile, strings.Join(available, ", "))
}

func unknownScannerInProfileError(profile string, scanner string) error {
	return fmt.Errorf("Profile %s references unknown scanner: %s", profile, scanner)
}

func sortedProfileNames(profiles map[string]resolvedProfile) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func readValue(args []string, index int, flag string) (string, int, error) {
	next := index + 1
	if next >= len(args) || args[next] == "" || strings.HasPrefix(args[next], "--") {
		return "", index, fmt.Errorf("Expected value after %s", flag)
	}
	return args[next], next, nil
}
