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

//go:embed builtin.yml clawhub/prompt.md clawhub/output.schema.json
var builtinFiles embed.FS

type Config struct {
	Version  int                `yaml:"version"`
	Profiles map[string]Profile `yaml:"profiles"`
}

type Profile struct {
	Scanners       []string          `yaml:"scanners"`
	ScannerResults map[string]string `yaml:"scannerResults,omitempty"`
	Output         string            `yaml:"output,omitempty"`
	JSON           bool              `yaml:"json,omitempty"`
	Judge          *Judge            `yaml:"judge,omitempty"`
}

type Judge struct {
	Command     string   `yaml:"command"`
	RequiredEnv []string `yaml:"requiredEnv,omitempty"`
}

type resolvedProfile struct {
	profile   Profile
	configDir string
	files     map[string][]byte
}

type cliIntent struct {
	target               string
	profile              string
	profileSet           bool
	configPath           string
	scanners             []string
	scannerResultPaths   map[string]string
	outputPath           string
	outputSet            bool
	json                 bool
	judge                string
	judgeSet             bool
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
}

var judgePathPlaceholderPattern = regexp.MustCompile(`\{\{\s*(prompt|output_schema):([^}]+)\}\}`)

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

	profileName := ""
	selected := resolvedProfile{profile: Profile{}}
	if intent.profileSet || intent.configPath != "" {
		registry, err := loadConfigs(cwd, intent.configPath)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		profileName = intent.profile
		var ok bool
		selected, ok = registry.Profile(profileName)
		if !ok {
			return ResolvedRunSet{}, unknownProfileError(profileName, registry.IDs())
		}
	}

	finalArgs, extraEnv, files, err := buildRunnerArgs(intent, selected, profileName)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	opts, err := runner.ParseArgs(finalArgs)
	if err != nil {
		return ResolvedRunSet{}, err
	}
	opts.Profile = profileName
	opts.AdditionalRequiredEnv = extraEnv
	if opts.Judge != nil {
		opts.Judge.Files = files
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
	return errors.New("No scanner, profile, config, or benchmark selected. Pass --scanner, --profile, --config, or --benchmark.")
}

func loadConfigs(cwd string, explicitConfig string) (ProfileRegistry, error) {
	registry := DefaultProfileRegistry()

	var projectPath string
	var err error
	if explicitConfig != "" {
		projectPath = explicitConfig
		if !filepath.IsAbs(projectPath) {
			projectPath = filepath.Join(cwd, projectPath)
		}
	} else {
		projectPath, err = discoverConfig(cwd)
		if err != nil {
			return ProfileRegistry{}, err
		}
	}
	if projectPath == "" {
		return registry, nil
	}
	projectProfiles, err := loadProjectProfiles(projectPath)
	if err != nil {
		return ProfileRegistry{}, err
	}
	return registry.Merge(projectProfiles)
}

func resolveAllConfigProfiles(intent cliIntent, cwd string) (ResolvedRunSet, error) {
	if intent.benchmarkSet {
		return ResolvedRunSet{}, errors.New("--config without --profile does not support --benchmark")
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
		finalArgs, extraEnv, files, err := buildRunnerArgs(intent, selected, profileName)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		opts, err := runner.ParseArgs(finalArgs)
		if err != nil {
			return ResolvedRunSet{}, err
		}
		opts.Profile = profileName
		opts.OutputPath = ""
		opts.JSON = false
		opts.AdditionalRequiredEnv = extraEnv
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
	mergeProfiles(projectProfiles, projectConfig, filepath.Dir(projectPath), nil)
	return projectProfiles, nil
}

func loadBuiltinProfiles() (map[string]resolvedProfile, error) {
	builtins, err := readConfigBytes("embedded built-in profiles", func() ([]byte, error) {
		return builtinFiles.ReadFile("builtin.yml")
	})
	if err != nil {
		return nil, err
	}
	files, err := loadBuiltinProfileFiles()
	if err != nil {
		return nil, err
	}
	profiles := map[string]resolvedProfile{}
	mergeProfiles(profiles, builtins, "", files)
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

func mergeProfiles(out map[string]resolvedProfile, config Config, configDir string, files map[string][]byte) {
	for name, profile := range config.Profiles {
		out[name] = resolvedProfile{profile: profile, configDir: configDir, files: files}
	}
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
		case "--benchmark":
			intent.benchmarkSet = true
			next := i + 1
			if next < len(args) && args[next] != "" && !strings.HasPrefix(args[next], "--") {
				intent.benchmark = args[next]
				i = next
			}
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
		default:
			return cliIntent{}, fmt.Errorf("Unknown argument: %s", arg)
		}
	}
	return intent, nil
}

func buildRunnerArgs(intent cliIntent, selected resolvedProfile, profileName string) ([]string, []runner.EnvRequirement, map[string][]byte, error) {
	profile := selected.profile
	scanners := append([]string{}, profile.Scanners...)
	if len(intent.scanners) > 0 {
		scanners = append([]string{}, intent.scanners...)
	}
	if len(scanners) == 0 {
		if profileName == "" {
			return nil, nil, nil, errors.New("At least one --scanner is required")
		}
		return nil, nil, nil, fmt.Errorf("Profile %s must include at least one scanner or use --scanner", profileName)
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
	if intent.benchmarkSet {
		args = append(args, "--benchmark")
		if intent.benchmark != "" {
			args = append(args, intent.benchmark)
		}
	}
	if intent.splitSet {
		args = append(args, "--split", intent.split)
	}
	if intent.limitSet {
		args = append(args, "--limit", strconv.Itoa(intent.limit))
	}
	if intent.offsetSet {
		args = append(args, "--offset", strconv.Itoa(intent.offset))
	}
	if intent.predictionsOutputSet {
		args = append(args, "--predictions-output", intent.predictionsOutput)
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

	var extraEnv []runner.EnvRequirement
	judgeCommand := ""
	if profile.Judge != nil && shouldUseProfileJudge(intent) {
		judgeCommand = resolveJudgePaths(profile.Judge.Command, selected.configDir)
		for _, envVar := range profile.Judge.RequiredEnv {
			extraEnv = append(extraEnv, runner.EnvRequirement{EnvVar: envVar, Reason: "judge " + profileName})
		}
	}
	if intent.judgeSet {
		judgeCommand = intent.judge
		extraEnv = nil
	}
	if judgeCommand != "" {
		args = append(args, "--judge", judgeCommand)
	}
	return args, extraEnv, selected.files, nil
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

func validateProfile(name string, profile Profile) error {
	seen := map[string]bool{}
	for _, scanner := range profile.Scanners {
		if seen[scanner] {
			return fmt.Errorf("Duplicate scanner in profile %s: %s", name, scanner)
		}
		seen[scanner] = true
	}
	return nil
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

func readValue(args []string, index int, flag string) (string, int, error) {
	next := index + 1
	if next >= len(args) || args[next] == "" || strings.HasPrefix(args[next], "--") {
		return "", index, fmt.Errorf("Expected value after %s", flag)
	}
	return args[next], next, nil
}
