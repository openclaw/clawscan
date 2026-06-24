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

//go:embed builtin.yml
var builtinFiles embed.FS

type Config struct {
	Version        int                      `yaml:"version"`
	Profiles       map[string]Profile       `yaml:"profiles"`
	CustomScanners map[string]CustomScanner `yaml:"customScanners,omitempty"`
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

type CustomScanner struct {
	Command     string   `yaml:"command"`
	RequiredEnv []string `yaml:"requiredEnv,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
}

type resolvedProfile struct {
	profile   Profile
	configDir string
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

const defaultProfile = "clawhub"

var judgePathPlaceholderPattern = regexp.MustCompile(`\{\{\s*(prompt|output_schema):([^}]+)\}\}`)

func ResolveArgs(args []string, cwd string) (runner.Options, error) {
	intent, err := parseCLIIntent(args)
	if err != nil {
		return runner.Options{}, err
	}
	if cwd == "" {
		cwd, err = os.Getwd()
		if err != nil {
			return runner.Options{}, err
		}
	}
	configs, customScanners, err := loadConfigs(cwd, intent.configPath)
	if err != nil {
		return runner.Options{}, err
	}
	profileName := intent.profile
	if profileName == "" {
		profileName = defaultProfile
	}
	selected, ok := configs[profileName]
	if !ok {
		return runner.Options{}, unknownProfileError(profileName, configs)
	}
	if err := validateProfile(profileName, selected.profile); err != nil {
		return runner.Options{}, err
	}

	finalArgs, extraEnv, err := buildRunnerArgs(intent, selected, profileName, customScanners)
	if err != nil {
		return runner.Options{}, err
	}
	opts, err := runner.ParseArgs(finalArgs)
	if err != nil {
		return runner.Options{}, err
	}
	opts.Profile = profileName
	opts.AdditionalRequiredEnv = extraEnv
	return opts, nil
}

func loadConfigs(cwd string, explicitConfig string) (map[string]resolvedProfile, map[string]CustomScanner, error) {
	builtins, err := readConfigBytes("embedded built-in profiles", func() ([]byte, error) {
		return builtinFiles.ReadFile("builtin.yml")
	})
	if err != nil {
		return nil, nil, err
	}
	profiles := map[string]resolvedProfile{}
	customScanners := map[string]CustomScanner{}
	mergeProfiles(profiles, builtins, "")
	mergeCustomScanners(customScanners, builtins)

	var projectPath string
	if explicitConfig != "" {
		projectPath = explicitConfig
		if !filepath.IsAbs(projectPath) {
			projectPath = filepath.Join(cwd, projectPath)
		}
	} else {
		projectPath, err = discoverConfig(cwd)
		if err != nil {
			return nil, nil, err
		}
	}
	if projectPath == "" {
		return profiles, customScanners, nil
	}
	projectConfig, err := readConfigFile(projectPath)
	if err != nil {
		return nil, nil, err
	}
	mergeProfiles(profiles, projectConfig, filepath.Dir(projectPath))
	mergeCustomScanners(customScanners, projectConfig)
	if err := validateCustomScannerIDs(customScanners); err != nil {
		return nil, nil, err
	}
	return profiles, customScanners, nil
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
	if config.CustomScanners == nil {
		config.CustomScanners = map[string]CustomScanner{}
	}
	return config, nil
}

func mergeProfiles(out map[string]resolvedProfile, config Config, configDir string) {
	for name, profile := range config.Profiles {
		out[name] = resolvedProfile{profile: profile, configDir: configDir}
	}
}

func mergeCustomScanners(out map[string]CustomScanner, config Config) {
	for name, scanner := range config.CustomScanners {
		out[name] = scanner
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

func buildRunnerArgs(intent cliIntent, selected resolvedProfile, profileName string, customScanners map[string]CustomScanner) ([]string, []runner.EnvRequirement, error) {
	profile := selected.profile
	scanners := append([]string{}, profile.Scanners...)
	if len(intent.scanners) > 0 {
		scanners = append([]string{}, intent.scanners...)
	}
	if len(scanners) == 0 {
		return nil, nil, fmt.Errorf("Profile %s must include at least one scanner or use --scanner", profileName)
	}
	if err := rejectCustomScannerReferences(scanners, customScanners); err != nil {
		return nil, nil, err
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
	if profile.Judge != nil {
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
	return args, extraEnv, nil
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

func rejectCustomScannerReferences(scanners []string, customScanners map[string]CustomScanner) error {
	for _, scanner := range scanners {
		if _, ok := customScanners[scanner]; ok {
			return fmt.Errorf("Custom scanner adapters are not implemented yet: %s", scanner)
		}
	}
	return nil
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

func validateCustomScannerIDs(customScanners map[string]CustomScanner) error {
	builtins := map[string]bool{}
	for _, scanner := range runner.ScannerIDs() {
		builtins[scanner] = true
	}
	for id := range customScanners {
		if builtins[id] {
			return fmt.Errorf("Custom scanner id reuses built-in scanner id: %s", id)
		}
	}
	return nil
}

func unknownProfileError(profile string, profiles map[string]resolvedProfile) error {
	return fmt.Errorf("Unknown profile: %s (available: %s)", profile, strings.Join(sortedProfileNames(profiles), ", "))
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
