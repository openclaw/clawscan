package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openclaw/clawscan/internal/runner"
	"gopkg.in/yaml.v3"
)

var jsonIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

type ProfileScannerGate struct {
	BlockOnExitCode *profileExitCodeRule  `yaml:"blockOnExitCode,omitempty"`
	WarnOnExitCode  *profileExitCodeRule  `yaml:"warnOnExitCode,omitempty"`
	Rules           []profileJSONGateRule `yaml:"rules,omitempty"`
}

type profileJSONGateRule struct {
	ID         string     `yaml:"id"`
	Paths      []string   `yaml:"-"`
	Equals     *yaml.Node `yaml:"equals,omitempty"`
	Exists     bool       `yaml:"exists,omitempty"`
	Normalize  string     `yaml:"normalize,omitempty"`
	Fallback   string     `yaml:"fallback,omitempty"`
	Action     string     `yaml:"action"`
	equalsSet  bool
	existsSet  bool
	equalsJSON json.RawMessage
}

type profileExitCodeRule struct {
	Codes   []int
	Nonzero bool
}

func (rule *profileExitCodeRule) UnmarshalYAML(node *yaml.Node) error {
	node = resolvedYAMLNode(node)
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!str" && node.Value == "nonzero" {
			rule.Nonzero = true
			return nil
		}
		if node.Tag == "!!int" {
			var code int
			if err := node.Decode(&code); err == nil && code >= 0 && code <= runner.MaxGateExitCode {
				rule.Codes = []int{code}
				return nil
			}
			return fmt.Errorf("exit-code gate rule must contain only integers from 0 through %d", runner.MaxGateExitCode)
		}
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return errors.New("exit-code gate rule must not be an empty list")
		}
		codes := make([]int, 0, len(node.Content))
		for _, item := range node.Content {
			item = resolvedYAMLNode(item)
			if item.Kind != yaml.ScalarNode || item.Tag != "!!int" {
				return fmt.Errorf("exit-code gate rule must contain only integers from 0 through %d", runner.MaxGateExitCode)
			}
			var code int
			if err := item.Decode(&code); err != nil || code < 0 || code > runner.MaxGateExitCode {
				return fmt.Errorf("exit-code gate rule must contain only integers from 0 through %d", runner.MaxGateExitCode)
			}
			codes = append(codes, code)
		}
		rule.Codes = codes
		return nil
	}
	return fmt.Errorf(`exit-code gate rule must be an integer from 0 through %d, a list of those integers, or "nonzero"`, runner.MaxGateExitCode)
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

func (rule *profileJSONGateRule) UnmarshalYAML(node *yaml.Node) error {
	node = resolvedYAMLNode(node)
	if node.Kind != yaml.MappingNode {
		return errors.New("JSON gate rule must be an object")
	}
	seenFields := make(map[string]bool, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if seenFields[key] {
			return fmt.Errorf("JSON gate rule %s has duplicate field %s", rule.ID, key)
		}
		seenFields[key] = true
		value := resolvedYAMLNode(node.Content[index+1])
		switch key {
		case "id":
			if err := value.Decode(&rule.ID); err != nil {
				return err
			}
		case "path":
			if err := rule.decodePaths(value); err != nil {
				return err
			}
		case "action":
			if err := value.Decode(&rule.Action); err != nil {
				return err
			}
		case "equals":
			if err := rule.decodeEquals(value); err != nil {
				return err
			}
		case "exists":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!bool" {
				return fmt.Errorf("JSON gate rule %s exists must be true", rule.ID)
			}
			rule.existsSet = true
			if err := value.Decode(&rule.Exists); err != nil {
				return err
			}
		case "normalize":
			if err := value.Decode(&rule.Normalize); err != nil {
				return err
			}
		case "fallback":
			if err := value.Decode(&rule.Fallback); err != nil {
				return err
			}
		default:
			return fmt.Errorf("field %s not found in type profiles.profileJSONGateRule", key)
		}
	}
	return rule.validate()
}

func (rule *profileJSONGateRule) decodePaths(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return fmt.Errorf("JSON gate rule %s path must be a string or list of strings", rule.ID)
		}
		rule.Paths = []string{node.Value}
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return fmt.Errorf("JSON gate rule %s path list must not be empty", rule.ID)
		}
		rule.Paths = make([]string, 0, len(node.Content))
		for _, pathNode := range node.Content {
			pathNode = resolvedYAMLNode(pathNode)
			if pathNode.Kind != yaml.ScalarNode || pathNode.Tag != "!!str" {
				return fmt.Errorf("JSON gate rule %s path must be a string or list of strings", rule.ID)
			}
			rule.Paths = append(rule.Paths, pathNode.Value)
		}
	default:
		return fmt.Errorf("JSON gate rule %s path must be a string or list of strings", rule.ID)
	}
	return nil
}

func (rule *profileJSONGateRule) decodeEquals(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return fmt.Errorf("JSON gate rule %s equals must be a string, number, or boolean", rule.ID)
	}
	switch node.Tag {
	case "!!str":
		rule.equalsJSON, _ = json.Marshal(node.Value)
	case "!!bool":
		var parsed bool
		if err := node.Decode(&parsed); err != nil {
			return fmt.Errorf("JSON gate rule %s equals must be a boolean", rule.ID)
		}
		rule.equalsJSON, _ = json.Marshal(parsed)
	case "!!int":
		if !validJSONGateNumber(node.Value) {
			return fmt.Errorf("JSON gate rule %s equals must be a finite JSON number", rule.ID)
		}
		if !jsonIntegerPattern.MatchString(node.Value) {
			return fmt.Errorf("JSON gate rule %s equals must be a JSON integer", rule.ID)
		}
		rule.equalsJSON = append(json.RawMessage(nil), node.Value...)
	case "!!float":
		if !validJSONGateNumber(node.Value) {
			return fmt.Errorf("JSON gate rule %s equals must be a finite JSON number", rule.ID)
		}
		rule.equalsJSON = append(json.RawMessage(nil), node.Value...)
	default:
		return fmt.Errorf("JSON gate rule %s equals must be a string, number, or boolean", rule.ID)
	}
	rule.Equals = node
	rule.equalsSet = true
	return nil
}

func (rule profileJSONGateRule) validate() error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("JSON gate rule id must not be empty")
	}
	if len(rule.Paths) == 0 {
		return fmt.Errorf("JSON gate rule %s path must not be empty", rule.ID)
	}
	seenPaths := map[string]bool{}
	for _, path := range rule.Paths {
		if err := runner.ValidateJSONGatePath(path); err != nil {
			return fmt.Errorf("JSON gate rule %s path %q is invalid: %w", rule.ID, path, err)
		}
		if seenPaths[path] {
			return fmt.Errorf("JSON gate rule %s has duplicate path %q", rule.ID, path)
		}
		seenPaths[path] = true
	}
	if rule.Action != "warn" && rule.Action != "block" {
		return fmt.Errorf("JSON gate rule %s action must be warn or block", rule.ID)
	}
	if rule.existsSet && !rule.Exists {
		return fmt.Errorf("JSON gate rule %s exists must be true", rule.ID)
	}
	if rule.equalsSet == rule.existsSet {
		return fmt.Errorf("JSON gate rule %s must include exactly one of equals or exists: true", rule.ID)
	}
	if rule.Normalize != "" && rule.Normalize != "identifier" {
		return fmt.Errorf("JSON gate rule %s normalize must be identifier", rule.ID)
	}
	if rule.Normalize != "" && (!rule.equalsSet || rule.Equals.Tag != "!!str") {
		return fmt.Errorf("JSON gate rule %s normalize requires a string equals value", rule.ID)
	}
	if rule.Fallback != "" && rule.Fallback != "root" {
		return fmt.Errorf("JSON gate rule %s fallback must be root", rule.ID)
	}
	return nil
}

func validJSONGateNumber(value string) bool {
	if !json.Valid([]byte(value)) {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return false
	}
	_, ok := parsed.(json.Number)
	return ok
}

func (rule profileJSONGateRule) MarshalYAML() (interface{}, error) {
	var path any
	if len(rule.Paths) == 1 {
		path = rule.Paths[0]
	} else {
		path = append([]string(nil), rule.Paths...)
	}
	return struct {
		ID        string     `yaml:"id"`
		Path      any        `yaml:"path"`
		Equals    *yaml.Node `yaml:"equals,omitempty"`
		Exists    bool       `yaml:"exists,omitempty"`
		Normalize string     `yaml:"normalize,omitempty"`
		Fallback  string     `yaml:"fallback,omitempty"`
		Action    string     `yaml:"action"`
	}{rule.ID, path, rule.Equals, rule.Exists, rule.Normalize, rule.Fallback, rule.Action}, nil
}

func (gate *ProfileScannerGate) UnmarshalYAML(node *yaml.Node) error {
	node = resolvedYAMLNode(node)
	if node.Kind != yaml.MappingNode {
		return errors.New("scanner gate must be an object")
	}
	if len(node.Content) == 0 {
		return errors.New("scanner gate must include blockOnExitCode, warnOnExitCode, or rules")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "blockOnExitCode", "warnOnExitCode", "rules":
			value := resolvedYAMLNode(node.Content[index+1])
			if value.Tag == "!!null" {
				return fmt.Errorf("scanner gate %s must not be null", node.Content[index].Value)
			}
		default:
			return fmt.Errorf("field %s not found in type profiles.ProfileScannerGate", node.Content[index].Value)
		}
	}
	type plainGate ProfileScannerGate
	if err := node.Decode((*plainGate)(gate)); err != nil {
		return err
	}
	if gate.Rules != nil && len(gate.Rules) == 0 {
		return errors.New("scanner gate rules must not be empty")
	}
	seenRuleIDs := map[string]bool{}
	for _, rule := range gate.Rules {
		if seenRuleIDs[rule.ID] {
			return fmt.Errorf("duplicate JSON gate rule id %s", rule.ID)
		}
		seenRuleIDs[rule.ID] = true
	}
	if gate.BlockOnExitCode == nil && gate.WarnOnExitCode == nil && len(gate.Rules) == 0 {
		return errors.New("scanner gate must include blockOnExitCode, warnOnExitCode, or rules")
	}
	return nil
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
			case "id", "command", "env", "secretEnv", "targets", "gate":
				if node.Content[index].Value == "command" {
					scanner.custom = true
				}
				if node.Content[index].Value == "gate" {
					gateNode := resolvedYAMLNode(node.Content[index+1])
					if gateNode.Kind != yaml.MappingNode {
						return errors.New("scanner gate must be an object")
					}
				}
			default:
				return fmt.Errorf("field %s not found in type profiles.ProfileScanner", node.Content[index].Value)
			}
		}
		var value struct {
			ID        string              `yaml:"id"`
			Command   string              `yaml:"command"`
			Env       []string            `yaml:"env,omitempty"`
			SecretEnv []string            `yaml:"secretEnv,omitempty"`
			Targets   []string            `yaml:"targets,omitempty"`
			Gate      *ProfileScannerGate `yaml:"gate,omitempty"`
		}
		if err := node.Decode(&value); err != nil {
			return err
		}
		scanner.ID = value.ID
		scanner.Command = value.Command
		scanner.Env = value.Env
		scanner.SecretEnv = value.SecretEnv
		scanner.Targets = value.Targets
		scanner.Gate = value.Gate
		scanner.mapping = true
		return nil
	default:
		return fmt.Errorf("scanner entry must be a string or object")
	}
}

func (scanner ProfileScanner) MarshalYAML() (interface{}, error) {
	if !scanner.mapping && !scanner.custom {
		return scanner.ID, nil
	}
	return struct {
		ID        string              `yaml:"id"`
		Command   string              `yaml:"command,omitempty"`
		Env       []string            `yaml:"env,omitempty"`
		SecretEnv []string            `yaml:"secretEnv,omitempty"`
		Targets   []string            `yaml:"targets,omitempty"`
		Gate      *ProfileScannerGate `yaml:"gate,omitempty"`
	}{scanner.ID, scanner.Command, scanner.Env, scanner.SecretEnv, scanner.Targets, scanner.Gate}, nil
}

func (m *SandboxMount) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Decode(&m.Path)
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			switch node.Content[index].Value {
			case "path", "write":
			default:
				return fmt.Errorf("field %s not found in type profiles.SandboxMount", node.Content[index].Value)
			}
		}
		var value struct {
			Path  string `yaml:"path"`
			Write bool   `yaml:"write"`
		}
		if err := node.Decode(&value); err != nil {
			return err
		}
		m.Path, m.Write = value.Path, value.Write
		return nil
	default:
		return fmt.Errorf("sandbox mount must be a string or object")
	}
}

func (m SandboxMount) MarshalYAML() (interface{}, error) {
	if !m.Write {
		return m.Path, nil
	}
	return struct {
		Path  string `yaml:"path"`
		Write bool   `yaml:"write"`
	}{Path: m.Path, Write: m.Write}, nil
}

func resolvedYAMLNode(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}
