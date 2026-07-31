package schemas_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/runner"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestClawScanSchemaAcceptsSupportedProfiles(t *testing.T) {
	schema := compileClawScanSchema(t)
	fixtures := map[string][]byte{
		"embedded clawhub profile": readFixture(t, filepath.Join("..", "internal", "profiles", "clawhub", "clawscan.yml")),
		"custom scanner and gate": []byte(`
version: 1
sandbox:
  mode: docker
  image: ghcr.io/openclaw/clawscan-runtime:latest
  env: [OPENAI_API_KEY]
  mounts:
    - /opt/rules
    - path: /var/cache/clawscan
      write: true
profiles:
  review:
    scanners:
      - skillspector
      - id: clawscan-static
        gate:
          rules:
            - id: any-finding
              path: findings[]
              exists: true
              action: warn
      - id: third-party
        command: third-party scan --json {{target}}
        env: [THIRD_PARTY_REGION]
        secretEnv: [THIRD_PARTY_TOKEN]
        targets: [skill, plugin, url]
        gate:
          blockOnExitCode: nonzero
          warnOnExitCode: [1, 2]
          rules:
            - id: critical-risk
              path:
                - result.risk
                - result.risk_level
              equals: critical
              normalize: identifier
              fallback: root
              action: block
    scannerResults:
      skillspector: ./fixtures/skillspector.json
    output: ./artifacts/review.json
    json: true
    judge:
      command: judge --input {{ workspace }} --output {{ output }}
`),
	}

	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate(decodeYAMLAsJSON(t, data)); err != nil {
				t.Fatalf("schema rejected supported profile: %v", err)
			}
		})
	}
}

func TestClawScanSchemaAcceptsEveryBuiltInScanner(t *testing.T) {
	schema := compileClawScanSchema(t)
	for _, scannerID := range runner.DefaultScannerRegistry().IDs() {
		t.Run(scannerID, func(t *testing.T) {
			data := []byte("version: 1\nprofiles:\n  review:\n    scanners:\n      - " + scannerID + "\n")
			if err := schema.Validate(decodeYAMLAsJSON(t, data)); err != nil {
				t.Fatalf("schema rejected built-in scanner %q: %v", scannerID, err)
			}
		})
	}
}

func TestClawScanSchemaRejectsInvalidGateRules(t *testing.T) {
	schema := compileClawScanSchema(t)
	tests := map[string]string{
		"unknown field": `
          - id: risky
            path: result.risk
            equals: critical
            aciton: block
`,
		"invalid action": `
          - id: risky
            path: result.risk
            equals: critical
            action: deny
`,
		"false exists": `
          - id: risky
            path: result.risk
            exists: false
            action: block
`,
		"both conditions": `
          - id: risky
            path: result.risk
            equals: critical
            exists: true
            action: block
`,
		"numeric normalization": `
          - id: risky
            path: result.score
            equals: 10
            normalize: identifier
            action: block
`,
		"empty path list": `
          - id: risky
            path: []
            exists: true
            action: block
`,
		"indexed scalar path": `
          - id: risky
            path: "findings[0].severity"
            equals: critical
            action: block
`,
		"indexed path in list": `
          - id: risky
            path: [result.risk, "findings[0].severity"]
            equals: critical
            action: block
`,
	}

	for name, rules := range tests {
		t.Run(name, func(t *testing.T) {
			data := []byte("version: 1\nprofiles:\n  review:\n    scanners:\n      - id: demo\n        command: demo {{target}}\n        gate:\n          rules:\n" + rules)
			if err := schema.Validate(decodeYAMLAsJSON(t, data)); err == nil {
				t.Fatal("schema accepted invalid gate rule")
			}
		})
	}
}

func TestClawScanSchemaRejectsInvalidScannerDeclarations(t *testing.T) {
	schema := compileClawScanSchema(t)
	tests := map[string]string{
		"unknown built-in": "not-a-scanner",
		"custom scanner without target": `
        id: custom
        command: custom scan
`,
		"built-in scanner overridden as custom": `
        id: snyk
        command: custom scan {{target}}
`,
	}

	for name, scanner := range tests {
		t.Run(name, func(t *testing.T) {
			data := []byte("version: 1\nprofiles:\n  review:\n    scanners:\n      - " + scanner)
			if err := schema.Validate(decodeYAMLAsJSON(t, data)); err == nil {
				t.Fatal("schema accepted invalid scanner declaration")
			}
		})
	}
}

func compileClawScanSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data := readFixture(t, "clawscan.schema.json")
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("clawscan.schema.json", document); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile("clawscan.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func decodeYAMLAsJSON(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(false)
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode YAML fixture: %v", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode YAML fixture as JSON: %v", err)
	}
	jsonDecoder := json.NewDecoder(bytes.NewReader(encoded))
	jsonDecoder.UseNumber()
	if err := jsonDecoder.Decode(&value); err != nil {
		t.Fatalf("decode normalized JSON fixture: %v", err)
	}
	return value
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestProfileDocsAdvertiseThePublishedSchema(t *testing.T) {
	docs := readFixture(t, filepath.Join("..", "docs", "profiles.md"))
	const directive = "# yaml-language-server: $schema=https://raw.githubusercontent.com/openclaw/clawscan/main/schemas/clawscan.schema.json"
	if !strings.Contains(string(docs), directive) {
		t.Fatalf("profile docs do not include schema directive %q", directive)
	}
}
