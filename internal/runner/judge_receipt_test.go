package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRunJudgeVersion2Receipt(test *testing.T) {
	for _, verdict := range []string{"benign", "suspicious", "malicious"} {
		test.Run(verdict, func(test *testing.T) {
			target := test.TempDir()
			for name, content := range map[string]string{"SKILL.md": "# Demo", "README.md": "# Additional evidence"} {
				if err := os.WriteFile(filepath.Join(target, name), []byte(content), 0o600); err != nil {
					test.Fatal(err)
				}
			}
			files := map[string][]byte{}
			for _, name := range []string{"prompt.md", "output.schema.json"} {
				raw, err := os.ReadFile(filepath.Join("..", "profiles", "clawhub", name))
				if err != nil {
					test.Fatal(err)
				}
				files["clawhub/"+name] = raw
			}
			commandRunner := &recordingCommandRunner{}
			commandRunner.runHook = func(_ string, _ []string, workspace string) error {
				receipt := judgeRetryReceipt(test, workspace)
				receipt["version"] = 2
				receipt["required_file"] = "artifact/SKILL.md"
				receipt["additional_files_inspected"] = []string{"artifact/README.md"}
				delete(receipt, "files_inspected")
				result := map[string]any{"artifact_inspection": receipt, "verdict": verdict}
				schemaRaw, err := os.ReadFile(filepath.Join(workspace, "schema.json"))
				if err != nil {
					return err
				}
				var document map[string]any
				if err := json.Unmarshal(schemaRaw, &document); err != nil {
					return err
				}
				inspectionSchema := document["properties"].(map[string]any)["artifact_inspection"]
				compiler := jsonschema.NewCompiler()
				if err := compiler.AddResource("receipt.json", inspectionSchema); err != nil {
					return err
				}
				schema, err := compiler.Compile("receipt.json")
				if err != nil {
					return err
				}
				raw, err := json.Marshal(receipt)
				if err != nil {
					return err
				}
				value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if err != nil {
					return err
				}
				if err := schema.Validate(value); err != nil {
					test.Fatalf("rendered schema rejected complete v2 receipt: %v", err)
				}
				value.(map[string]any)["required_file"] = "artifact/NOT.md"
				if schema.Validate(value) == nil {
					test.Fatal("rendered schema accepted the wrong required file")
				}
				delete(value.(map[string]any), "required_file")
				if schema.Validate(value) == nil {
					test.Fatal("rendered schema accepted an omitted required file")
				}
				if strings.Contains(string(schemaRaw), receipt["challenge"].(string)) || strings.Contains(string(schemaRaw), receipt["required_file_sha256"].(string)) {
					test.Fatal("schema revealed the expected challenge or hash")
				}
				commandRunner.writeOutput = string(judgeRetryOutput(test, result).Stdout)
				return nil
			}
			result, err := RunJudge(JudgeOptions{
				Command: "judge --prompt {{ prompt:clawhub/prompt.md }} --schema {{ output_schema:clawhub/output.schema.json }} --output {{ output }}", Files: files,
			}, Artifact{Profile: "clawhub", Target: Target{Kind: "skill", ResolvedPath: target}}, commandRunner, time.Second, nil, SandboxModeOff)
			if err != nil {
				test.Fatal(err)
			}
			if result.Status != "completed" || len(result.Attempts) != 1 {
				test.Fatalf("v2 receipt failed: %+v", result)
			}
			inspection := result.Result.(map[string]any)["artifact_inspection"].(map[string]any)
			if result.Result.(map[string]any)["verdict"] != verdict || inspection["required_file"] != "artifact/SKILL.md" || inspection["additional_files_inspected"].([]any)[0] != "artifact/README.md" {
				test.Fatal("returned security verdict or complete file record changed")
			}
		})
	}
}

func TestRunJudgeVersion2ReceiptFailsClosed(test *testing.T) {
	for _, failure := range []string{"wrong_path", "path_alias", "missing_path", "wrong_hash", "wrong_challenge", "missing_additional", "wrong_additional", "traversal", "unknown_version", "string_version", "hybrid_v1", "versionless_hybrid", "versionless_required", "versionless_additional"} {
		test.Run(failure, func(test *testing.T) {
			target := test.TempDir()
			if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o600); err != nil {
				test.Fatal(err)
			}
			command := judgeRetryCommand(func(workspace string, _ time.Duration) (CommandOutput, error) {
				receipt := judgeRetryReceipt(test, workspace)
				receipt["version"] = 2
				receipt["required_file"] = "artifact/SKILL.md"
				receipt["additional_files_inspected"] = []string{}
				delete(receipt, "files_inspected")
				switch failure {
				case "wrong_path":
					receipt["required_file"] = "artifact/NOT.md"
				case "path_alias":
					receipt["required_file"] = "artifact/./SKILL.md"
				case "missing_path":
					delete(receipt, "required_file")
				case "wrong_hash":
					receipt["required_file_sha256"] = strings.Repeat("0", 64)
				case "wrong_challenge":
					receipt["challenge"] = "wrong"
				case "missing_additional":
					delete(receipt, "additional_files_inspected")
				case "wrong_additional":
					receipt["additional_files_inspected"] = []any{42}
				case "traversal":
					receipt["additional_files_inspected"] = []string{"artifact/../outside"}
				case "unknown_version":
					receipt["version"] = 3
				case "string_version":
					receipt["version"] = "2"
				case "hybrid_v1":
					receipt["files_inspected"] = []string{"artifact/SKILL.md"}
				case "versionless_hybrid", "versionless_required", "versionless_additional":
					delete(receipt, "version")
					receipt["files_inspected"] = []string{"artifact/SKILL.md"}
					if failure == "versionless_hybrid" {
						receipt["required_file"] = "artifact/NOT.md"
					} else if failure == "versionless_required" {
						delete(receipt, "additional_files_inspected")
					} else {
						delete(receipt, "required_file")
					}
				}
				return judgeRetryOutput(test, map[string]any{"verdict": "suspicious", "artifact_inspection": receipt}), nil
			})
			result, err := RunJudge(JudgeOptions{Command: "judge"}, Artifact{Profile: "clawhub", Target: Target{Kind: "skill", ResolvedPath: target}}, command, time.Second, nil, SandboxModeOff)
			if err != nil {
				test.Fatal(err)
			}
			if result.Status != "failed" || len(result.Attempts) != 2 || result.Attempts[0].Status != "failed" || result.Attempts[1].Status != "failed" {
				test.Fatalf("malformed v2 receipt did not retain two failed native attempts: %+v", result)
			}
		})
	}
}

func TestPrepareJudgeOutputSchemaInspectionPath(test *testing.T) {
	template := []byte(`{"type":"string","enum":["{{ artifact_inspection.required_file }}"]}`)
	for _, required := range []string{"artifact/SKILL.md", "artifact/package.json", "artifact/quoted\"file\n雪.md", `artifact/back\slash.md`, "artifact/{{ artifact_inspection.required_file }}"} {
		test.Run(required, func(test *testing.T) {
			state := &judgeCommandState{
				workspace: test.TempDir(), files: map[string][]byte{"schema.json": template},
				inspection: &artifactInspectionChallenge{RequiredFile: required, Challenge: "workspace-only-challenge", RequiredSHA256: strings.Repeat("f", 64)},
			}
			filename, err := prepareJudgeOutputSchema("schema.json", state)
			if err != nil {
				test.Fatal(err)
			}
			raw, err := os.ReadFile(filename)
			if err != nil {
				test.Fatal(err)
			}
			var schema struct{ Enum []string }
			if err := json.Unmarshal(raw, &schema); err != nil {
				test.Fatal(err)
			}
			if len(schema.Enum) != 1 || schema.Enum[0] != required || state.outputSchemaSHA != sha256Hex(string(raw)) {
				test.Fatal("required-file enum or rendered provenance changed")
			}
			if bytes.Contains(raw, []byte(state.inspection.Challenge)) || bytes.Contains(raw, []byte(state.inspection.RequiredSHA256)) {
				test.Fatal("schema exposed expected challenge/hash")
			}
		})
	}
	for _, example := range []struct {
		name       string
		template   []byte
		inspection *artifactInspectionChallenge
	}{
		{name: "no_challenge", template: template},
		{name: "partial_string", template: []byte(`{"type":"string","enum":["prefix{{ artifact_inspection.required_file }}"]}`), inspection: &artifactInspectionChallenge{}},
	} {
		test.Run(example.name, func(test *testing.T) {
			state := &judgeCommandState{workspace: test.TempDir(), files: map[string][]byte{"schema.json": example.template}, inspection: example.inspection}
			if _, err := prepareJudgeOutputSchema("schema.json", state); err == nil {
				test.Fatal("unbound inspection schema did not fail closed")
			}
		})
	}
}

func TestRunJudgeVersion2ReceiptRetriesShareDeadline(test *testing.T) {
	var budgets []time.Duration
	var firstChallenge string
	command := judgeRetryCommand(func(workspace string, timeout time.Duration) (CommandOutput, error) {
		budgets = append(budgets, timeout)
		receipt := judgeRetryReceipt(test, workspace)
		receipt["version"] = 2
		receipt["required_file"] = "artifact/SKILL.md"
		receipt["additional_files_inspected"] = []string{}
		delete(receipt, "files_inspected")
		if len(budgets) == 1 {
			firstChallenge = receipt["challenge"].(string)
			time.Sleep(20 * time.Millisecond)
			receipt["required_file"] = "artifact/NOT.md"
		} else {
			receipt["challenge"] = firstChallenge
		}
		return judgeRetryOutput(test, map[string]any{"artifact_inspection": receipt}), nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(test), command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "failed" || len(budgets) != 2 || len(result.Attempts) != 2 {
		test.Fatalf("result = %+v, err = %v, budgets = %v", result, err, budgets)
	}
	if budgets[0] > time.Second || budgets[1] >= budgets[0]-10*time.Millisecond || budgets[1] <= 0 {
		test.Fatalf("retry reset timeout budget: %v", budgets)
	}
	if result.Attempts[0].Challenge == result.Attempts[1].Challenge || !strings.Contains(result.Error, "challenge did not match") {
		test.Fatal("v2 retry accepted a stale challenge")
	}
}
