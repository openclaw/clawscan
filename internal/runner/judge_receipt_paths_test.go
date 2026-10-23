package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestArtifactInspectionAdditionalPathContract(test *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "profiles", "clawhub", "output.schema.json"))
	if err != nil {
		test.Fatal(err)
	}
	expected := artifactInspectionChallenge{RequiredFile: "artifact/SKILL.md", Challenge: "workspace-only", RequiredSHA256: strings.Repeat("a", 64)}
	state := &judgeCommandState{workspace: test.TempDir(), files: map[string][]byte{"schema.json": raw}, inspection: &expected}
	filename, err := prepareJudgeOutputSchema("schema.json", state)
	if err != nil {
		test.Fatal(err)
	}
	rendered, err := os.ReadFile(filename)
	if err != nil {
		test.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(rendered, &document); err != nil {
		test.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("receipt.json", document["properties"].(map[string]any)["artifact_inspection"]); err != nil {
		test.Fatal(err)
	}
	schema, err := compiler.Compile("receipt.json")
	if err != nil {
		test.Fatal(err)
	}
	check := func(file string, valid bool) {
		test.Helper()
		receipt := map[string]any{
			"version": float64(2), "status": "completed", "challenge": expected.Challenge,
			"required_file": expected.RequiredFile, "required_file_sha256": expected.RequiredSHA256,
			"additional_files_inspected": []any{file},
		}
		schemaErr := schema.Validate(receipt)
		guardErr := validateArtifactInspectionReceipt(map[string]any{"artifact_inspection": receipt}, expected)
		if (schemaErr == nil) != valid || (guardErr == nil) != valid {
			test.Fatalf("path %q: valid=%v schema=%v Go=%v", file, valid, schemaErr, guardErr)
		}
		if receipt["additional_files_inspected"].([]any)[0] != file {
			test.Fatal("returned path was repaired")
		}
	}
	for _, file := range []string{
		"artifact/README.md", "artifact/a", "artifact/ab", "artifact/.a", "artifact/...", "artifact/..a",
		"artifact/.hidden/雪☃.md", "artifact/a b/quoted\"file\n.md", `artifact/back\slash.md`,
		"artifact/README.md\n", "artifact/\n",
	} {
		check(file, true)
	}
	for _, file := range []string{
		"artifact/../scanner-report.json", "artifact/sub/../../scanner-report.json", "artifact/a/../b",
		"artifact/.", "artifact/..", "artifact/a/.", "artifact/a/..", "artifact/./a", "artifact//a",
		"artifact/a//b", "artifact/a/", "artifact/", "artifact", "", "/artifact/a", "other/a",
	} {
		check(file, false)
	}
	receipt := map[string]any{
		"version": float64(2), "status": "completed", "challenge": expected.Challenge,
		"required_file": expected.RequiredFile, "required_file_sha256": expected.RequiredSHA256,
		"additional_files_inspected": []any{},
	}
	if err := schema.Validate(receipt); err != nil {
		test.Fatal(err)
	}
	if err := validateArtifactInspectionReceipt(map[string]any{"artifact_inspection": receipt}, expected); err != nil {
		test.Fatal(err)
	}
	var compare func(string, int)
	comparisons := 0
	compare = func(suffix string, remaining int) {
		file := "artifact/" + suffix
		receipt["additional_files_inspected"] = []any{file}
		guardErr := validateArtifactInspectionReceipt(map[string]any{"artifact_inspection": receipt}, expected)
		check(file, guardErr == nil)
		comparisons++
		if remaining > 0 {
			for _, character := range []string{".", "/", "a", "\n", "雪", `\`} {
				compare(suffix+character, remaining-1)
			}
		}
	}
	compare("", 5)
	test.Logf("compared rendered JSON Schema and independent Go guard on %d generated paths", comparisons)
}

func TestRunJudgeInvalidAdditionalPathRetainsEvidence(test *testing.T) {
	const badPath = "artifact/../scanner-report.json"
	const originalError = "Judge artifact inspection v2 additional_files_inspected contained an invalid artifact path."
	additional := []any{"artifact/.hidden/雪.md", "artifact/a b.md", `artifact/back\slash.md`, "artifact/README.md"}
	var budgets []time.Duration
	command := judgeRetryCommand(func(workspace string, timeout time.Duration) (CommandOutput, error) {
		budgets = append(budgets, timeout)
		receipt := judgeRetryReceipt(test, workspace)
		delete(receipt, "files_inspected")
		receipt["version"] = 2
		receipt["required_file"] = "artifact/SKILL.md"
		receipt["additional_files_inspected"] = additional
		if len(budgets) == 1 {
			receipt["additional_files_inspected"] = []any{additional[0], badPath, additional[1]}
			time.Sleep(20 * time.Millisecond)
		}
		return judgeRetryOutput(test, map[string]any{"verdict": "malicious", "artifact_inspection": receipt}), nil
	})
	result, err := RunJudge(JudgeOptions{Command: "judge"}, judgeRetryArtifact(test), command, time.Second, nil, SandboxModeOff)
	if err != nil || result.Status != "completed" || len(budgets) != 2 || len(result.Attempts) != 2 {
		test.Fatalf("result=%+v err=%v budgets=%v", result, err, budgets)
	}
	failed := result.Attempts[0]
	if failed.Status != "failed" || failed.Error != originalError || failed.Result.(map[string]any)["artifact_inspection"].(map[string]any)["additional_files_inspected"].([]any)[1] != badPath {
		test.Fatalf("original malformed receipt/error changed: %+v", failed)
	}
	returned := result.Result.(map[string]any)
	encoded, _ := json.Marshal(returned["artifact_inspection"].(map[string]any)["additional_files_inspected"])
	want, _ := json.Marshal(additional)
	if string(encoded) != string(want) || returned["verdict"] != "malicious" || result.Attempts[1].Status != "completed" {
		test.Fatal("security verdict or full additional-file evidence changed")
	}
	if budgets[0] > time.Second || budgets[1] <= 0 || budgets[1] >= budgets[0]-10*time.Millisecond || failed.Challenge == result.Attempts[1].Challenge {
		test.Fatalf("fresh retry did not share original deadline: %+v", result.Attempts)
	}
}
