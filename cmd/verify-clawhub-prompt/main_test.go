package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveClawHubDirReturnsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("clawhub", 0o755); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveClawHubDir("clawhub")
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dir, "clawhub")
	if resolved != want {
		t.Fatalf("resolved = %q, want %q", resolved, want)
	}
}

func TestBuildPromptTemplateReplacesSkillSpectorFixture(t *testing.T) {
	skillSpectorFixture := `{
  "status": "suspicious",
  "score": 55
}`
	prompt := strings.Join([]string{
		"SkillSpector findings supplied to Codex:",
		"```json",
		skillSpectorFixture,
		"```",
	}, "\n")

	template, err := buildPromptTemplate(prompt, skillSpectorFixture)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(template, "{{ scanners.skillspector }}") {
		t.Fatalf("template missing SkillSpector placeholder:\n%s", template)
	}
	if strings.Contains(template, skillSpectorFixture) {
		t.Fatalf("template still contains raw fixture:\n%s", template)
	}
}

func TestBuildPromptTemplateFromRenderedReplacesSkillSpectorBlock(t *testing.T) {
	prompt := strings.Join([]string{
		"Before",
		"SkillSpector findings supplied to Codex:",
		"```json",
		`{"status":"suspicious"}`,
		"```",
		"After",
	}, "\n")

	template, err := buildPromptTemplateFromRendered(prompt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(template, "{{ scanners.skillspector }}") {
		t.Fatalf("template missing SkillSpector placeholder:\n%s", template)
	}
	if strings.Contains(template, `{"status":"suspicious"}`) {
		t.Fatalf("template still contains raw fixture:\n%s", template)
	}
}

func TestClawHubWorkerOutputSchemaRelPath(t *testing.T) {
	workerSource := `
const root = resolve(new URL("../..", import.meta.url).pathname);
const schemaPath = join(root, "scripts/security/codex-scan-output.schema.json");
const args = [
  "--output-schema",
  schemaPath,
];
`
	got, err := clawHubWorkerOutputSchemaRelPath(workerSource)
	if err != nil {
		t.Fatal(err)
	}

	want := "scripts/security/codex-scan-output.schema.json"
	if got != want {
		t.Fatalf("schema path = %q, want %q", got, want)
	}
}

func TestClawHubWorkerOutputSchemaRelPathRequiresWorkerSchemaArg(t *testing.T) {
	workerSource := `
const root = resolve(new URL("../..", import.meta.url).pathname);
const schemaPath = join(root, "scripts/security/codex-scan-output.schema.json");
const args = [];
`
	_, err := clawHubWorkerOutputSchemaRelPath(workerSource)
	if err == nil {
		t.Fatal("expected missing worker schema arg to fail")
	}
	if !strings.Contains(err.Error(), "schemaPath to --output-schema") {
		t.Fatalf("error = %q", err)
	}
}

func TestClawHubWorkerOutputSchemaRelPathRequiresSchemaPathDeclaration(t *testing.T) {
	workerSource := `
const args = [
  "--output-schema",
  schemaPath,
];
`
	_, err := clawHubWorkerOutputSchemaRelPath(workerSource)
	if err == nil {
		t.Fatal("expected missing schemaPath declaration to fail")
	}
	if !strings.Contains(err.Error(), "schemaPath declaration") {
		t.Fatalf("error = %q", err)
	}
}
