package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/clawhubprompt"
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

func TestBuildPromptTemplatePreservesTextOutsideScannerEvidence(t *testing.T) {
	const system = "An optional value may be null.\nSkillSpector findings supplied to Codex:\n```json\nnull\n```"
	prompt, err := clawhubprompt.Build(system, clawhubprompt.Job{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := buildPromptTemplate(prompt)
	if err != nil {
		t.Fatal(err)
	}
	const evidence = "SkillSpector findings supplied to Codex:\n```json\n"
	want := system + strings.Replace(strings.TrimPrefix(prompt, system), evidence+"null", evidence+"{{ scanners.skillspector }}", 1)
	if want == prompt || template != want {
		t.Fatalf("exported template differs outside the expected substitution:\n%s", template)
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
