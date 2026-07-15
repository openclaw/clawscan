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

func TestBuildPromptTemplateReplacesScannerFixtures(t *testing.T) {
	vtFixture := `{
  "status": "suspicious",
  "source": "engines"
}`
	skillSpectorFixture := `{
  "status": "suspicious",
  "score": 55
}`
	prompt := strings.Join([]string{
		"VirusTotal telemetry supplied to Codex:",
		"```json",
		vtFixture,
		"```",
		"SkillSpector findings supplied to Codex:",
		"```json",
		skillSpectorFixture,
		"```",
	}, "\n")

	template, err := buildPromptTemplate(prompt, vtFixture, skillSpectorFixture)
	if err != nil {
		t.Fatal(err)
	}

	for _, placeholder := range []string{"{{ scanners.virustotal }}", "{{ scanners.skillspector }}"} {
		if !strings.Contains(template, placeholder) {
			t.Fatalf("template missing placeholder %s:\n%s", placeholder, template)
		}
	}
	for _, fixture := range []string{vtFixture, skillSpectorFixture} {
		if strings.Contains(template, fixture) {
			t.Fatalf("template still contains raw fixture %q:\n%s", fixture, template)
		}
	}
}

func TestBuildPromptTemplateFromRenderedReplacesScannerBlocks(t *testing.T) {
	prompt := strings.Join([]string{
		"Before",
		"VirusTotal telemetry supplied to Codex:",
		"```json",
		`{"status":"clean"}`,
		"```",
		"Middle",
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
	for _, placeholder := range []string{"{{ scanners.virustotal }}", "{{ scanners.skillspector }}"} {
		if !strings.Contains(template, placeholder) {
			t.Fatalf("template missing placeholder %s:\n%s", placeholder, template)
		}
	}
	for _, fixture := range []string{`{"status":"clean"}`, `{"status":"suspicious"}`} {
		if strings.Contains(template, fixture) {
			t.Fatalf("template still contains raw fixture %q:\n%s", fixture, template)
		}
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
