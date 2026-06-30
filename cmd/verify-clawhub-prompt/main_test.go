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
