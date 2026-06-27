package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRegistryReturnsSortedIDs(t *testing.T) {
	registry, err := NewProfileRegistry(map[string]resolvedProfile{
		"skills-sh": {profile: Profile{Scanners: []string{"snyk"}}},
		"clawhub":   {profile: Profile{Scanners: []string{"skillspector"}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(registry.IDs(), ","); got != "clawhub,skills-sh" {
		t.Fatalf("ids = %q", got)
	}
}

func TestDefaultProfileRegistryContainsEmbeddedBuiltIns(t *testing.T) {
	registry := DefaultProfileRegistry()

	clawhub, ok := registry.Profile("clawhub")
	if !ok {
		t.Fatal("missing clawhub profile")
	}
	if got := strings.Join(clawhub.profile.Scanners, ","); got != "skillspector,clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}
	if clawhub.configDir != "clawhub" {
		t.Fatalf("clawhub config dir = %q", clawhub.configDir)
	}
	if clawhub.source != "built-in" {
		t.Fatalf("clawhub source = %q", clawhub.source)
	}
	if string(clawhub.files["clawhub/prompt.md"]) == "" {
		t.Fatal("missing clawhub embedded prompt")
	}
	if string(clawhub.files["clawhub/output.schema.json"]) == "" {
		t.Fatal("missing clawhub embedded output schema")
	}

	skillsSH, ok := registry.Profile("skills-sh")
	if !ok {
		t.Fatal("missing skills-sh profile")
	}
	if got := strings.Join(skillsSH.profile.Scanners, ","); got != "socket,snyk" {
		t.Fatalf("skills-sh scanners = %q", got)
	}
	if skillsSH.configDir != "skills-sh" {
		t.Fatalf("skills-sh config dir = %q", skillsSH.configDir)
	}
	if skillsSH.source != "built-in" {
		t.Fatalf("skills-sh source = %q", skillsSH.source)
	}
}

func TestProfileRegistryRejectsUnknownScannerReferences(t *testing.T) {
	_, err := NewProfileRegistry(map[string]resolvedProfile{
		"bad": {profile: Profile{Scanners: []string{"missing-scanner"}}},
	})
	if err == nil || err.Error() != "Profile bad references unknown scanner: missing-scanner" {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectProfilesDiscoversNearestConfigAndShadowsBuiltIns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  clawhub:
    scanners:
      - clawscan-static
  local:
    scanners:
      - socket
`)
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	catalog, err := InspectProfiles(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(catalog.IDs(), ","); got != "clawhub,local,skills-sh" {
		t.Fatalf("profile ids = %q", got)
	}

	clawhub, ok := catalog.Profile("clawhub")
	if !ok {
		t.Fatal("missing clawhub profile")
	}
	if got := strings.Join(clawhub.Profile.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}
	if !strings.HasSuffix(clawhub.Source, ".clawscan.yml") {
		t.Fatalf("clawhub source = %q", clawhub.Source)
	}

	skillsSH, ok := catalog.Profile("skills-sh")
	if !ok {
		t.Fatal("missing skills-sh profile")
	}
	if skillsSH.Source != "built-in" {
		t.Fatalf("skills-sh source = %q", skillsSH.Source)
	}
}
