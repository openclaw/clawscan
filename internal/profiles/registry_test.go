package profiles

import (
	"strings"
	"testing"
)

func TestProfileRegistryReturnsSortedIDs(t *testing.T) {
	registry, err := NewProfileRegistry(map[string]resolvedProfile{
		"review":  {profile: Profile{Scanners: []string{"snyk"}}},
		"clawhub": {profile: Profile{Scanners: []string{"skillspector"}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(registry.IDs(), ","); got != "clawhub,review" {
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

	candidate, ok := registry.Profile("clawhub-aig")
	if !ok {
		t.Fatal("missing clawhub-aig profile")
	}
	if got := strings.Join(candidate.profile.Scanners, ","); got != "skillspector,aig" {
		t.Fatalf("clawhub-aig scanners = %q", got)
	}
	if candidate.configDir != "clawhub" {
		t.Fatalf("clawhub-aig config dir = %q", candidate.configDir)
	}
	if candidate.source != "built-in" {
		t.Fatalf("clawhub-aig source = %q", candidate.source)
	}
	if candidate.profile.Judge == nil || clawhub.profile.Judge == nil {
		t.Fatal("missing built-in judge")
	}
	if candidate.profile.Judge.Command != clawhub.profile.Judge.Command {
		t.Fatalf("clawhub-aig judge command differs from clawhub")
	}
	if string(candidate.files["clawhub/prompt.md"]) != string(clawhub.files["clawhub/prompt.md"]) {
		t.Fatal("clawhub-aig prompt differs from clawhub")
	}
	if string(candidate.files["clawhub/output.schema.json"]) != string(clawhub.files["clawhub/output.schema.json"]) {
		t.Fatal("clawhub-aig output schema differs from clawhub")
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

func TestInspectProfilesReturnsBuiltIns(t *testing.T) {
	catalog, err := InspectProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(catalog.IDs(), ","); got != "clawhub,clawhub-aig" {
		t.Fatalf("profile ids = %q", got)
	}

	clawhub, ok := catalog.Profile("clawhub")
	if !ok {
		t.Fatal("missing clawhub profile")
	}
	if got := strings.Join(clawhub.Profile.Scanners, ","); got != "skillspector,clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}
	if clawhub.Source != "built-in" {
		t.Fatalf("clawhub source = %q", clawhub.Source)
	}

}
