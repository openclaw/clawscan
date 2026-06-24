package profiles

import (
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
	if got := strings.Join(clawhub.profile.Scanners, ","); got != "skillspector,virustotal,clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}

	skillsSH, ok := registry.Profile("skills-sh")
	if !ok {
		t.Fatal("missing skills-sh profile")
	}
	if got := strings.Join(skillsSH.profile.Scanners, ","); got != "socket,snyk" {
		t.Fatalf("skills-sh scanners = %q", got)
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
