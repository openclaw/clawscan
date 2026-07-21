package profiles

import (
	"sort"

	"github.com/openclaw/clawscan/internal/runner"
	"gopkg.in/yaml.v3"
)

type ProfileRegistry struct {
	profiles map[string]resolvedProfile
}

type ProfileInfo struct {
	ID      string
	Profile Profile
	Source  string
}

type ProfileCatalog struct {
	profiles map[string]ProfileInfo
}

func NewProfileRegistry(profiles map[string]resolvedProfile) (ProfileRegistry, error) {
	registry := ProfileRegistry{profiles: map[string]resolvedProfile{}}
	for id, profile := range profiles {
		if err := validateProfile(id, profile.profile); err != nil {
			return ProfileRegistry{}, err
		}
		for _, scanner := range profile.profile.Scanners {
			if !runner.DefaultScannerRegistry().Contains(scanner) {
				return ProfileRegistry{}, unknownScannerInProfileError(id, scanner)
			}
		}
		registry.profiles[id] = profile
	}
	return registry, nil
}

func DefaultProfileRegistry() ProfileRegistry {
	profiles, err := loadBuiltinProfiles()
	if err != nil {
		panic(err)
	}
	registry, err := NewProfileRegistry(profiles)
	if err != nil {
		panic(err)
	}
	return registry
}

func ProfileIDs() []string {
	return DefaultProfileRegistry().IDs()
}

func InspectProfiles(cwd string) (ProfileCatalog, error) {
	registry, _, err := loadConfigs(cwd, "", true)
	if err != nil {
		return ProfileCatalog{}, err
	}
	catalog := ProfileCatalog{profiles: map[string]ProfileInfo{}}
	for _, id := range registry.IDs() {
		resolved, _ := registry.Profile(id)
		profile := resolved.profile
		if !sandboxIsZero(resolved.sandbox) {
			sandbox := resolved.sandbox
			profile.Sandbox = &sandbox
		}
		catalog.profiles[id] = ProfileInfo{
			ID:      id,
			Profile: profile,
			Source:  resolved.source,
		}
	}
	return catalog, nil
}

func (catalog ProfileCatalog) IDs() []string {
	ids := make([]string, 0, len(catalog.profiles))
	for id := range catalog.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (catalog ProfileCatalog) Profile(id string) (ProfileInfo, bool) {
	profile, ok := catalog.profiles[id]
	return profile, ok
}

func (catalog ProfileCatalog) Config() Config {
	config := Config{Version: 1, Profiles: map[string]Profile{}}
	for _, id := range catalog.IDs() {
		config.Profiles[id] = catalog.profiles[id].Profile
	}
	return config
}

func (catalog ProfileCatalog) YAML() ([]byte, error) {
	return yaml.Marshal(catalog.Config())
}

func (registry ProfileRegistry) Profile(id string) (resolvedProfile, bool) {
	profile, ok := registry.profiles[id]
	return profile, ok
}

func (registry ProfileRegistry) Merge(profiles map[string]resolvedProfile) (ProfileRegistry, error) {
	merged := map[string]resolvedProfile{}
	for id, profile := range registry.profiles {
		merged[id] = profile
	}
	for id, profile := range profiles {
		merged[id] = profile
	}
	return NewProfileRegistry(merged)
}

func (registry ProfileRegistry) IDs() []string {
	ids := make([]string, 0, len(registry.profiles))
	for id := range registry.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sandboxIsZero(sandbox Sandbox) bool {
	return sandbox.Mode == "" && sandbox.Image == "" && len(sandbox.Env) == 0
}
