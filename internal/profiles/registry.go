package profiles

import (
	"sort"

	"github.com/openclaw/clawscan/internal/runner"
)

type ProfileRegistry struct {
	profiles map[string]resolvedProfile
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
