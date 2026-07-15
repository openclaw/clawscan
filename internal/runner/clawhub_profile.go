package runner

const (
	clawHubProfileID    = "clawhub"
	clawHubAIGProfileID = "clawhub-aig"
)

func isClawHubParityProfile(profile string) bool {
	return profile == clawHubProfileID || profile == clawHubAIGProfileID
}
