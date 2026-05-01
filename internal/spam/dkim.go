package spam

import "strings"

// ScoreDKIM returns a spam score based on the DKIM verification result.
func ScoreDKIM(result string) float64 {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "pass":
		return 0
	case "fail":
		return 2.5
	case "none":
		return 0.3 // Many legitimate senders don't have DKIM; absence alone isn't suspicious.
	default:
		return 0.3
	}
}
