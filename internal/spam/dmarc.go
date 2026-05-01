package spam

import "strings"

// ScoreDMARC returns a spam score based on the DMARC check result.
func ScoreDMARC(result string) float64 {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "pass":
		return 0
	case "fail":
		return 4.0
	case "none":
		return 0.2 // DMARC adoption is still partial; absence shouldn't penalize heavily.
	default:
		return 0.2
	}
}
