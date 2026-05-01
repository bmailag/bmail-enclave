package spam

import "strings"

// ScoreSPF returns a spam score based on the SPF check result.
func ScoreSPF(result string) float64 {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "pass":
		return 0
	case "fail":
		return 3.0
	case "softfail":
		return 1.5
	case "neutral", "none":
		return 0.3
	default:
		return 0.3
	}
}
