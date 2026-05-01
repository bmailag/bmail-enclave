package spam

import (
	"strings"
	"time"
)

// ScoreHeaders applies heuristic rules to message headers and returns
// a total score plus a list of triggered rule names.
func ScoreHeaders(headers map[string][]string) (float64, []string) {
	var score float64
	var triggered []string

	// Rule: missing Message-ID.
	if !headerPresent(headers, "Message-Id") && !headerPresent(headers, "Message-ID") {
		score += 1.0
		triggered = append(triggered, "missing_message_id")
	}

	// Rule: date anomalies (missing, unparseable, or far in the future/past).
	if dateScore, ruleName := checkDateAnomaly(headers); dateScore > 0 {
		score += dateScore
		triggered = append(triggered, ruleName)
	}

	// Rule: suspicious X-Mailer values.
	if xmailerScore, ruleName := checkXMailer(headers); xmailerScore > 0 {
		score += xmailerScore
		triggered = append(triggered, ruleName)
	}

	// Rule: charset anomalies.
	if charsetScore, ruleName := checkCharsetAnomaly(headers); charsetScore > 0 {
		score += charsetScore
		triggered = append(triggered, ruleName)
	}

	return score, triggered
}

// headerPresent checks if a header key exists (case-insensitive search).
func headerPresent(headers map[string][]string, key string) bool {
	// Try exact match first.
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return true
	}
	// Case-insensitive fallback.
	keyLower := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == keyLower && len(vals) > 0 {
			return true
		}
	}
	return false
}

// getHeaderValues retrieves header values case-insensitively.
func getHeaderValues(headers map[string][]string, key string) []string {
	keyLower := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == keyLower {
			return vals
		}
	}
	return nil
}

// checkDateAnomaly checks the Date header for anomalies.
func checkDateAnomaly(headers map[string][]string) (float64, string) {
	dateVals := getHeaderValues(headers, "Date")
	if len(dateVals) == 0 {
		return 1.0, "missing_date"
	}

	dateStr := dateVals[0]
	if dateStr == "" {
		return 1.0, "empty_date"
	}

	// Try common date formats.
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 -0700",
	}

	var parsed time.Time
	var parseErr error
	for _, fmt := range formats {
		parsed, parseErr = time.Parse(fmt, dateStr)
		if parseErr == nil {
			break
		}
	}

	if parseErr != nil {
		return 1.0, "unparseable_date"
	}

	now := time.Now()
	diff := now.Sub(parsed)

	// Date more than 24 hours in the future.
	if diff < -24*time.Hour {
		return 1.0, "date_future"
	}

	// Date more than 30 days in the past.
	if diff > 30*24*time.Hour {
		return 1.0, "date_old"
	}

	return 0, ""
}

// suspiciousMailers is the set of X-Mailer values associated with spam tools.
var suspiciousMailers = []string{
	"the bat",
	"mass mailer",
	"bulk",
	"blastmail",
	"mailmerge",
	"phpmailer",
	"swiftmailer",
	"mailchimp", // not inherently spam, but suspicious in unsolicited context
}

// checkXMailer checks for suspicious X-Mailer header values.
func checkXMailer(headers map[string][]string) (float64, string) {
	mailerVals := getHeaderValues(headers, "X-Mailer")
	if len(mailerVals) == 0 {
		return 0, ""
	}

	mailer := strings.ToLower(mailerVals[0])
	for _, suspicious := range suspiciousMailers {
		if strings.Contains(mailer, suspicious) {
			return 0.5, "suspicious_xmailer"
		}
	}

	return 0, ""
}

// checkCharsetAnomaly checks for unusual charset declarations.
func checkCharsetAnomaly(headers map[string][]string) (float64, string) {
	ctVals := getHeaderValues(headers, "Content-Type")
	if len(ctVals) == 0 {
		return 0, ""
	}

	ct := strings.ToLower(ctVals[0])

	// Unusual charsets that are sometimes used to bypass filters.
	unusualCharsets := []string{
		"koi8-r",
		"iso-2022-jp",
		"windows-874",
		"viscii",
		"big5",
		"gb2312",
		"gbk",
	}

	for _, charset := range unusualCharsets {
		if strings.Contains(ct, charset) {
			return 0.5, "unusual_charset"
		}
	}

	return 0, ""
}
