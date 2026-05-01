package spam

import "strings"

// trustedProviderDomains maps HELO/reverse-DNS suffixes of major email
// providers to a negative spam score bonus. These providers enforce strict
// outbound spam filtering, so mail originating from their infrastructure is
// very unlikely to be spam. The bonus offsets false positives from DNS
// resolution failures or missing authentication results.
var trustedProviderDomains = []string{
	// Google / Gmail
	".google.com",
	".googlemail.com",
	".gmail.com",
	// Microsoft / Outlook / Hotmail / Office 365
	".outlook.com",
	".hotmail.com",
	".microsoft.com",
	".protection.outlook.com",
	// Apple / iCloud
	".apple.com",
	".icloud.com",
	".me.com",
	// Yahoo / AOL
	".yahoo.com",
	".yahoodns.net",
	".aol.com",
	// ProtonMail
	".protonmail.ch",
	".proton.me",
	// Fastmail
	".fastmail.com",
	".messagingengine.com",
	// Amazon SES
	".amazonses.com",
	// Atonline
	".atonline.com",
	// Zoho
	".zoho.com",
	".zohomail.com",
}

// trustedFromDomains matches the sender's email domain.
var trustedFromDomains = []string{
	"gmail.com",
	"googlemail.com",
	"outlook.com",
	"hotmail.com",
	"live.com",
	"icloud.com",
	"me.com",
	"mac.com",
	"yahoo.com",
	"aol.com",
	"protonmail.com",
	"proton.me",
	"fastmail.com",
	"zoho.com",
}

// whitelistedDomains are domains whose mail is always delivered to inbox
// when both SPF and DKIM pass. If either check fails, normal spam scoring applies.
var whitelistedDomains = []string{
	"vp.net",
}

// isWhitelistedSender returns true if the sender's domain is whitelisted
// AND both SPF and DKIM passed authentication.
func isWhitelistedSender(from, spfResult, dkimResult string) bool {
	if spfResult != "pass" || dkimResult != "pass" {
		return false
	}
	fromDomain := ""
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		fromDomain = strings.ToLower(from[idx+1:])
	}
	for _, d := range whitelistedDomains {
		if fromDomain == d {
			return true
		}
	}
	return false
}

// scoreTrustedProvider returns a negative score (bonus) if the message
// originates from a known trusted email provider based on HELO identity
// and sender domain. Returns 0 if not matched.
func scoreTrustedProvider(helo, from string) float64 {
	heloLower := strings.ToLower(helo)
	for _, suffix := range trustedProviderDomains {
		if strings.HasSuffix(heloLower, suffix) {
			return -4.0
		}
	}

	// Fallback: check sender domain if HELO didn't match.
	fromDomain := ""
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		fromDomain = strings.ToLower(from[idx+1:])
	}
	for _, domain := range trustedFromDomains {
		if fromDomain == domain {
			return -3.0
		}
	}

	return 0
}
