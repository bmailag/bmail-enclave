package spam

import (
	"context"
	"net"
)

// CheckResult represents the outcome of a single spam check.
type CheckResult struct {
	Name    string  `json:"name"`
	Score   float64 `json:"score"`
	Details string  `json:"details,omitempty"`
}

// SpamResult is the aggregate output of all spam checks on a message.
type SpamResult struct {
	Score            float64       `json:"score"`
	IsSpam           bool          `json:"is_spam"`
	Checks           []CheckResult `json:"checks"`
	FolderAssignment string        `json:"folder_assignment"`
}

// SpamFilter is the aggregate scoring engine that combines all sub-checks.
type SpamFilter struct {
	dnsblLists      []string
	urlBlocklist    map[string]bool
	bayesClassifier *BayesClassifier
	config          *Config
	dnsResolver     DNSResolver
	rdnsResolver    ReverseDNSResolver
}

// NewSpamFilter creates a SpamFilter with default configuration.
func NewSpamFilter() *SpamFilter {
	cfg := DefaultConfig()
	return &SpamFilter{
		dnsblLists:      cfg.DNSBLLists,
		urlBlocklist:    cfg.URLBlocklist,
		bayesClassifier: NewBayesClassifier(),
		config:          cfg,
		dnsResolver:     DefaultResolver(),
		rdnsResolver:    DefaultReverseDNSResolver(),
	}
}

// NewSpamFilterWithConfig creates a SpamFilter with a custom configuration.
func NewSpamFilterWithConfig(cfg *Config) *SpamFilter {
	return &SpamFilter{
		dnsblLists:      cfg.DNSBLLists,
		urlBlocklist:    cfg.URLBlocklist,
		bayesClassifier: NewBayesClassifier(),
		config:          cfg,
		dnsResolver:     DefaultResolver(),
		rdnsResolver:    DefaultReverseDNSResolver(),
	}
}

// SetDNSResolver sets a custom DNS resolver (for testing).
func (sf *SpamFilter) SetDNSResolver(r DNSResolver) {
	sf.dnsResolver = r
}

// SetReverseDNSResolver sets a custom reverse DNS resolver (for testing).
func (sf *SpamFilter) SetReverseDNSResolver(r ReverseDNSResolver) {
	sf.rdnsResolver = r
}

// BayesClassifier returns the filter's Bayes classifier for training.
func (sf *SpamFilter) BayesClassifier() *BayesClassifier {
	return sf.bayesClassifier
}

// CheckMessage runs all spam checks against a message and returns the aggregate result.
func (sf *SpamFilter) CheckMessage(
	ctx context.Context,
	ip net.IP,
	helo string,
	from string,
	headers map[string][]string,
	body []byte,
	spfResult, dkimResult, dmarcResult string,
) *SpamResult {
	// Whitelisted domains: always deliver to inbox when both SPF and DKIM pass.
	if isWhitelistedSender(from, spfResult, dkimResult) {
		return &SpamResult{
			Score:            0,
			IsSpam:           false,
			Checks:           []CheckResult{{Name: "whitelist", Score: 0, Details: "trusted sender, SPF+DKIM pass"}},
			FolderAssignment: "inbox",
		}
	}

	var checks []CheckResult
	var totalScore float64

	// 1. SPF scoring.
	spfScore := ScoreSPF(spfResult) * sf.config.WeightSPF
	checks = append(checks, CheckResult{Name: "spf", Score: spfScore, Details: spfResult})
	totalScore += spfScore

	// 2. DKIM scoring.
	dkimScore := ScoreDKIM(dkimResult) * sf.config.WeightDKIM
	checks = append(checks, CheckResult{Name: "dkim", Score: dkimScore, Details: dkimResult})
	totalScore += dkimScore

	// 3. DMARC scoring.
	dmarcScore := ScoreDMARC(dmarcResult) * sf.config.WeightDMARC
	checks = append(checks, CheckResult{Name: "dmarc", Score: dmarcScore, Details: dmarcResult})
	totalScore += dmarcScore

	// 4. DNSBL check (network call).
	dnsblScore, dnsblMatched := CheckDNSBLWithResolver(ctx, ip, sf.dnsblLists, sf.dnsResolver)
	dnsblScore *= sf.config.WeightDNSBL
	dnsblDetails := ""
	if len(dnsblMatched) > 0 {
		dnsblDetails = "matched: " + joinStrings(dnsblMatched)
	}
	checks = append(checks, CheckResult{Name: "dnsbl", Score: dnsblScore, Details: dnsblDetails})
	totalScore += dnsblScore

	// 5. Reverse DNS check (network call).
	rdnsScore := CheckReverseDNSWithResolver(ctx, ip, helo, sf.rdnsResolver) * sf.config.WeightReverseDNS
	checks = append(checks, CheckResult{Name: "reverse_dns", Score: rdnsScore})
	totalScore += rdnsScore

	// 6. Header heuristics.
	headerScore, headerRules := ScoreHeaders(headers)
	headerScore *= sf.config.WeightHeaders
	headerDetails := ""
	if len(headerRules) > 0 {
		headerDetails = joinStrings(headerRules)
	}
	checks = append(checks, CheckResult{Name: "headers", Score: headerScore, Details: headerDetails})
	totalScore += headerScore

	// 7. Bayes classification (CPU-intensive).
	features := ExtractFeatures(body)
	bayesProb := sf.bayesClassifier.Predict(features)
	bayesScore := bayesProb * 5.0 * sf.config.WeightBayes
	checks = append(checks, CheckResult{Name: "bayes", Score: bayesScore})
	totalScore += bayesScore

	// 8. URL analysis.
	urls := ExtractURLs(body)
	urlScore := ScoreURLs(urls, sf.urlBlocklist) * sf.config.WeightURLs
	checks = append(checks, CheckResult{Name: "urls", Score: urlScore})
	totalScore += urlScore

	// 9. Trusted provider bonus — major providers already filter outbound spam,
	// so messages from their SMTP servers get a negative score adjustment.
	trustedBonus := scoreTrustedProvider(helo, from)
	if trustedBonus < 0 {
		checks = append(checks, CheckResult{Name: "trusted_provider", Score: trustedBonus, Details: helo})
		totalScore += trustedBonus
	}

	// Clamp to zero — trusted provider bonus should not make score negative.
	if totalScore < 0 {
		totalScore = 0
	}

	// Determine spam classification.
	isSpam := totalScore >= sf.config.SpamThreshold
	folder := "inbox"
	if isSpam {
		folder = "junk"
	}

	return &SpamResult{
		Score:            totalScore,
		IsSpam:           isSpam,
		Checks:           checks,
		FolderAssignment: folder,
	}
}

// joinStrings joins a string slice with ", ".
func joinStrings(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += ", " + s
	}
	return result
}
