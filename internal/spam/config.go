package spam

// Config holds tunable thresholds and weights for the spam filter.
type Config struct {
	// SpamThreshold is the score at or above which a message is classified as spam.
	SpamThreshold float64

	// Weight multipliers for each check category.
	WeightSPF        float64
	WeightDKIM       float64
	WeightDMARC      float64
	WeightDNSBL      float64
	WeightReverseDNS float64
	WeightHeaders    float64
	WeightBayes      float64
	WeightURLs       float64

	// DNSBLLists is the set of DNS blocklists to query.
	DNSBLLists []string

	// URLShorteners is the set of known URL shortener domains.
	URLShorteners map[string]bool

	// URLBlocklist is the set of blocked URL domains.
	URLBlocklist map[string]bool
}

// DefaultConfig returns a Config with sensible production defaults.
//
// All weights start at 1.0 as a uniform baseline. In production, tune based on
// false-positive/negative rates from training data. Typical tuned values after
// sufficient corpus (10k+ messages): WeightBayes 2.0, WeightDNSBL 1.5,
// WeightHeaders 0.8. The threshold of 5.0 is deliberately conservative
// (favors low false-positive rate over catch rate).
func DefaultConfig() *Config {
	return &Config{
		SpamThreshold: 5.0,

		WeightSPF:        1.0,
		WeightDKIM:       1.0,
		WeightDMARC:      1.0,
		WeightDNSBL:      1.0,
		WeightReverseDNS: 1.0,
		WeightHeaders:    1.0,
		WeightBayes:      1.0,
		WeightURLs:       1.0,

		DNSBLLists: []string{
			"zen.spamhaus.org",
			"b.barracudacentral.org",
		},

		URLShorteners: map[string]bool{
			"bit.ly":    true,
			"t.co":      true,
			"goo.gl":    true,
			"tinyurl.com": true,
			"ow.ly":     true,
			"is.gd":     true,
			"buff.ly":   true,
			"rebrand.ly": true,
			"short.io":  true,
		},

		URLBlocklist: map[string]bool{},
	}
}
