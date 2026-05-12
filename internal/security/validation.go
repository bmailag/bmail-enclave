// Package security provides input validation, sanitization, and security
// middleware for the Bmail mail service.
package security

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Validation errors.
var (
	ErrEmptyEmail       = errors.New("email address is empty")
	ErrInvalidEmail     = errors.New("invalid email address")
	ErrEmailTooLong     = errors.New("email address exceeds 254 characters")
	ErrPasswordTooShort = errors.New("password must be at least 12 characters")
	ErrPasswordTooWeak  = errors.New("password is too weak: requires at least 2 character classes")
	ErrEmptyDomain      = errors.New("domain is empty")
	ErrInvalidDomain    = errors.New("invalid domain name")
	ErrDomainTooLong    = errors.New("domain exceeds 253 characters")
)

// emailLocalPartChars defines valid characters for the local part of an email
// address (simplified RFC 5321 — no quoted strings or comments).
var emailRegex = regexp.MustCompile(
	`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`,
)

// injectionChars are characters that must never appear in an email address
// (SMTP injection prevention).
var injectionChars = []string{"\n", "\r", "\x00", "|", ";", "&"}

// domainRegex validates a hostname per RFC 952 / RFC 1123.
var domainRegex = regexp.MustCompile(
	`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`,
)

// emailPattern matches email-like strings for sanitization.
var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// ipv4Pattern matches IPv4 addresses for sanitization.
var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// ipv6Pattern matches common IPv6 address forms for sanitization.
var ipv6Pattern = regexp.MustCompile(`(?i)[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}`)

// ValidateEmailAddress validates an email address per RFC 5321 with injection
// character prevention.
func ValidateEmailAddress(addr string) error {
	if addr == "" {
		return ErrEmptyEmail
	}
	if len(addr) > 254 {
		return ErrEmailTooLong
	}

	// Check for injection characters.
	for _, c := range injectionChars {
		if strings.Contains(addr, c) {
			return fmt.Errorf("%w: contains forbidden character", ErrInvalidEmail)
		}
	}

	// Must have exactly one @.
	atCount := strings.Count(addr, "@")
	if atCount != 1 {
		return fmt.Errorf("%w: must contain exactly one @ symbol", ErrInvalidEmail)
	}

	parts := strings.SplitN(addr, "@", 2)
	local := parts[0]
	domainPart := parts[1]

	if local == "" {
		return fmt.Errorf("%w: empty local part", ErrInvalidEmail)
	}
	if len(local) > 64 {
		return fmt.Errorf("%w: local part exceeds 64 characters", ErrInvalidEmail)
	}
	if domainPart == "" {
		return fmt.Errorf("%w: empty domain part", ErrInvalidEmail)
	}

	// Validate with regex.
	if !emailRegex.MatchString(addr) {
		return fmt.Errorf("%w: does not match RFC 5321 pattern", ErrInvalidEmail)
	}

	return nil
}

// ValidatePassword checks that a password meets minimum requirements (F-13 fix).
// Requires at least 12 characters and at least 2 character classes
// (lowercase, uppercase, digits, special characters).
func ValidatePassword(pwd string) error {
	if len(pwd) < 12 {
		return ErrPasswordTooShort
	}
	classes := 0
	if strings.ContainsAny(pwd, "abcdefghijklmnopqrstuvwxyz") {
		classes++
	}
	if strings.ContainsAny(pwd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		classes++
	}
	if strings.ContainsAny(pwd, "0123456789") {
		classes++
	}
	if strings.IndexFunc(pwd, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) >= 0 {
		classes++
	}
	if classes < 2 {
		return ErrPasswordTooWeak
	}
	return nil
}

// ValidateDomain validates a domain/hostname.
func ValidateDomain(d string) error {
	if d == "" {
		return ErrEmptyDomain
	}
	if len(d) > 253 {
		return ErrDomainTooLong
	}

	// Check for injection characters.
	for _, c := range injectionChars {
		if strings.Contains(d, c) {
			return fmt.Errorf("%w: contains forbidden character", ErrInvalidDomain)
		}
	}

	if !domainRegex.MatchString(d) {
		return fmt.Errorf("%w: does not match hostname pattern", ErrInvalidDomain)
	}

	// Must have at least one dot for a real domain (except localhost).
	if !strings.Contains(d, ".") && d != "localhost" {
		return fmt.Errorf("%w: must contain at least one dot", ErrInvalidDomain)
	}

	return nil
}

// SanitizeLogString strips PII patterns (email addresses, IP addresses) from
// a string before it is written to logs.
func SanitizeLogString(s string) string {
	s = emailPattern.ReplaceAllString(s, "[EMAIL]")
	s = ipv4Pattern.ReplaceAllString(s, "[IPv4]")
	s = ipv6Pattern.ReplaceAllString(s, "[IPv6]")
	return s
}
