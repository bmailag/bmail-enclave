package gateway

import "strings"

// RedactEmail redacts the local part of an email address, showing only the domain.
// "alice@example.com" -> "***@example.com"
// Non-email strings are returned as "***".
func RedactEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return "***"
	}
	return "***@" + email[at+1:]
}
