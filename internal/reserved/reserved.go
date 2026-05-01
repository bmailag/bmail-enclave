// Package reserved enumerates mailbox local-parts that must never be
// claimable by self-service signup or by custom-domain users on a
// bmail-managed default domain. The list is RFC-driven (RFC 5321,
// 2142, 9116) plus a couple of platform-operational additions.
//
// Inbound mail to these addresses is routed to the role-message inbox
// surfaced under /admin to platform admins / support; it never lands
// in any individual user's mailbox.
//
// This lives outside internal/auth so the smtp-inbound enclave (which
// only needs to ask "is this address reserved?") does not pull the
// rest of the auth package — OPAQUE login, recovery, settings, etc. —
// into its build closure.
package reserved

import (
	"strings"
)

var reservedLocalParts = map[string]bool{
	"postmaster":    true, // RFC 5321 §4.5.1 — required
	"abuse":         true, // RFC 2142 — FBL / complaint dest
	"security":      true, // RFC 9116 — pair with /.well-known/security.txt
	"hostmaster":    true, // RFC 2142 — DNS issues
	"webmaster":     true, // RFC 2142 — web issues
	"noc":           true, // RFC 2142 — network operations
	"dmarc-reports": true, // DMARC rua/ruf landing address
	"admin":         true, // platform-admin role; never user-claimable
	"root":          true, // shell-name confusion with infra
	"mailer-daemon": true, // bounce sender; never user-claimable
}

// IsLocalPart returns true if the given mailbox local-part
// (case-insensitive, plus-tag stripped) is platform-reserved.
func IsLocalPart(localPart string) bool {
	lp := strings.ToLower(strings.TrimSpace(localPart))
	if i := strings.Index(lp, "+"); i >= 0 {
		lp = lp[:i]
	}
	return reservedLocalParts[lp]
}

// IsAddress returns true if the given full address has a reserved
// local-part. Domain is ignored — the caller is responsible for
// deciding whether the reservation applies (default-domain signup,
// or custom-domain on a bmail-managed tenant). The address is expected
// in `local@domain` form; a malformed address returns false.
func IsAddress(address string) bool {
	at := strings.IndexByte(address, '@')
	if at <= 0 {
		return false
	}
	return IsLocalPart(address[:at])
}
