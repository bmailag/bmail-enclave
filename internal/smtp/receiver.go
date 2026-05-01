package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"

	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/reserved"
	"github.com/bmailag/bmail/internal/storage"
)

// SMTP server configuration constants.
const (
	smtpReadWriteTimeout = 60 * time.Second
	maxMessageBytes      = 37 * 1024 * 1024 // 37 MB — allows 25MB attachments after MIME base64 encoding (~33% overhead) + headers
	maxRecipients        = 50
	rcptLookupTimeout    = 5 * time.Second
	dataProcessTimeout   = 30 * time.Second
	rcptTimingPad        = 50 * time.Millisecond
)

// SMTPReceiver is the SMTP server that receives inbound mail.
type SMTPReceiver struct {
	authStore          *storage.AuthStore
	billingStore       *storage.BillingStore       // optional — enables over-cap soft-bounce at RCPT TO
	driveStore         *storage.DriveStore         // optional — feeds drive usage into the over-cap check
	adminStore         *storage.AdminStore         // optional — enables role-message capture for postmaster/abuse/...
	defaultDomainStore *storage.DefaultDomainStore // optional — required alongside adminStore to scope reservation to bmail-managed domains
	pipeline           *Pipeline
	server             *gosmtp.Server
	tlsConfig          *tls.Config
	connLimiter        *ConnRateLimiter
}

// ReceiverOption configures optional dependencies for SMTPReceiver.
type ReceiverOption func(*SMTPReceiver)

// WithReceiverRedis sets the Redis client for connection rate limiting.
func WithReceiverRedis(rdb *redis.Client) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.connLimiter = NewConnRateLimiter(WithConnRateRedis(rdb))
	}
}

// WithConnLimiter sets a custom connection rate limiter (useful for testing).
func WithConnLimiter(limiter *ConnRateLimiter) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.connLimiter = limiter
	}
}

// WithBillingStore enables the over-cap soft-bounce at RCPT TO. When set,
// the receiver checks effective storage limit vs used for the recipient
// and returns "452 4.2.2 mailbox over quota" if over. Without this,
// quota enforcement falls back to whatever the worker / mail service
// applies post-delivery (which today is nothing for the inbound path).
func WithBillingStore(billing *storage.BillingStore) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.billingStore = billing
	}
}

// WithDriveStore feeds drive usage into the over-cap check (mail + drive
// share the same per-user storage cap). Optional — without it, the
// quota check sees only mail usage.
func WithDriveStore(drive *storage.DriveStore) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.driveStore = drive
	}
}

// WithAdminStore enables role-message capture for reserved local-parts
// (postmaster, abuse, security, …). When set, RCPT TO for an unknown
// reserved address on a default domain is accepted and the message is
// written to role_messages instead of routed through the encrypted
// mail pipeline. Pair with WithDefaultDomainStore so the reservation
// only applies to bmail-managed domains; on custom domains, owners
// can still register their own postmaster/abuse handles.
func WithAdminStore(admin *storage.AdminStore) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.adminStore = admin
	}
}

// WithDefaultDomainStore scopes reserved-address capture to
// bmail-managed default domains. Required for role-message capture to
// kick in.
func WithDefaultDomainStore(d *storage.DefaultDomainStore) ReceiverOption {
	return func(r *SMTPReceiver) {
		r.defaultDomainStore = d
	}
}

// NewSMTPReceiver creates a new SMTP receiver.
func NewSMTPReceiver(authStore *storage.AuthStore, pipeline *Pipeline, tlsConfig *tls.Config, opts ...ReceiverOption) *SMTPReceiver {
	r := &SMTPReceiver{
		authStore:   authStore,
		pipeline:    pipeline,
		tlsConfig:   tlsConfig,
		connLimiter: NewConnRateLimiter(), // default: in-memory only
	}

	for _, opt := range opts {
		opt(r)
	}

	s := gosmtp.NewServer(r)
	s.Domain = os.Getenv("SMTP_HOSTNAME")
	if s.Domain == "" {
		s.Domain = "bmail.ag"
	}
	s.ReadTimeout = smtpReadWriteTimeout
	s.WriteTimeout = smtpReadWriteTimeout
	s.MaxMessageBytes = maxMessageBytes
	s.MaxRecipients = maxRecipients
	s.AllowInsecureAuth = false

	if tlsConfig != nil {
		s.TLSConfig = tlsConfig
	}

	r.server = s
	return r
}

// ListenAndServe starts the SMTP server on the given address.
func (r *SMTPReceiver) ListenAndServe(addr string) error {
	r.server.Addr = addr
	slog.Info("SMTP server listening", "addr", addr)
	return r.server.ListenAndServe()
}

// Shutdown gracefully drains inflight SMTP sessions before closing.
func (r *SMTPReceiver) Shutdown(ctx context.Context) error {
	return r.server.Shutdown(ctx)
}

// Close immediately shuts down the SMTP server without draining.
func (r *SMTPReceiver) Close() error {
	return r.server.Close()
}

// NewSession implements the go-smtp Backend interface.
func (r *SMTPReceiver) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	// Per-IP connection rate limiting.
	if r.connLimiter != nil && c != nil {
		if addr := c.Conn().RemoteAddr(); addr != nil {
			if !r.connLimiter.Allow(addr) {
				return nil, &gosmtp.SMTPError{
					Code:    421,
					Message: "too many connections from your IP, try again later",
				}
			}
		}
	}

	return &session{
		receiver: r,
		conn:     c,
	}, nil
}

// session implements the go-smtp Session interface.
type session struct {
	receiver       *SMTPReceiver
	conn           *gosmtp.Conn
	from           string
	recipients     []string // user-mail recipients, routed through the encrypted pipeline
	roleRecipients []string // reserved-address recipients on default domains, routed to role_messages
	clientIP       net.IP
	helo           string
}

// AuthMechanisms implements gosmtp.Session — we don't require auth for inbound.
func (s *session) AuthMechanisms() []string {
	return nil
}

// Auth implements gosmtp.Session — reject auth attempts on inbound.
func (s *session) Auth(mech string) (gosmtp.Session, error) {
	return nil, errors.New("authentication not supported on inbound")
}

// Mail implements gosmtp.Session — handles MAIL FROM.
func (s *session) Mail(from string, opts *gosmtp.MailOptions) error {
	// Basic validation of the from address.
	from = strings.TrimSpace(from)
	if from == "" {
		// Empty MAIL FROM is allowed (bounce messages per RFC 5321).
		s.from = ""
		return nil
	}

	// Extract just the email address if it's in angle brackets.
	from = stripAngleBrackets(from)

	// RFC 5321 validation: reject control characters and require '@'.
	if from != "" {
		if containsControlChars(from) {
			return &gosmtp.SMTPError{Code: 553, EnhancedCode: gosmtp.EnhancedCode{5, 1, 7}, Message: "invalid sender address"}
		}
		if !strings.Contains(from, "@") {
			return &gosmtp.SMTPError{Code: 553, EnhancedCode: gosmtp.EnhancedCode{5, 1, 7}, Message: "invalid sender address format"}
		}
	}

	s.from = from

	// Capture client IP and HELO hostname from the connection.
	if s.conn != nil {
		if addr := s.conn.Conn().RemoteAddr(); addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				s.clientIP = tcpAddr.IP
			}
		}
		s.helo = s.conn.Hostname()
	}

	return nil
}

// Rcpt implements gosmtp.Session — handles RCPT TO.
func (s *session) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	to = stripAngleBrackets(strings.TrimSpace(to))
	if to == "" || containsControlChars(to) {
		return &gosmtp.SMTPError{
			Code:         553,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 3},
			Message:      "bad recipient address syntax",
		}
	}

	// Reserved local-part on a bmail-managed default domain → role
	// inbox. Skip the user-lookup + storage-cap gates because these
	// are platform addresses with no user row. Reservation only
	// applies on default domains so custom-domain owners can still
	// register their own postmaster/abuse mailboxes against their own
	// users table row.
	rcptStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), rcptLookupTimeout)
	defer cancel()

	if s.receiver.adminStore != nil && s.receiver.defaultDomainStore != nil {
		if at := strings.IndexByte(to, '@'); at > 0 {
			local, dom := to[:at], to[at+1:]
			if reserved.IsLocalPart(local) {
				isDefault, derr := s.receiver.defaultDomainStore.IsDefaultDomain(ctx, dom)
				if derr == nil && isDefault {
					// Pad timing too — still leaks "default domain or
					// not" via response time, but doesn't leak
					// per-user enumeration.
					padSMTPTiming(rcptStart)
					s.roleRecipients = append(s.roleRecipients, strings.ToLower(to))
					return nil
				}
			}
		}
	}

	// Look up the recipient in the auth store.
	// Timing is padded to prevent user enumeration via RCPT TO probing.
	user, err := s.receiver.authStore.GetUserByAddress(ctx, to)

	padSMTPTiming(rcptStart)

	if err != nil {
		// 550 5.1.1 mirrors Gmail / Outlook for unknown recipient. Hard
		// bounce — sender's MTA emits the DSN immediately. The padded
		// timing above (rcptLookupTimeout / padSMTPTiming) prevents
		// enumeration via response-time correlation.
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
			Message:      "the email account that you tried to reach does not exist",
		}
	}

	// Whitelist of statuses that are still receiving mail. lapsed_to_free
	// (lapsed paid → free), prune_warned, and pruning are still
	// receiving — the user is functional, just on the free tier or in
	// the cleanup window. Tombstone, deleted_tombstone, suspended,
	// pending_payment, and the legacy purge_pending / deletion_pending
	// states are not.
	status := user.AccountStatus
	if status == "" {
		status = "active"
	}
	receivingStatuses := map[string]bool{
		"active":          true,
		"payment_failed":  true,
		"lapsed_to_free":  true,
		"prune_warned":    true,
		"pruning":         true,
	}
	if !receivingStatuses[status] {
		// Differentiate the bounce reason so the sender's DSN is
		// clear about why delivery failed:
		//   - tombstone / deleted_tombstone → 5.1.6 mailbox has been
		//     archived or deleted
		//   - suspended / pending_payment / purge_pending /
		//     deletion_pending → 5.2.1 mailbox is disabled
		switch status {
		case "tombstone", "deleted_tombstone", "purge_pending", "deletion_pending":
			return &gosmtp.SMTPError{
				Code:         550,
				EnhancedCode: gosmtp.EnhancedCode{5, 1, 6},
				Message:      "the email account that you tried to reach has been deleted",
			}
		default:
			return &gosmtp.SMTPError{
				Code:         550,
				EnhancedCode: gosmtp.EnhancedCode{5, 2, 1},
				Message:      "the email account that you tried to reach is disabled and not accepting messages",
			}
		}
	}

	// Storage over-cap → soft-bounce. Sender's MTA queues and retries
	// for ~5 days, giving the user time to upgrade or clear space
	// before mail is permanently lost. Skipped silently if the billing
	// store isn't wired in (dev / test).
	if s.receiver.billingStore != nil {
		limit, lerr := s.receiver.billingStore.EffectiveStorageLimit(ctx, user.UserID, user.AccountType, user.Tier)
		if lerr == nil && limit > 0 {
			var driveUsed int64
			if s.receiver.driveStore != nil {
				if du, _, derr := s.receiver.driveStore.GetStorageUsed(ctx, user.UserID, user.TenantID); derr == nil {
					driveUsed = du
				}
			}
			used, uerr := s.receiver.billingStore.EffectiveStorageUsed(ctx, user.UserID, user.TenantID, user.AccountType, driveUsed)
			if uerr == nil && used >= limit {
				// Hard 552 5.2.2 — matches Gmail / Outlook / Yahoo /
				// Proton. Soft 452 was the older "transient" reading
				// of RFC 3463, but every major provider now uses the
				// permanent 5xx form so the sender's MTA bounces
				// immediately instead of queuing for ~5 days. Better
				// UX: sender gets actionable feedback, recipient can
				// clear space and ask for a resend.
				slog.Info("rcpt 552 over quota",
					"to", gateway.RedactEmail(to),
					"used_bytes", used,
					"limit_bytes", limit)
				return &gosmtp.SMTPError{
					Code:         552,
					EnhancedCode: gosmtp.EnhancedCode{5, 2, 2},
					Message:      "mailbox over quota — recipient is over their storage limit, ask them to clear space or upgrade",
				}
			}
		}
	}

	s.recipients = append(s.recipients, to)
	return nil
}

// padSMTPTiming ensures RCPT TO lookups take a consistent minimum time
// to prevent timing-based email address enumeration.
func padSMTPTiming(start time.Time) {
	const minDuration = rcptTimingPad
	elapsed := time.Since(start)
	if elapsed < minDuration {
		time.Sleep(minDuration - elapsed)
	}
}

// Data implements gosmtp.Session — handles the DATA command.
func (s *session) Data(r io.Reader) error {
	// Limit message size to prevent memory exhaustion from slow-read attacks.
	lr := io.LimitReader(r, maxMessageBytes+1)
	rawMessage, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("read message data: %w", err)
	}
	if int64(len(rawMessage)) > maxMessageBytes {
		return &gosmtp.SMTPError{
			Code:    552,
			Message: "message exceeds maximum size",
		}
	}

	if len(s.recipients) == 0 && len(s.roleRecipients) == 0 {
		return &gosmtp.SMTPError{
			Code:    503,
			Message: "no recipients specified",
		}
	}

	clientIP := s.clientIP
	if clientIP == nil {
		clientIP = net.IPv4(127, 0, 0, 1)
	}

	// Process message for each recipient independently.
	// Partial success: deliver what we can, failures bounce asynchronously.
	ctx, cancel := context.WithTimeout(context.Background(), dataProcessTimeout)
	defer cancel()

	// Role-message recipients first. Parsing errors here are logged
	// but not fatal — we still try to insert the raw bytes so that no
	// abuse complaint is silently dropped just because a sender's
	// MIME is malformed.
	var roleSubject string
	if len(s.roleRecipients) > 0 {
		if msg, perr := mail.ReadMessage(bytes.NewReader(rawMessage)); perr == nil {
			roleSubject = msg.Header.Get("Subject")
		} else {
			slog.Warn("role_message parse subject", "error", perr)
		}
	}
	var roleSucceeded, roleFailed int
	for _, rcpt := range s.roleRecipients {
		if _, err := s.receiver.adminStore.InsertRoleMessage(ctx, rcpt, s.from, roleSubject, rawMessage); err != nil {
			slog.Error("role_message insert", "from", gateway.RedactEmail(s.from), "to", rcpt, "error", err)
			roleFailed++
			continue
		}
		roleSucceeded++
		slog.Info("role_message captured", "to", rcpt, "from", gateway.RedactEmail(s.from), "size", len(rawMessage))
	}

	var succeeded, failed int
	for _, rcpt := range s.recipients {
		if err := s.receiver.pipeline.ProcessMessage(ctx, s.from, rcpt, rawMessage, clientIP, s.helo); err != nil {
			slog.Error("pipeline error", "from", gateway.RedactEmail(s.from), "to", gateway.RedactEmail(rcpt), "error", err)
			failed++
		} else {
			succeeded++
		}
	}

	// At least one recipient (mail or role) must have succeeded for a
	// 250 OK response. Otherwise the sender's MTA retries.
	if succeeded == 0 && roleSucceeded == 0 {
		return &gosmtp.SMTPError{
			Code:    451,
			Message: "temporary processing error",
		}
	}

	return nil
}

// Reset implements gosmtp.Session — handles RSET.
func (s *session) Reset() {
	s.from = ""
	s.recipients = nil
	s.roleRecipients = nil
}

// Logout implements gosmtp.Session — handles QUIT.
func (s *session) Logout() error {
	return nil
}

// containsControlChars reports whether s contains any ASCII control characters
// (\x00-\x1F or \x7F). Used to reject malformed SMTP addresses per RFC 5321.
func containsControlChars(s string) bool {
	for _, c := range s {
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}

// stripAngleBrackets removes angle brackets from an email address.
func stripAngleBrackets(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}
	return addr
}
