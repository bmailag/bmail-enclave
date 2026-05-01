package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminStore wraps DB-level operations for the /admin panel: the
// is_admin user flag, the role-message inbox (postmaster, abuse,
// security, …), and the immutable admin_audit log. Lives here so the
// HTTP handlers and the smtp-inbound role-routing path share one
// implementation.
type AdminStore struct {
	DB *DB
}

func NewAdminStore(db *DB) *AdminStore { return &AdminStore{DB: db} }

// IsAdmin returns whether the given user holds the admin flag. Returns
// false (no error) for unknown users so callers can treat
// "not-admin-or-not-found" as a single denial path.
func (s *AdminStore) IsAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isAdmin bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT is_admin FROM users WHERE user_id = $1`, userID,
	).Scan(&isAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is_admin lookup: %w", err)
	}
	return isAdmin, nil
}

// IsSupport returns whether the given user has support access. Admins
// always count as support; the explicit is_support flag is for users
// who are support but not admin. Same not-found-is-false semantics.
func (s *AdminStore) IsSupport(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isAdmin, isSupport bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT is_admin, is_support FROM users WHERE user_id = $1`, userID,
	).Scan(&isAdmin, &isSupport)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is_support lookup: %w", err)
	}
	return isAdmin || isSupport, nil
}

// IsMarketing returns whether the given user has marketing access.
// Admins always count as marketing — same pattern as IsSupport.
func (s *AdminStore) IsMarketing(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isAdmin, isMarketing bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT is_admin, is_marketing FROM users WHERE user_id = $1`, userID,
	).Scan(&isAdmin, &isMarketing)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is_marketing lookup: %w", err)
	}
	return isAdmin || isMarketing, nil
}

// SetAdminByAddress flips the is_admin flag for a user looked up by
// address. Used by the bootstrap-admin sync at backend startup so the
// first admin can be seeded from an env var without manual SQL.
func (s *AdminStore) SetAdminByAddress(ctx context.Context, address string, isAdmin bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET is_admin = $2 WHERE address = lower($1)`,
		address, isAdmin,
	)
	if err != nil {
		return fmt.Errorf("set_admin: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", address)
	}
	return nil
}

// SetAdmin flips the is_admin flag for a user by ID.
func (s *AdminStore) SetAdmin(ctx context.Context, userID uuid.UUID, isAdmin bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET is_admin = $2 WHERE user_id = $1`, userID, isAdmin,
	)
	if err != nil {
		return fmt.Errorf("set_admin: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// UserRoles is the before/after snapshot of role flags returned from
// SetRoles for audit logging.
type UserRoles struct {
	IsAdmin     bool `json:"is_admin"`
	IsSupport   bool `json:"is_support"`
	IsMarketing bool `json:"is_marketing"`
}

// SetRoles atomically sets is_admin, is_support, and is_marketing for a
// user. Returns the previous flags so the caller can include them in
// the audit log.
func (s *AdminStore) SetRoles(ctx context.Context, userID uuid.UUID, target UserRoles) (UserRoles, error) {
	var before UserRoles
	if scanErr := s.DB.Pool.QueryRow(ctx,
		`SELECT is_admin, is_support, is_marketing FROM users WHERE user_id = $1`, userID,
	).Scan(&before.IsAdmin, &before.IsSupport, &before.IsMarketing); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return UserRoles{}, fmt.Errorf("user not found: %s", userID)
		}
		return UserRoles{}, fmt.Errorf("read pre-state: %w", scanErr)
	}
	if _, execErr := s.DB.Pool.Exec(ctx,
		`UPDATE users SET is_admin = $2, is_support = $3, is_marketing = $4 WHERE user_id = $1`,
		userID, target.IsAdmin, target.IsSupport, target.IsMarketing,
	); execErr != nil {
		return UserRoles{}, fmt.Errorf("set_roles: %w", execErr)
	}
	return before, nil
}

// RoleMessage is one row of the role-message inbox. See migration 097
// for column docs and the rationale for plaintext storage.
type RoleMessage struct {
	RoleMessageID uuid.UUID  `json:"role_message_id"`
	Address       string     `json:"address"`
	RawRFC822     []byte     `json:"-"`              // never serialized in list responses
	ReceivedAt    time.Time  `json:"received_at"`
	Sender        string     `json:"sender,omitempty"`
	Subject       string     `json:"subject,omitempty"`
	SizeBytes     int64      `json:"size_bytes"`
	Status        string     `json:"status"`
	HandledBy     *uuid.UUID `json:"handled_by,omitempty"`
	HandledAt     *time.Time `json:"handled_at,omitempty"`
	Notes         string     `json:"notes,omitempty"`
}

// InsertRoleMessage stores an inbound message destined for a reserved
// role address. SMTP-inbound calls this in lieu of the encrypted-mail
// pipeline when the recipient local-part is reserved. sender + subject
// are best-effort metadata for the list view.
func (s *AdminStore) InsertRoleMessage(ctx context.Context, address, sender, subject string, raw []byte) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO role_messages (role_message_id, address, raw_rfc822, sender, subject, size_bytes)
		 VALUES ($1, lower($2), $3, $4, $5, $6)`,
		id, address, raw, sender, subject, int64(len(raw)),
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert role_message: %w", err)
	}
	return id, nil
}

// ListRoleMessages returns role messages, optionally filtered to a
// specific address and/or status. unhandledOnly takes precedence over
// the status filter for the common UI case "show me what needs
// attention." A nil address filter returns rows for all reserved
// addresses.
func (s *AdminStore) ListRoleMessages(ctx context.Context, addressFilter, statusFilter string, unhandledOnly bool, limit, offset int) ([]*RoleMessage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT role_message_id, address, received_at,
	             COALESCE(sender, ''), COALESCE(subject, ''), size_bytes,
	             status, handled_by, handled_at, COALESCE(notes, '')
	      FROM role_messages
	      WHERE 1=1`
	args := []any{}
	if addressFilter != "" {
		args = append(args, addressFilter)
		q += fmt.Sprintf(" AND address = lower($%d)", len(args))
	}
	if unhandledOnly {
		q += " AND status = 'unhandled'"
	} else if statusFilter != "" {
		args = append(args, statusFilter)
		q += fmt.Sprintf(" AND status = $%d", len(args))
	}
	q += " ORDER BY received_at DESC"
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	args = append(args, offset)
	q += fmt.Sprintf(" OFFSET $%d", len(args))

	rows, err := s.DB.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list role_messages: %w", err)
	}
	defer rows.Close()
	var out []*RoleMessage
	for rows.Next() {
		m := &RoleMessage{}
		if err := rows.Scan(&m.RoleMessageID, &m.Address, &m.ReceivedAt,
			&m.Sender, &m.Subject, &m.SizeBytes,
			&m.Status, &m.HandledBy, &m.HandledAt, &m.Notes); err != nil {
			return nil, fmt.Errorf("scan role_message: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetRoleMessage returns one role message including its raw RFC 5322
// body. Caller is responsible for the admin-gate check.
func (s *AdminStore) GetRoleMessage(ctx context.Context, id uuid.UUID) (*RoleMessage, error) {
	m := &RoleMessage{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT role_message_id, address, raw_rfc822, received_at,
		        COALESCE(sender, ''), COALESCE(subject, ''), size_bytes,
		        status, handled_by, handled_at, COALESCE(notes, '')
		 FROM role_messages WHERE role_message_id = $1`, id,
	).Scan(&m.RoleMessageID, &m.Address, &m.RawRFC822, &m.ReceivedAt,
		&m.Sender, &m.Subject, &m.SizeBytes,
		&m.Status, &m.HandledBy, &m.HandledAt, &m.Notes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("role message not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get role_message: %w", err)
	}
	return m, nil
}

// MarkRoleMessage updates the status + notes of a role message. status
// must be one of {unhandled, handled, spam}. If status != "unhandled"
// the handled_by/handled_at columns are stamped; otherwise they're
// cleared (so re-opening a triaged message resets accountability).
func (s *AdminStore) MarkRoleMessage(ctx context.Context, id, adminID uuid.UUID, status, notes string) error {
	switch status {
	case "unhandled", "handled", "spam":
	default:
		return fmt.Errorf("invalid status: %s", status)
	}
	if status == "unhandled" {
		_, err := s.DB.Pool.Exec(ctx,
			`UPDATE role_messages
			    SET status = 'unhandled', handled_by = NULL, handled_at = NULL, notes = $2
			  WHERE role_message_id = $1`,
			id, notes,
		)
		if err != nil {
			return fmt.Errorf("mark role_message unhandled: %w", err)
		}
		return nil
	}
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE role_messages
		    SET status = $2, handled_by = $3, handled_at = now(), notes = $4
		  WHERE role_message_id = $1`,
		id, status, adminID, notes,
	)
	if err != nil {
		return fmt.Errorf("mark role_message: %w", err)
	}
	return nil
}

// AuditEvent is one row of admin_audit. The store never offers an
// UPDATE — audit history is append-only and the only deletion path is
// PG-level retention.
type AuditEvent struct {
	AuditID       uuid.UUID       `json:"audit_id"`
	AdminUserID   uuid.UUID       `json:"admin_user_id"`
	AdminAddress  string          `json:"admin_address,omitempty"` // joined from users for the UI
	Action        string          `json:"action"`
	TargetUserID  *uuid.UUID      `json:"target_user_id,omitempty"`
	TargetAddress string          `json:"target_address,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// LogAudit inserts one admin_audit row. details is marshaled JSON;
// callers should pass a small struct or map describing before/after
// state for the action. A nil details is stored as JSON null.
func (s *AdminStore) LogAudit(ctx context.Context, adminID uuid.UUID, action string, targetUserID *uuid.UUID, targetAddress string, details any) error {
	var detailsJSON []byte
	if details != nil {
		b, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		detailsJSON = b
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO admin_audit (admin_user_id, action, target_user_id, target_address, details)
		 VALUES ($1, $2, $3, NULLIF($4, ''), $5)`,
		adminID, action, targetUserID, targetAddress, detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("log audit: %w", err)
	}
	return nil
}

// ListAudit returns recent audit events with the admin's address
// joined in for display. limit is clamped to [1, 200]; default 100.
func (s *AdminStore) ListAudit(ctx context.Context, limit, offset int) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT a.audit_id, a.admin_user_id, COALESCE(u.address, ''),
		        a.action, a.target_user_id, COALESCE(a.target_address, ''),
		        a.details, a.created_at
		 FROM admin_audit a LEFT JOIN users u ON u.user_id = a.admin_user_id
		 ORDER BY a.created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		e := &AuditEvent{}
		if err := rows.Scan(&e.AuditID, &e.AdminUserID, &e.AdminAddress,
			&e.Action, &e.TargetUserID, &e.TargetAddress,
			&e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
