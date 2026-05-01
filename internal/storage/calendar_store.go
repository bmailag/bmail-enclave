package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CalendarEvent represents a row in the calendar_events table.
type CalendarEvent struct {
	EventID            uuid.UUID  `db:"event_id"`
	UserID             uuid.UUID  `db:"user_id"`
	TenantID           uuid.UUID  `db:"tenant_id"`
	EncryptedTitle     []byte     `db:"encrypted_title"`
	EncryptedLocation  []byte     `db:"encrypted_location"`
	EncryptedAttendees []byte     `db:"encrypted_attendees"`
	EphemeralPubkey    []byte     `db:"ephemeral_pubkey"`
	EncryptedEventKey  []byte     `db:"encrypted_event_key"`
	DescriptionBlobRef *string    `db:"description_blob_ref"`
	StartTime          time.Time  `db:"start_time"`
	EndTime            time.Time  `db:"end_time"`
	AllDay             bool       `db:"all_day"`
	RecurrenceRule     *string    `db:"recurrence_rule"`
	ReminderMinutes    *int       `db:"reminder_minutes"`
	Color              string     `db:"color"`
	ReminderSent       bool              `db:"reminder_sent"`
	AttendeeResponses  map[string]string `db:"attendee_responses"`
	ExternalUID        *string           `db:"external_uid"`
	Cancelled          bool              `db:"cancelled"`
	CreatedAt          time.Time         `db:"created_at"`
	UpdatedAt          time.Time         `db:"updated_at"`
}

// CalendarStore wraps DB and provides calendar-related database operations.
type CalendarStore struct {
	DB *DB
}

// NewCalendarStore returns a new CalendarStore backed by the given DB.
func NewCalendarStore(db *DB) *CalendarStore {
	return &CalendarStore{DB: db}
}

const calendarEventColumns = `event_id, user_id, tenant_id, encrypted_title, encrypted_location,
	encrypted_attendees, ephemeral_pubkey, encrypted_event_key, description_blob_ref,
	start_time, end_time, all_day, recurrence_rule, reminder_minutes, color,
	reminder_sent, attendee_responses, external_uid, cancelled, created_at, updated_at`

func scanCalendarEvent(rows pgx.Rows) (*CalendarEvent, error) {
	e := &CalendarEvent{}
	var attendeeResponsesRaw []byte
	if err := rows.Scan(
		&e.EventID, &e.UserID, &e.TenantID,
		&e.EncryptedTitle, &e.EncryptedLocation, &e.EncryptedAttendees,
		&e.EphemeralPubkey, &e.EncryptedEventKey, &e.DescriptionBlobRef,
		&e.StartTime, &e.EndTime, &e.AllDay,
		&e.RecurrenceRule, &e.ReminderMinutes, &e.Color,
		&e.ReminderSent, &attendeeResponsesRaw, &e.ExternalUID, &e.Cancelled, &e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(attendeeResponsesRaw) > 0 {
		e.AttendeeResponses = make(map[string]string)
		_ = json.Unmarshal(attendeeResponsesRaw, &e.AttendeeResponses)
	}
	return e, nil
}

// Create inserts a new calendar event.
func (s *CalendarStore) Create(ctx context.Context, e *CalendarEvent) error {
	if e.EventID == uuid.Nil {
		e.EventID = uuid.New()
	}
	now := time.Now()
	e.CreatedAt = now
	e.UpdatedAt = now
	var attendeeResponsesJSON []byte
	if len(e.AttendeeResponses) > 0 {
		attendeeResponsesJSON, _ = json.Marshal(e.AttendeeResponses)
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO calendar_events (event_id, user_id, tenant_id,
			encrypted_title, encrypted_location, encrypted_attendees,
			ephemeral_pubkey, encrypted_event_key, description_blob_ref,
			start_time, end_time, all_day, recurrence_rule, reminder_minutes, color,
			reminder_sent, attendee_responses, external_uid, cancelled, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		e.EventID, e.UserID, e.TenantID,
		e.EncryptedTitle, e.EncryptedLocation, e.EncryptedAttendees,
		e.EphemeralPubkey, e.EncryptedEventKey, e.DescriptionBlobRef,
		e.StartTime, e.EndTime, e.AllDay, e.RecurrenceRule, e.ReminderMinutes, e.Color,
		e.ReminderSent, attendeeResponsesJSON, e.ExternalUID, e.Cancelled, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create calendar event: %w", err)
	}
	return nil
}

// Get retrieves a single calendar event by ID, scoped to user+tenant.
func (s *CalendarStore) Get(ctx context.Context, userID, tenantID, eventID uuid.UUID) (*CalendarEvent, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+calendarEventColumns+`
		 FROM calendar_events
		 WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		eventID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get calendar event: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("calendar event not found")
	}
	return scanCalendarEvent(rows)
}

// ListByRange returns all events for a user within a time range.
func (s *CalendarStore) ListByRange(ctx context.Context, userID, tenantID uuid.UUID, start, end time.Time) ([]*CalendarEvent, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+calendarEventColumns+`
		 FROM calendar_events
		 WHERE user_id = $1 AND tenant_id = $2
		   AND start_time < $4 AND end_time > $3
		 ORDER BY start_time`,
		userID, tenantID, start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("list calendar events: %w", err)
	}
	defer rows.Close()

	var events []*CalendarEvent
	for rows.Next() {
		e, err := scanCalendarEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan calendar event: %w", err)
		}
		events = append(events, e)
	}
	return events, nil
}

// Update modifies an existing calendar event.
func (s *CalendarStore) Update(ctx context.Context, e *CalendarEvent) error {
	e.UpdatedAt = time.Now()
	e.ReminderSent = false // Reset reminder on update
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events SET
			encrypted_title = $4, encrypted_location = $5, encrypted_attendees = $6,
			ephemeral_pubkey = $7, encrypted_event_key = $8, description_blob_ref = $9,
			start_time = $10, end_time = $11, all_day = $12,
			recurrence_rule = $13, reminder_minutes = $14, color = $15,
			reminder_sent = $16, external_uid = $17, cancelled = $18, updated_at = $19
		 WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		e.EventID, e.UserID, e.TenantID,
		e.EncryptedTitle, e.EncryptedLocation, e.EncryptedAttendees,
		e.EphemeralPubkey, e.EncryptedEventKey, e.DescriptionBlobRef,
		e.StartTime, e.EndTime, e.AllDay,
		e.RecurrenceRule, e.ReminderMinutes, e.Color,
		e.ReminderSent, e.ExternalUID, e.Cancelled, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update calendar event: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("calendar event not found")
	}
	return nil
}

// Delete removes a calendar event by ID.
// MarkCancelled marks an event as cancelled without deleting it.
func (s *CalendarStore) MarkCancelled(ctx context.Context, userID, tenantID, eventID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events SET cancelled = true, updated_at = now()
		 WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		eventID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("mark calendar event cancelled: %w", err)
	}
	return nil
}

func (s *CalendarStore) Delete(ctx context.Context, userID, tenantID, eventID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM calendar_events WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		eventID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete calendar event: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("calendar event not found")
	}
	return nil
}

// ListDueReminders returns events with pending reminders that are due.
func (s *CalendarStore) ListDueReminders(ctx context.Context) ([]*CalendarEvent, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+calendarEventColumns+`
		 FROM calendar_events
		 WHERE reminder_minutes IS NOT NULL
		   AND NOT reminder_sent
		   AND start_time - (reminder_minutes * interval '1 minute') <= now()
		   AND start_time > now()
		 ORDER BY start_time
		 LIMIT 100`,
	)
	if err != nil {
		return nil, fmt.Errorf("list due reminders: %w", err)
	}
	defer rows.Close()

	var events []*CalendarEvent
	for rows.Next() {
		e, err := scanCalendarEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan reminder event: %w", err)
		}
		events = append(events, e)
	}
	return events, nil
}

// MarkReminderSent marks a reminder as sent.
func (s *CalendarStore) MarkReminderSent(ctx context.Context, eventID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events SET reminder_sent = true WHERE event_id = $1`,
		eventID,
	)
	if err != nil {
		return fmt.Errorf("mark reminder sent: %w", err)
	}
	return nil
}

// UpdateAttendeeResponse updates a single attendee's RSVP status using JSONB
// concatenation. Ownership is enforced via user_id+tenant_id so a malicious
// caller can't write into someone else's event.
func (s *CalendarStore) UpdateAttendeeResponse(ctx context.Context, userID, tenantID, eventID uuid.UUID, email string, status string) error {
	patch, err := json.Marshal(map[string]string{email: status})
	if err != nil {
		return fmt.Errorf("marshal attendee response: %w", err)
	}
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events
		 SET attendee_responses = COALESCE(attendee_responses, '{}'::jsonb) || $4::jsonb,
		     updated_at = now()
		 WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		eventID, userID, tenantID, patch,
	)
	if err != nil {
		return fmt.Errorf("update attendee response: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("calendar event not found")
	}
	return nil
}

// BroadcastAttendeeResponse applies an attendee RSVP patch to every copy of a
// logical event within a tenant, keyed by external_uid. Use this after an
// organizer updates their own event so fellow attendees (each of whom owns a
// separate calendar_events row with the same external_uid) see the status
// change without having to receive their own email. Caller provides the UID
// of the logical event — typically the organizer's event.external_uid.
func (s *CalendarStore) BroadcastAttendeeResponse(ctx context.Context, tenantID uuid.UUID, externalUID string, email string, status string) error {
	if externalUID == "" {
		return nil
	}
	patch, err := json.Marshal(map[string]string{email: status})
	if err != nil {
		return fmt.Errorf("marshal attendee response: %w", err)
	}
	_, err = s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events
		 SET attendee_responses = COALESCE(attendee_responses, '{}'::jsonb) || $3::jsonb,
		     updated_at = now()
		 WHERE tenant_id = $1 AND external_uid = $2`,
		tenantID, externalUID, patch,
	)
	if err != nil {
		return fmt.Errorf("broadcast attendee response: %w", err)
	}
	return nil
}

// ListUsersByExternalUID returns the distinct user_ids that own a copy of a
// logical event within a tenant. Used to notify every attendee when one of
// them RSVPs, so their calendar view refreshes in real time instead of
// waiting for the next reload.
func (s *CalendarStore) ListUsersByExternalUID(ctx context.Context, tenantID uuid.UUID, externalUID string) ([]uuid.UUID, error) {
	if externalUID == "" {
		return nil, nil
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT DISTINCT user_id FROM calendar_events
		 WHERE tenant_id = $1 AND external_uid = $2`,
		tenantID, externalUID,
	)
	if err != nil {
		return nil, fmt.Errorf("list users by external uid: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan user id: %w", err)
		}
		out = append(out, id)
	}
	return out, nil
}

// SetAttendeeResponses replaces the entire attendee_responses jsonb column
// with the given map. Use this when you need authoritative truth about
// who is invited (e.g. when the user removes attendees in the editor).
func (s *CalendarStore) SetAttendeeResponses(ctx context.Context, userID, tenantID, eventID uuid.UUID, responses map[string]string) error {
	if responses == nil {
		responses = map[string]string{}
	}
	payload, err := json.Marshal(responses)
	if err != nil {
		return fmt.Errorf("marshal attendee responses: %w", err)
	}
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE calendar_events
		 SET attendee_responses = $4::jsonb,
		     updated_at = now()
		 WHERE event_id = $1 AND user_id = $2 AND tenant_id = $3`,
		eventID, userID, tenantID, payload,
	)
	if err != nil {
		return fmt.Errorf("set attendee responses: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("calendar event not found")
	}
	return nil
}

// GetByExternalUID retrieves a calendar event by its ICS UID, scoped to
// a specific user+tenant. Used to match incoming UPDATE/CANCEL invites
// AND inbound METHOD:REPLY RSVPs against an existing local event.
//
// Two lookup paths:
//   1. external_uid match — for events imported from inbound invites
//      where the organizer chose an arbitrary string UID.
//   2. event_id match (when the UID parses as a UUID) — for events
//      WE created locally and sent out as invites. The compose flow
//      uses the event_id UUID as the ICS UID, and Gmail/etc preserve
//      it byte-for-byte when sending the REPLY back. Without this
//      fallback, an RSVP to a self-created event would never match
//      because external_uid is NULL on the local row.
func (s *CalendarStore) GetByExternalUID(ctx context.Context, userID, tenantID uuid.UUID, externalUID string) (*CalendarEvent, error) {
	// Try external_uid first.
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+calendarEventColumns+`
		 FROM calendar_events
		 WHERE user_id = $1 AND tenant_id = $2 AND external_uid = $3
		 LIMIT 1`,
		userID, tenantID, externalUID,
	)
	if err != nil {
		return nil, fmt.Errorf("get calendar event by external uid: %w", err)
	}
	if rows.Next() {
		evt, scanErr := scanCalendarEvent(rows)
		rows.Close()
		if scanErr == nil {
			return evt, nil
		}
	}
	rows.Close()

	// Fall back to event_id (UUID match) for events we created locally.
	if eventID, parseErr := uuid.Parse(externalUID); parseErr == nil {
		rows2, err := s.DB.Pool.Query(ctx,
			`SELECT `+calendarEventColumns+`
			 FROM calendar_events
			 WHERE user_id = $1 AND tenant_id = $2 AND event_id = $3
			 LIMIT 1`,
			userID, tenantID, eventID,
		)
		if err != nil {
			return nil, fmt.Errorf("get calendar event by event id: %w", err)
		}
		defer rows2.Close()
		if rows2.Next() {
			return scanCalendarEvent(rows2)
		}
	}

	return nil, fmt.Errorf("calendar event not found")
}

// GetByExternalUIDForOrganizer looks up a calendar event by external_uid
// across any user in the tenant. Used for internal RSVP: the attendee
// needs to update the organizer's event, not their own copy.
func (s *CalendarStore) GetByExternalUIDForOrganizer(ctx context.Context, tenantID uuid.UUID, organizerAddress, externalUID string) (*CalendarEvent, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT ce.event_id, ce.user_id, ce.tenant_id, ce.encrypted_title, ce.encrypted_location,
			ce.encrypted_attendees, ce.ephemeral_pubkey, ce.encrypted_event_key, ce.description_blob_ref,
			ce.start_time, ce.end_time, ce.all_day, ce.recurrence_rule, ce.reminder_minutes, ce.color,
			ce.reminder_sent, ce.attendee_responses, ce.external_uid, ce.cancelled, ce.created_at, ce.updated_at
		 FROM calendar_events ce
		 JOIN users u ON u.user_id = ce.user_id
		 WHERE ce.tenant_id = $1 AND u.address = $2 AND ce.external_uid = $3
		 LIMIT 1`,
		tenantID, organizerAddress, externalUID,
	)
	if err != nil {
		return nil, fmt.Errorf("get event by uid for organizer: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return scanCalendarEvent(rows)
	}
	return nil, fmt.Errorf("calendar event not found for organizer %s uid %s", organizerAddress, externalUID)
}

// GetByEventIDGlobal retrieves a calendar event by event_id without user scoping.
// This is used for RSVP tracking from inbound mail where the user_id is unknown.
func (s *CalendarStore) GetByEventIDGlobal(ctx context.Context, eventID uuid.UUID) (*CalendarEvent, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+calendarEventColumns+`
		 FROM calendar_events
		 WHERE event_id = $1`,
		eventID,
	)
	if err != nil {
		return nil, fmt.Errorf("get calendar event by id: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("calendar event not found")
	}
	return scanCalendarEvent(rows)
}
