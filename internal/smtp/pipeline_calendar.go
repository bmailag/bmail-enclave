package smtp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/bmailag/bmail/internal/storage"
)

// parsedICS holds the parsed fields from a text/calendar (ICS) attachment
// relevant to REPLY and CANCEL processing.
type parsedICS struct {
	Method    string            // REQUEST, REPLY, CANCEL
	UID       string            // VEVENT UID — matches external_uid on stored events
	Attendees []parsedAttendee  // attendees with their PARTSTAT
}

// parsedAttendee represents a single attendee extracted from an ICS ATTENDEE line.
type parsedAttendee struct {
	Email    string // bare email address (lowercase)
	PartStat string // ACCEPTED, DECLINED, TENTATIVE, NEEDS-ACTION
}

// parseICSMethod does a simple line-by-line parse of an ICS body to extract
// the METHOD, UID, and ATTENDEE PARTSTAT values. This is intentionally not a
// full RFC 5545 parser — it only needs to handle the fields that Gmail,
// Outlook, and Apple Mail emit in REPLY and CANCEL messages.
func parseICSMethod(data []byte) *parsedICS {
	result := &parsedICS{}
	inVEvent := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// ICS lines can be long (especially ATTENDEE with many params).
	scanner.Buffer(make([]byte, 0, 4096), 8192)

	// Accumulate folded lines (RFC 5545 sec 3.1: continuation lines start
	// with a space or tab).
	var currentLine string

	processLine := func(line string) {
		line = strings.TrimRight(line, "\r\n")

		if strings.HasPrefix(line, "METHOD:") {
			result.Method = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "METHOD:")))
			return
		}

		if line == "BEGIN:VEVENT" {
			inVEvent = true
			return
		}
		if line == "END:VEVENT" {
			inVEvent = false
			return
		}

		if !inVEvent {
			return
		}

		if strings.HasPrefix(line, "UID:") {
			result.UID = strings.TrimSpace(strings.TrimPrefix(line, "UID:"))
			return
		}

		// Parse ATTENDEE lines. Examples:
		//   ATTENDEE;PARTSTAT=ACCEPTED;CN=Alice:mailto:alice@example.com
		//   ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=DECLINED:mailto:bob@example.com
		if strings.HasPrefix(line, "ATTENDEE") {
			att := parseAttendeeLine(line)
			if att.Email != "" {
				result.Attendees = append(result.Attendees, att)
			}
		}
	}

	for scanner.Scan() {
		raw := scanner.Text()
		// RFC 5545 line folding: continuation lines start with space or tab.
		if len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			currentLine += raw[1:] // append without the leading whitespace
			continue
		}
		// Process the previous accumulated line.
		if currentLine != "" {
			processLine(currentLine)
		}
		currentLine = raw
	}
	// Process the last line.
	if currentLine != "" {
		processLine(currentLine)
	}

	if result.Method == "" || result.UID == "" {
		return nil
	}
	return result
}

// parseAttendeeLine extracts email and PARTSTAT from an ICS ATTENDEE line.
func parseAttendeeLine(line string) parsedAttendee {
	var att parsedAttendee

	// Extract email from mailto: portion. The mailto: can appear after
	// the colon separator or after a semicolon-delimited parameter list.
	if idx := strings.LastIndex(strings.ToLower(line), "mailto:"); idx >= 0 {
		email := line[idx+7:]
		// Trim any trailing whitespace or angle brackets.
		email = strings.TrimRight(email, "> \t\r\n")
		att.Email = strings.ToLower(strings.TrimSpace(email))
	}

	// Extract PARTSTAT from parameters.
	upper := strings.ToUpper(line)
	if idx := strings.Index(upper, "PARTSTAT="); idx >= 0 {
		rest := line[idx+9:]
		// PARTSTAT value ends at the next semicolon, colon, or end of string.
		end := strings.IndexAny(rest, ";:")
		if end < 0 {
			end = len(rest)
		}
		att.PartStat = strings.ToUpper(strings.TrimSpace(rest[:end]))
	}

	return att
}

// processInboundICS handles text/calendar attachments from inbound email.
// For METHOD:REPLY, it updates the attendee's response on the organizer's event.
// For METHOD:CANCEL, it deletes the event from the recipient's calendar.
// Errors are logged and never propagated — calendar processing must not
// block email delivery.
func (p *Pipeline) processInboundICS(ctx context.Context, user *storage.User, icsData []byte) {
	ics := parseICSMethod(icsData)
	if ics == nil {
		return
	}

	switch ics.Method {
	case "REPLY":
		p.processICSReply(ctx, user, ics)
	case "CANCEL":
		p.processICSCancel(ctx, user, ics)
	default:
		// REQUEST and other methods are not processed automatically.
		// REQUEST invites are handled by the client when the user opens the email.
	}
}

// processICSReply updates attendee responses on the recipient's calendar event.
// The recipient of a REPLY email is the original organizer who sent the invite.
func (p *Pipeline) processICSReply(ctx context.Context, user *storage.User, ics *parsedICS) {
	if len(ics.Attendees) == 0 {
		slog.Debug("ics reply: no attendees in ICS", "uid", ics.UID)
		return
	}

	event, err := p.calendarStore.GetByExternalUID(ctx, user.UserID, user.TenantID, ics.UID)
	if err != nil {
		slog.Debug("ics reply: no matching event", "uid", ics.UID, "user_id", user.UserID, "error", err)
		return
	}

	for _, att := range ics.Attendees {
		if att.Email == "" || att.PartStat == "" {
			continue
		}

		// Map ICS PARTSTAT values to our internal lowercase convention.
		status := mapPartStat(att.PartStat)
		if status == "" {
			slog.Debug("ics reply: unknown partstat", "partstat", att.PartStat, "email", att.Email)
			continue
		}

		if err := p.calendarStore.UpdateAttendeeResponse(ctx, user.UserID, user.TenantID, event.EventID, att.Email, status); err != nil {
			slog.Warn("ics reply: failed to update attendee response",
				"event_id", event.EventID, "email", att.Email, "status", status, "error", err)
			continue
		}
		slog.Info("ics reply: updated attendee response",
			"event_id", event.EventID, "email", att.Email, "status", status, "uid", ics.UID)

		// Propagate to every fellow-attendee copy of the same logical
		// event within this tenant so their views don't stay stale.
		// External recipients already got the update via the organizer's
		// rebroadcast (handled in the calendar service).
		externalUID := ics.UID
		if event.ExternalUID != nil && *event.ExternalUID != "" {
			externalUID = *event.ExternalUID
		}
		if err := p.calendarStore.BroadcastAttendeeResponse(ctx, user.TenantID, externalUID, att.Email, status); err != nil {
			slog.Warn("ics reply: failed to broadcast attendee response",
				"uid", externalUID, "email", att.Email, "status", status, "error", err)
		}
		p.notifyCalendarEventUpdated(ctx, user.TenantID, externalUID)
	}
}

// processICSCancel marks the event as cancelled in the recipient's calendar.
// The event is NOT deleted — it remains visible with a "Cancelled" indicator
// so the user knows the organizer cancelled it.
func (p *Pipeline) processICSCancel(ctx context.Context, user *storage.User, ics *parsedICS) {
	event, err := p.calendarStore.GetByExternalUID(ctx, user.UserID, user.TenantID, ics.UID)
	if err != nil {
		slog.Debug("ics cancel: no matching event", "uid", ics.UID, "user_id", user.UserID, "error", err)
		return
	}

	if err := p.calendarStore.MarkCancelled(ctx, user.UserID, user.TenantID, event.EventID); err != nil {
		slog.Warn("ics cancel: failed to mark event cancelled",
			"event_id", event.EventID, "uid", ics.UID, "error", err)
	} else {
		slog.Info("ics cancel: marked event cancelled",
			"event_id", event.EventID, "uid", ics.UID, "user_id", user.UserID)
	}
}

// notifyCalendarEventUpdated publishes a calendar_event_updated SSE event
// to every user in the tenant that owns a copy of the event — so their
// calendar view refreshes in real time after an inbound ICS REPLY updates
// the responder's status. Fire-and-forget; silently no-ops without Redis.
func (p *Pipeline) notifyCalendarEventUpdated(ctx context.Context, tenantID uuid.UUID, externalUID string) {
	if p.redis == nil || p.calendarStore == nil || externalUID == "" {
		return
	}
	userIDs, err := p.calendarStore.ListUsersByExternalUID(ctx, tenantID, externalUID)
	if err != nil {
		slog.Warn("calendar notify: list users failed", "uid", externalUID, "error", err)
		return
	}
	payload, err := json.Marshal(map[string]string{
		"type":         "calendar_event_updated",
		"external_uid": externalUID,
	})
	if err != nil {
		return
	}
	for _, uid := range userIDs {
		channel := fmt.Sprintf("notifications:%s", uid)
		if err := p.redis.Publish(ctx, channel, payload).Err(); err != nil {
			slog.Warn("calendar notify: publish failed", "user_id", uid, "error", err)
		}
	}
}

// mapPartStat converts an ICS PARTSTAT value to the lowercase status string
// used in attendee_responses. Returns empty string for unrecognized values.
func mapPartStat(partstat string) string {
	switch strings.ToUpper(partstat) {
	case "ACCEPTED":
		return "accepted"
	case "DECLINED":
		return "declined"
	case "TENTATIVE":
		return "tentative"
	case "NEEDS-ACTION":
		return "needs-action"
	default:
		return ""
	}
}
