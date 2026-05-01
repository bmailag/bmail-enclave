package main

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/bmailag/bmail/internal/config"
	bmailcrypto "github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/domain"
	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/peer"
	"github.com/bmailag/bmail/internal/queue"
	"github.com/bmailag/bmail/internal/smtp"
	"github.com/bmailag/bmail/internal/storage"
	"github.com/bmailag/bmail/internal/tee"
)

// plaintextAttachment holds decrypted attachment data for external delivery.
type plaintextAttachment struct {
	AttachmentID string `json:"attachment_id"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Data         string `json:"data"` // base64
}

// OutboundMessage matches the outboundPayload struct in internal/mail/service.go.
type OutboundMessage struct {
	ToAddress            string                `json:"to_address"`
	SenderAddress        string                `json:"sender_address"`
	EncryptedBody        string                `json:"encrypted_body"`
	EncryptedSubject     string                `json:"encrypted_subject"`
	EncryptedMessageKey  string                `json:"encrypted_message_key"`
	EphemeralPubkey      string                `json:"ephemeral_pubkey"`
	TenantID             string                `json:"tenant_id"`
	EncryptionType       string                `json:"encryption_type"`
	RFCMessageID         string                `json:"rfc_message_id"`
	SenderDisplayName    string                `json:"sender_display_name,omitempty"`
	AttachmentIDs        []string              `json:"attachment_ids,omitempty"`
	SenderUserID         string                `json:"sender_user_id,omitempty"`
	SenderTier           string                `json:"sender_tier,omitempty"` // free / mail / unlimited / business / enterprise
	SenderAffiliateCode  string                `json:"sender_affiliate_code,omitempty"` // KLB affiliate code; appended as ?_a=<code> on the free-tier footer URL
	PlaintextAttachments []plaintextAttachment  `json:"plaintext_attachments,omitempty"`
	CcAddresses          []string              `json:"cc_addresses,omitempty"`
	InReplyTo            string                `json:"in_reply_to,omitempty"`
	BodyFormat           string                `json:"body_format,omitempty"` // "html" (default) or "plain"
	Attempt              int                   `json:"attempt"`
}

// mimeAttachment holds fetched attachment data for MIME composition.
type mimeAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// normalizeEditorHTML cleans up contentEditable quirks in the HTML body.
// Chrome wraps each line in <div> and empty lines become <div><br></div>.
// This produces valid but ugly HTML that some email clients handle poorly.
func normalizeEditorHTML(s string) string {
	// <div><br></div> → <br> (empty line between blocks)
	s = strings.ReplaceAll(s, "<div><br></div>", "<br>")
	s = strings.ReplaceAll(s, "<div><br/></div>", "<br>")
	return s
}

// sanitizeHeaderValue strips CR, LF, and NUL bytes from a string to prevent
// RFC 5322 header injection via CRLF sequences.
func sanitizeHeaderValue(s string) string {
	return strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\x00", "").Replace(s)
}

// encodeRFC2231Filename encodes a filename for use in Content-Type/Content-Disposition
// headers using RFC 2231 encoding (percent-encoded UTF-8).
func encodeRFC2231Filename(filename string) string {
	var b strings.Builder
	for _, c := range []byte(filename) {
		// Safe ASCII characters that don't need encoding per RFC 2231.
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe encoding.
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return string(b), nil
}

// composeRFC5322 builds a minimal RFC 5322 message from the outbound payload.
// For external delivery, we send the encrypted body as the message content since
// the recipient won't be able to decrypt bmail encryption anyway — the gateway
// handles PGP encryption before queuing, so encrypted_body here is either:
//   - PGP-encrypted armored text (encryption_type == "pgp")
//   - Plaintext (encryption_type == "plaintext" or when sending to external non-PGP)
//   - Bmail-encrypted ciphertext (shouldn't reach external delivery, but handle gracefully)
// stripHTMLTags removes HTML tags from a string for plain-text conversion.
func stripHTMLTags(s string) string {
	var out strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// cidImage holds an inline image extracted from data URIs in HTML.
type cidImage struct {
	CID         string // e.g. "img001@bmail.ag"
	ContentType string // e.g. "image/png"
	Data        []byte // raw image bytes
}

// safeImageMIMEs is a whitelist of safe raster image MIME subtypes. SVG and other
// vector/XML types are excluded because they can contain embedded scripts.
var safeImageMIMEs = map[string]bool{
	"png": true, "jpeg": true, "jpg": true, "gif": true,
	"webp": true, "bmp": true, "ico": true, "avif": true,
}

// dataURIRegexp matches <img src="data:image/TYPE;base64,DATA"> tags.
var dataURIRegexp = regexp.MustCompile(`(<img\b[^>]*\bsrc\s*=\s*["'])data:image/([a-zA-Z0-9+.-]+);base64,([A-Za-z0-9+/=\s]+)(["'][^>]*>)`)

// bounceReasonRegexp matches a typical SMTP DSN code prefix at the
// head of a bounce reason string, e.g. "550 5.1.1 No such user" or
// "5.7.1 spam blocked". The two capturing groups carry (a) just the
// status code and (b) the human-readable remainder.
var bounceReasonRegexp = regexp.MustCompile(`^\s*((?:\d{3}\s+)?\d+\.\d+\.\d+|\d{3})\b\s*(.*)$`)

// splitBounceReason tries to split a remote SMTP rejection string into
// the DSN status code and the free-form message. Falls back to
// ("", reason) when the prefix doesn't look like a code.
func splitBounceReason(reason string) (code, message string) {
	m := bounceReasonRegexp.FindStringSubmatch(reason)
	if m == nil {
		return "", reason
	}
	return m[1], m[2]
}

// extractInlineImages finds data URI images in HTML, replaces them with cid: references,
// and returns the modified HTML plus the extracted image parts.
func extractInlineImages(html string) (string, []cidImage) {
	var images []cidImage
	counter := 0
	result := dataURIRegexp.ReplaceAllStringFunc(html, func(match string) string {
		parts := dataURIRegexp.FindStringSubmatch(match)
		if len(parts) != 5 {
			return match
		}
		prefix, imgType, b64Data, suffix := parts[1], parts[2], parts[3], parts[4]

		// Only allow safe raster image types — reject SVG and other potentially dangerous formats.
		if !safeImageMIMEs[strings.ToLower(imgType)] {
			return match // leave non-raster data URIs as-is (will be stripped by sanitizer)
		}

		// Strip whitespace from base64 data.
		b64Data = strings.Join(strings.Fields(b64Data), "")

		raw, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			return match // leave as-is if we can't decode
		}

		counter++
		cid := fmt.Sprintf("img%03d@bmail.ag", counter)
		images = append(images, cidImage{
			CID:         cid,
			ContentType: "image/" + imgType,
			Data:        raw,
		})
		return fmt.Sprintf("%scid:%s%s", prefix, cid, suffix)
	})
	return result, images
}

// writeBase64Lines writes base64-encoded data in 76-char lines per RFC 2045.
func writeBase64Lines(w *strings.Builder, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		fmt.Fprintf(w, "%s\r\n", encoded[i:end])
	}
}

// extractICSMethod scans an iCalendar body for the top-level METHOD property
// (REQUEST, REPLY, CANCEL, etc.). Returns "" if no METHOD line is present.
// Tolerates both CRLF and bare LF line endings since some producers (notably
// Google Calendar) emit non-RFC-compliant LF folding.
// appendFreeTierFooter adds the Hotmail-style signup line at the end
// of an outbound cleartext body. format may be "html" or "plain"; for
// HTML we wrap the line in styled markup, for plaintext we add a
// signature delimiter so well-behaved clients hide it as a footer.
//
// senderDomain is reflected in the visible text ("Get your @<domain>
// email") to advertise the same bmail-managed address namespace the
// sender is on (bmail.ag / naru.to / gund.am / *.pizza all resolve to
// the gateway, so the visitor can pick @<domain> on signup). The URL
// is always bmail.ag — that's where the marketing + signup form lives.
//
// affiliateCode is appended as ?_a=<code> so referrals attribute back
// to the sender. Empty code falls back to the bare bmail.ag URL.
func appendFreeTierFooter(body, format, senderDomain, affiliateCode string) string {
	if senderDomain == "" {
		senderDomain = "bmail.ag"
	}
	signupURL := "https://bmail.ag/"
	if affiliateCode != "" {
		signupURL = "https://bmail.ag/?_a=" + url.QueryEscape(affiliateCode)
	}
	if format == "plain" {
		return body + fmt.Sprintf("\r\n\r\n-- \r\nSent with bmail — private encrypted email. Get your @%s email free at %s\r\n", senderDomain, signupURL)
	}
	return body + fmt.Sprintf(
		`<div style="margin-top:24px;padding-top:8px;border-top:1px solid #eee;color:#888;font:12px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif"><a href="%s" style="color:#888;text-decoration:none">Sent with bmail — private encrypted email. Get your @%s email free →</a></div>`,
		signupURL, senderDomain,
	)
}

func extractICSMethod(body string) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	for _, line := range strings.Split(normalized, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "METHOD:") {
			return strings.TrimSpace(trimmed[len("METHOD:"):])
		}
	}
	return ""
}

func composeRFC5322(om *OutboundMessage, attachments []mimeAttachment) []byte {
	// Use pre-generated Message-ID if available, otherwise generate one.
	msgID := om.RFCMessageID
	if msgID == "" {
		msgDomain := "bmail.ag"
		if idx := strings.LastIndex(om.SenderAddress, "@"); idx >= 0 {
			msgDomain = om.SenderAddress[idx+1:]
		}
		msgID = fmt.Sprintf("<%s@%s>", uuid.New().String(), msgDomain)
	}
	date := time.Now().UTC().Format(time.RFC1123Z)

	subject := om.EncryptedSubject
	if subject == "" {
		subject = "(no subject)"
	}

	body := om.EncryptedBody
	if body == "" {
		body = ""
	}

	// For plaintext messages, the subject and body are base64-encoded plaintext.
	// Decode them for the RFC 5322 message.
	if om.EncryptionType == "plaintext" {
		if decoded, err := base64Decode(subject); err == nil {
			subject = decoded
		}
		// Strip CRLF from decoded subject to prevent header injection.
		subject = sanitizeHeaderValue(subject)
		if decoded, err := base64Decode(body); err == nil {
			body = decoded
		}
		// Strip NUL bytes from decoded body to prevent content injection.
		body = strings.ReplaceAll(body, "\x00", "")

		// Hotmail-style signup footer on outbound from free-tier
		// accounts. Only appended for cleartext sends — PGP / S/MIME
		// payloads can't be modified without breaking signatures, and
		// bmail-to-bmail traffic is encrypted to the recipient's key
		// and never reaches this branch. Recipients on the receiving
		// side see a small line inviting them to get their own bmail.
		if om.SenderTier == "free" {
			senderDomain := ""
			if idx := strings.LastIndex(om.SenderAddress, "@"); idx >= 0 {
				senderDomain = om.SenderAddress[idx+1:]
			}
			body = appendFreeTierFooter(body, om.BodyFormat, senderDomain, om.SenderAffiliateCode)
		}
	}

	// Normalize contentEditable HTML quirks before sending.
	// Chrome wraps empty lines as <div><br></div> — collapse to <br>.
	body = normalizeEditorHTML(body)

	// Extract inline data URI images from the HTML body, replacing them with cid: references.
	var inlineImages []cidImage
	body, inlineImages = extractInlineImages(body)

	// Body format is determined by the sender. Default to HTML (compose editor output).
	isCalendar := om.BodyFormat == "calendar"
	isHTML := om.BodyFormat != "plain" && !isCalendar

	var b strings.Builder

	// No Received header added here — the receiving MTA adds the authoritative
	// one with real TLS info. A self-referential Received header from our own
	// outbound server triggers SpamAssassin RCVD_NO_TLS_LAST.

	// RFC 5322 headers — all values sanitized to prevent header injection.
	if om.SenderDisplayName != "" {
		safeName := sanitizeHeaderValue(om.SenderDisplayName)
		// RFC 5322 quoted-string: escape backslashes and double quotes.
		safeName = strings.ReplaceAll(safeName, `\`, `\\`)
		safeName = strings.ReplaceAll(safeName, `"`, `\"`)
		fmt.Fprintf(&b, "From: \"%s\" <%s>\r\n", safeName, sanitizeHeaderValue(om.SenderAddress))
	} else {
		fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeaderValue(om.SenderAddress))
	}
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeaderValue(om.ToAddress))
	if len(om.CcAddresses) > 0 {
		var safeCc []string
		for _, cc := range om.CcAddresses {
			safeCc = append(safeCc, sanitizeHeaderValue(cc))
		}
		fmt.Fprintf(&b, "Cc: %s\r\n", strings.Join(safeCc, ", "))
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeaderValue(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", date)
	fmt.Fprintf(&b, "Message-Id: %s\r\n", msgID)
	if om.InReplyTo != "" {
		fmt.Fprintf(&b, "In-Reply-To: %s\r\n", sanitizeHeaderValue(om.InReplyTo))
		fmt.Fprintf(&b, "References: %s\r\n", sanitizeHeaderValue(om.InReplyTo))
	}
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")

	hasFileAttachments := len(attachments) > 0
	hasInlineImages := len(inlineImages) > 0

	// Helper: write text/plain + text/html as multipart/alternative (or just text/plain).
	writeAltParts := func(w *strings.Builder) {
		if !isHTML {
			fmt.Fprintf(w, "Content-Type: text/plain; charset=utf-8\r\n")
			fmt.Fprintf(w, "\r\n")
			fmt.Fprintf(w, "%s\r\n", html.UnescapeString(body))
		} else {
			altBoundary := fmt.Sprintf("=_bmail_alt_%d", time.Now().UnixNano())
			fmt.Fprintf(w, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", altBoundary)
			fmt.Fprintf(w, "\r\n")

			plainBody := body
			plainBody = strings.ReplaceAll(plainBody, "<br>", "\n")
			plainBody = strings.ReplaceAll(plainBody, "<br/>", "\n")
			plainBody = strings.ReplaceAll(plainBody, "<br />", "\n")
			plainBody = strings.ReplaceAll(plainBody, "</p>", "\n")
			plainBody = strings.ReplaceAll(plainBody, "</div>", "\n")
			plainBody = stripHTMLTags(plainBody)
			plainBody = html.UnescapeString(plainBody)

			fmt.Fprintf(w, "--%s\r\n", altBoundary)
			fmt.Fprintf(w, "Content-Type: text/plain; charset=utf-8\r\n")
			fmt.Fprintf(w, "\r\n")
			fmt.Fprintf(w, "%s\r\n", strings.TrimSpace(plainBody))

			fmt.Fprintf(w, "--%s\r\n", altBoundary)
			fmt.Fprintf(w, "Content-Type: text/html; charset=utf-8\r\n")
			fmt.Fprintf(w, "\r\n")
			fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>\r\n", body)

			fmt.Fprintf(w, "--%s--\r\n", altBoundary)
		}
	}

	// Helper: write multipart/related (alt body + CID inline images).
	// Uses index-based access to nil image data after writing.
	writeRelatedParts := func(w *strings.Builder) {
		relBoundary := fmt.Sprintf("=_bmail_rel_%d", time.Now().UnixNano())
		fmt.Fprintf(w, "Content-Type: multipart/related; boundary=\"%s\"\r\n", relBoundary)
		fmt.Fprintf(w, "\r\n")

		fmt.Fprintf(w, "--%s\r\n", relBoundary)
		writeAltParts(w)

		for i := range inlineImages {
			fmt.Fprintf(w, "--%s\r\n", relBoundary)
			fmt.Fprintf(w, "Content-Type: %s\r\n", inlineImages[i].ContentType)
			fmt.Fprintf(w, "Content-Transfer-Encoding: base64\r\n")
			fmt.Fprintf(w, "Content-ID: <%s>\r\n", inlineImages[i].CID)
			fmt.Fprintf(w, "Content-Disposition: inline\r\n")
			fmt.Fprintf(w, "\r\n")
			writeBase64Lines(w, inlineImages[i].Data)
			inlineImages[i].Data = nil
		}

		fmt.Fprintf(w, "--%s--\r\n", relBoundary)
	}

	// Helper: write file attachment MIME parts. Uses index-based access
	// so we can nil each attachment's Data after writing its base64 to
	// the builder, freeing potentially large (25 MB) buffers before
	// processing the next attachment. Critical for the 512 MB SGX heap.
	writeFileAttachments := func(w *strings.Builder, boundary string) {
		for i := range attachments {
			fmt.Fprintf(w, "--%s\r\n", boundary)
			ct := attachments[i].ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			// RFC 2231 encoding prevents header injection via filenames with
			// CRLF, quotes, or non-ASCII characters.
			encoded := encodeRFC2231Filename(attachments[i].Filename)
			fmt.Fprintf(w, "Content-Type: %s;\r\n\tname*=UTF-8''%s\r\n", ct, encoded)
			fmt.Fprintf(w, "Content-Disposition: attachment;\r\n\tfilename*=UTF-8''%s\r\n", encoded)
			fmt.Fprintf(w, "Content-Transfer-Encoding: base64\r\n")
			fmt.Fprintf(w, "\r\n")
			writeBase64Lines(w, attachments[i].Data)
			// Release raw bytes now that they've been base64-encoded
			// into the builder. GC can reclaim this before the next
			// attachment is written.
			attachments[i].Data = nil
		}
	}

	// Build the MIME structure depending on what we have:
	//   - No images, no attachments → just body
	//   - Inline images, no attachments → multipart/related(alt + cid images)
	//   - No images, file attachments → multipart/mixed(body + attachments)
	//   - Both → multipart/mixed(multipart/related(alt + cid images) + attachments)
	// Calendar messages: send as text/calendar with the METHOD pulled from
	// the ICS body itself (REQUEST, REPLY, CANCEL, etc.). Gmail and other
	// MUAs require the Content-Type method parameter to match the ICS METHOD
	// for the message to be recognized as an RSVP/cancellation.
	if isCalendar {
		method := extractICSMethod(body)
		if method == "" {
			method = "REQUEST"
		}
		fmt.Fprintf(&b, "Content-Type: text/calendar; charset=utf-8; method=%s\r\n", method)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "%s\r\n", body)
		goto sendMsg
	}

	switch {
	case !hasInlineImages && !hasFileAttachments:
		writeAltParts(&b)

	case hasInlineImages && !hasFileAttachments:
		writeRelatedParts(&b)

	case !hasInlineImages && hasFileAttachments:
		mixedBoundary := fmt.Sprintf("=_bmail_mixed_%d", time.Now().UnixNano())
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n", mixedBoundary)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "--%s\r\n", mixedBoundary)
		writeAltParts(&b)
		writeFileAttachments(&b, mixedBoundary)
		fmt.Fprintf(&b, "--%s--\r\n", mixedBoundary)

	default: // both inline images and file attachments
		mixedBoundary := fmt.Sprintf("=_bmail_mixed_%d", time.Now().UnixNano())
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n", mixedBoundary)
		fmt.Fprintf(&b, "\r\n")
		fmt.Fprintf(&b, "--%s\r\n", mixedBoundary)
		writeRelatedParts(&b)
		writeFileAttachments(&b, mixedBoundary)
		fmt.Fprintf(&b, "--%s--\r\n", mixedBoundary)
	}

sendMsg:
	return []byte(b.String())
}

const maxAttempts = 3

// outboundHandler processes messages from the mail.outbound.> queue.
type outboundHandler struct {
	ctx              context.Context
	sender           *smtp.SMTPSender
	qc               *queue.QueueClient
	attachmentStore  *storage.AttachmentStore
	blobStore        *storage.BlobStore
	authStore        *storage.AuthStore
	mailStore        *storage.MailStore
	folderStore      *storage.FolderStore
	bounceEventStore *storage.BounceEventStore
}

func (h *outboundHandler) handle(msg []byte) error {
	var om OutboundMessage
	if err := json.Unmarshal(msg, &om); err != nil {
		slog.Error("invalid outbound message", "error", err)
		return nil // ack bad messages to avoid infinite loop
	}

	slog.Info("delivering message", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress), "attempt", om.Attempt+1, "encryption_type", om.EncryptionType)

	tenantID, err := uuid.Parse(om.TenantID)
	if err != nil {
		slog.Error("invalid tenant_id", "tenant_id", om.TenantID, "error", err)
		return nil
	}

	// Use plaintext attachments from payload if available (E2E encrypted flow —
	// client decrypted and provided plaintext for external delivery).
	var attachments []mimeAttachment
	if len(om.PlaintextAttachments) > 0 {
		for _, pa := range om.PlaintextAttachments {
			// Data field is a MinIO blob reference (stored by gateway to avoid NATS size limits).
			var data []byte
			var fetchErr error
			if h.blobStore != nil && strings.Contains(pa.Data, "/att/") {
				// Blob reference — download from MinIO.
				data, fetchErr = h.blobStore.DownloadShared(h.ctx, pa.Data)
				if fetchErr == nil {
					// Clean up temporary blob after fetching.
					_ = h.blobStore.Delete(h.ctx, pa.Data)
				}
			} else {
				// Legacy: inline base64 data.
				data, fetchErr = base64.StdEncoding.DecodeString(pa.Data)
			}
			if fetchErr != nil {
				slog.Warn("fetch plaintext attachment failed, skipping", "attachment_id", pa.AttachmentID, "error", fetchErr)
				continue
			}
			attachments = append(attachments, mimeAttachment{
				Filename:    pa.Filename,
				ContentType: pa.ContentType,
				Data:        data,
			})
			slog.Info("using plaintext attachment for outbound", "attachment_id", pa.AttachmentID, "size", len(data))
		}
	} else if len(om.AttachmentIDs) > 0 && om.SenderUserID != "" && h.attachmentStore != nil && h.blobStore != nil {
		// Legacy fallback: fetch from blob store.
		senderUID, parseErr := uuid.Parse(om.SenderUserID)
		if parseErr != nil {
			slog.Error("invalid sender_user_id", "sender_user_id", om.SenderUserID, "error", parseErr)
		} else {
			for _, aidStr := range om.AttachmentIDs {
				aid, parseErr := uuid.Parse(aidStr)
				if parseErr != nil {
					slog.Warn("invalid attachment_id, skipping", "attachment_id", aidStr, "error", parseErr)
					continue
				}
				att, fetchErr := h.attachmentStore.GetAttachment(h.ctx, aid, senderUID, tenantID)
				if fetchErr != nil {
					slog.Warn("failed to fetch attachment metadata, skipping", "attachment_id", aidStr, "error", fetchErr)
					continue
				}
				data, dlErr := h.blobStore.DownloadVerified(h.ctx, att.BlobKey, senderUID)
				if dlErr != nil {
					slog.Warn("failed to download attachment blob, skipping", "attachment_id", aidStr, "error", dlErr)
					continue
				}
				attachments = append(attachments, mimeAttachment{
					Filename:    string(att.EncryptedFilename),
					ContentType: string(att.EncryptedContentType),
					Data:        data,
				})
				slog.Info("fetched attachment for outbound message", "attachment_id", aidStr, "size", len(data))
			}
		}
	}

	// Compose RFC 5322 message from the payload fields.
	rfcBody := composeRFC5322(&om, attachments)

	// Release raw attachment data now that it's been base64-encoded into
	// rfcBody. The writeFileAttachments helper already nils individual
	// entries, but clear the slice itself so GC can collect the backing
	// array. This avoids holding attachment bytes alongside the composed
	// RFC 5322 body (which is already 4/3× the raw size).
	for i := range attachments {
		attachments[i].Data = nil
	}
	attachments = nil

	slog.Info("composed RFC 5322 message", "total_bytes", len(rfcBody))

	sendErr := h.sender.SendMessage(h.ctx, om.SenderAddress, om.ToAddress, rfcBody, tenantID)
	if sendErr == nil {
		slog.Info("delivered message", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress))
		return nil
	}

	// Permanent failure — bounce, do not retry.
	var permErr *smtp.ErrPermanent
	if errors.As(sendErr, &permErr) {
		slog.Error("permanent failure", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress), "error", permErr)
		h.insertBounce(om.SenderAddress, om.ToAddress, permErr.Error(), om.RFCMessageID, true)
		return nil
	}

	// Temporary failure — retry with exponential backoff.
	om.Attempt++
	if om.Attempt >= maxAttempts {
		slog.Error("max retries exceeded", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress), "error", sendErr)
		h.insertBounce(om.SenderAddress, om.ToAddress, sendErr.Error(), om.RFCMessageID, false)
		return nil
	}

	// Exponential backoff: 30s, 120s, ... capped at 5 minutes.
	backoff := time.Duration(30*math.Pow(4, float64(om.Attempt-1))) * time.Second
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}
	slog.Info("retrying delivery", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress), "backoff", backoff, "attempt", om.Attempt+1, "max_attempts", maxAttempts, "error", sendErr)

	retryData, _ := json.Marshal(om)
	// Use context-aware timer so retries cancel on shutdown.
	go func() {
		timer := time.NewTimer(backoff)
		defer timer.Stop()
		select {
		case <-h.ctx.Done():
			slog.Warn("retry canceled due to shutdown", "from", gateway.RedactEmail(om.SenderAddress), "to", gateway.RedactEmail(om.ToAddress))
			return
		case <-timer.C:
			if pubErr := h.qc.Publish(h.ctx, fmt.Sprintf("mail.outbound.retry.%d", om.Attempt), retryData); pubErr != nil {
				slog.Error("failed to re-queue message", "error", pubErr)
			}
		}
	}()

	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Postgres connection.
	pgURL := config.Require("DATABASE_URL", "")
	db, err := storage.NewDB(ctx, pgURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %v", err)
	}
	defer db.Close()

	domainStore := storage.NewDomainStore(db)
	attachmentStore := storage.NewAttachmentStore(db)

	// MinIO/S3 blob store for fetching attachment data.
	var blobStore *storage.BlobStore
	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	minioAccess := os.Getenv("MINIO_ACCESS_KEY")
	minioSecret := os.Getenv("MINIO_SECRET_KEY")
	minioSSL := os.Getenv("MINIO_USE_SSL") == "true"
	if minioEndpoint != "" && minioAccess != "" && minioSecret != "" {
		bs, bsErr := storage.NewBlobStore(minioEndpoint, minioAccess, minioSecret, minioSSL)
		if bsErr != nil {
			slog.Warn("failed to connect to blob store, attachments will not be included in outbound mail", "error", bsErr)
		} else {
			blobStore = bs
			slog.Info("blob store connected for outbound attachments")
		}
	} else {
		slog.Warn("MINIO_ENDPOINT/ACCESS_KEY/SECRET_KEY not set, outbound attachments disabled")
	}

	// Redis connection for MTA-STS policy caching.
	var senderOpts []smtp.SMTPSenderOption
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Warn("invalid REDIS_URL, MTA-STS caching disabled", "error", err)
		} else {
			rdb := redis.NewClient(opt)
			if err := rdb.Ping(ctx).Err(); err != nil {
				slog.Warn("redis ping failed, MTA-STS caching disabled", "error", err)
			} else {
				senderOpts = append(senderOpts, smtp.WithRedis(rdb))
				slog.Info("MTA-STS policy caching enabled via Redis")
			}
		}
	}

	// TEE runtime for unsealing DKIM keys.
	teeRuntime := tee.NewRuntime()
	senderOpts = append(senderOpts, smtp.WithTEERuntime(teeRuntime))

	// ADR-007: optional pool-key path. When KEYSTORE_ADDR +
	// KEYSTORE_MRENCLAVE_HEX are set, smtp-outbound fetches DKIM
	// keys from the keystore for tenants that have flipped their
	// DKIMPoolSelector flag. Tenants without the flag stay on the
	// legacy per-tenant unseal path.
	smtpHostnameForKeystore := os.Getenv("SMTP_HOSTNAME")
	if smtpHostnameForKeystore == "" {
		smtpHostnameForKeystore = os.Getenv("DEFAULT_DOMAIN")
	}
	if smtpHostnameForKeystore == "" {
		smtpHostnameForKeystore = "smtp-out.bmail.ag"
	}
	dkimWiring, err := buildDKIMPoolWiring(teeRuntime, smtpHostnameForKeystore, "/opt/bmail/sealed/sealed_smtp_outbound_tls_key.bin")
	if err != nil {
		return fmt.Errorf("build dkim pool wiring: %w", err)
	}
	if dkimWiring.getter != nil {
		senderOpts = append(senderOpts, smtp.WithDKIMPool(dkimWiring.getter))
		slog.Info("dkim pool path enabled (keystore-backed)")

		// Publish any active pool TXT records via attested
		// enclaveUpdate at startup. Idempotent (mode=replace) so
		// re-running on every boot just re-affirms what's already
		// in DNS. Non-fatal — sender works without DNS records as
		// long as no tenant has flipped its dkim_pool_selector.
		publishCtx, cancelPublish := context.WithTimeout(context.Background(), 60*time.Second)
		go func() {
			defer cancelPublish()
			publishDKIMPoolTXTs(publishCtx, dkimWiring, teeRuntime)
		}()
	}

	// Set EHLO hostname from env (same var used for peer discovery and Received header).
	heloHost := os.Getenv("SMTP_HOSTNAME")
	if heloHost == "" {
		heloHost = os.Getenv("DEFAULT_DOMAIN")
	}
	if heloHost == "" {
		heloHost = "smtp-out.bmail.ag"
	}
	senderOpts = append(senderOpts, smtp.WithHeloHostname(heloHost))

	sender := smtp.NewSMTPSender(domainStore, senderOpts...)

	// NATS connection.
	natsURL := config.Require("NATS_URL", "")
	// Load shared HMAC key for cross-instance message verification.
	var natsHMACKey []byte
	if natsKeyHex := config.RequireInProduction("NATS_HMAC_KEY"); natsKeyHex != "" {
		natsHMACKey, err = hex.DecodeString(natsKeyHex)
		if err != nil {
			return fmt.Errorf("invalid NATS_HMAC_KEY hex: %v", err)
		}
		if len(natsHMACKey) != 32 {
			return fmt.Errorf("NATS_HMAC_KEY must be 32 bytes (64 hex chars), got %d", len(natsHMACKey))
		}
	} else {
		slog.Warn("NATS_HMAC_KEY not set; using random key (messages won't be verifiable across instances)")
	}
	qc, err := queue.NewQueueClient(natsURL, natsHMACKey)
	if err != nil {
		return fmt.Errorf("connect to nats: %v", err)
	}
	defer qc.Close()

	authStore := storage.NewAuthStore(db)
	mailStore := storage.NewMailStore(db)
	folderStore := storage.NewFolderStore(db)
	bounceEventStore := storage.NewBounceEventStore(db)

	handler := &outboundHandler{
		ctx: ctx, sender: sender, qc: qc,
		attachmentStore: attachmentStore, blobStore: blobStore,
		authStore: authStore, mailStore: mailStore, folderStore: folderStore,
		bounceEventStore: bounceEventStore,
	}
	err = qc.Subscribe("mail.outbound.>", handler.handle)
	if err != nil {
		return fmt.Errorf("subscribe to mail.outbound: %v", err)
	}

	// Watchdog over core NATS — see internal/queue/watchdog.go. Three
	// missed heartbeats triggers exit(1) and systemd restart.
	if werr := qc.StartWatchdog(ctx, queue.WatchdogConfig{
		Label: "smtp-outbound",
		OnFail: func(reason string) {
			slog.Error("watchdog tripped — exiting for restart", "reason", reason)
			os.Exit(1)
		},
	}); werr != nil {
		slog.Warn("watchdog setup failed; continuing without health-loop", "error", werr)
	}

	// Peer discovery and certificate synchronization.
	smtpHostname := os.Getenv("SMTP_HOSTNAME")
	if smtpHostname == "" {
		smtpHostname = os.Getenv("DEFAULT_DOMAIN")
	}
	peerPort := os.Getenv("PEER_PORT")
	if peerPort == "" {
		peerPort = "8093"
	}
	// PEER_AUTH_SECRET — shared HMAC secret for /peer/key. See smtp-inbound
	// main.go for the full rationale; empty = peer key sharing disabled.
	var peerAuthSecret []byte
	if hexSecret := os.Getenv("PEER_AUTH_SECRET"); hexSecret != "" {
		if decoded, err := hex.DecodeString(hexSecret); err == nil && len(decoded) >= 32 {
			peerAuthSecret = decoded
		} else {
			slog.Warn("PEER_AUTH_SECRET invalid or too short (need >=32 bytes hex); peer key sharing disabled")
		}
	}
	var peerMgr *peer.Manager
	// tlsPub holds smtp-outbound's outbound-side TLS public key, hoisted
	// to outer scope so the attestation handler below can bind it as
	// REPORTDATA. Stays nil if smtpHostname is unset (no TLS to attest).
	var tlsPub []byte
	if smtpHostname != "" {
		peerMgr = peer.NewManager(peer.Config{
			Hostname:      smtpHostname,
			PeerPort:      peerPort,
			TEERuntime:    teeRuntime,
			TLSKeyPath:    "/opt/bmail/sealed/sealed_smtp_outbound_tls_key.bin",
			CertDir:       "/opt/bmail/certs",
			DANEUpdateURL: os.Getenv("DANE_UPDATE_URL"),
			AuthSecret:    peerAuthSecret,
		})
		_, pub, tlsErr := tee.GenerateServerTLSConfig(teeRuntime, smtpHostname, "/opt/bmail/sealed/sealed_smtp_outbound_tls_key.bin")
		if tlsErr == nil {
			tlsPub = pub
			tlsKeyBytes, _ := tee.LoadOrSealBytes(teeRuntime, "/opt/bmail/sealed/sealed_smtp_outbound_tls_key.bin", nil)
			if startErr := peerMgr.Start(ctx, nil, tlsKeyBytes, tlsPub); startErr != nil {
				slog.Warn("peer manager start failed", "error", startErr)
			}
		}
	}

	// Health check HTTP server for Kubernetes probes.
	healthPort := os.Getenv("HEALTH_PORT")
	if healthPort == "" {
		healthPort = "8093"
	}
	metrics := gateway.NewMetrics()

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", gateway.HealthHandler())

	// DKIM key generation API — called by the backend to generate SGX-sealed DKIM keys.
	dkimAPIKey := os.Getenv("DKIM_API_KEY")
	healthMux.HandleFunc("POST /dkim/generate", handleDKIMGenerate(teeRuntime, dkimAPIKey))

	// Pre-deploy hook — localhost-only endpoint that, given a new
	// smtp-outbound MRENCLAVE about to replace this one, uses our
	// currently-allowlisted attested mTLS to keystore to delegate
	// the DKIM pool roles to the new MRENCLAVE. Lets the deploy
	// script land code updates without operator break-glass.
	// (ADR-006 §"Allowlist + chained delegation".)
	healthMux.HandleFunc("POST /admin/pre-deploy", handlePreDeploy(dkimWiring))

	rc := gateway.NewReadinessChecker()
	rc.Add("postgres", func(hctx context.Context) error { return db.Pool.Ping(hctx) })
	rc.Add("queue", func(hctx context.Context) error {
		if !qc.IsConnected() {
			return fmt.Errorf("nats disconnected")
		}
		return nil
	})
	healthMux.HandleFunc("GET /readyz", rc.Handler())
	healthMux.HandleFunc("GET /metrics", metrics.MetricsHandler())
	// Attestation: SGX quote with REPORTDATA bound to the outbound TLS
	// public key. The /verify page (via gateway proxy
	// /.well-known/sgx-quotes/smtp-outbound) cross-checks against the
	// TLSA record at _25._tcp.smtp-out.bmail.ag.
	if tlsPub != nil {
		healthMux.HandleFunc("GET /attestation", gateway.AttestationHandler(teeRuntime, tlsPub))
	}
	if peerMgr != nil {
		peerMgr.RegisterHandlers(healthMux)
	}
	healthSrv := &http.Server{
		Addr:              ":" + healthPort,
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "error", err)
		}
	}()
	slog.Info("health server listening", "addr", ":"+healthPort)

	slog.Info("smtp-outbound worker running")

	// Wait for shutdown signal, then drain inflight work.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("received signal, draining inflight work", "signal", sig)

	// Cancel context to stop retry goroutines and new message processing.
	cancel()

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer drainCancel()

	// Shut down health server so load balancers stop routing to us.
	if err := healthSrv.Shutdown(drainCtx); err != nil {
		slog.Error("health server shutdown failed", "error", err)
	}

	if err := qc.Drain(drainCtx); err != nil {
		slog.Error("drain failed", "error", err)
	}

	slog.Info("smtp-outbound worker stopped")
	return nil
}

// insertBounce publishes a bounce notification via NATS for the worker to store.
// The smtp-outbound service can't write to the blob store directly (R2 Access Denied),
// so bounce delivery is delegated to the worker which has full blob access.
func (h *outboundHandler) insertBounce(originalFrom, originalTo, reason, originalMessageID string, permanent bool) {
	if !smtp.AllowBounce(originalFrom) {
		slog.Warn("bounce rate limited", "from", gateway.RedactEmail(originalFrom))
		return
	}

	user, err := h.authStore.GetUserByAddress(h.ctx, originalFrom)
	if err != nil {
		slog.Error("bounce: sender not found", "address", gateway.RedactEmail(originalFrom), "error", err)
		return
	}

	// Bounce-rate auto-freeze: only count permanent failures (these
	// indicate the recipient mail server actively rejected the
	// message — much stronger spam signal than a transient retry
	// timeout). Freeze the account at storage.BounceFreezeThreshold
	// rolling 7-day bounces.
	bounceType := "transient"
	if permanent {
		bounceType = "permanent"
		if n, ierr := h.authStore.IncrementBounces(h.ctx, user.UserID); ierr != nil {
			slog.Warn("bounce: increment counter", "user_id", user.UserID, "error", ierr)
		} else if n >= storage.BounceFreezeThreshold {
			if ferr := h.authStore.FreezeForAbuse(h.ctx, user.UserID, fmt.Sprintf("bounce-rate %d/7d", n)); ferr != nil {
				slog.Error("bounce: freeze failed", "user_id", user.UserID, "error", ferr)
			}
		}
	}

	// Persist the bounce event for the support panel — separate from
	// the rolling counter (which only gates auto-freeze). Best-effort:
	// log on failure but don't abort the bounce-DSN delivery.
	if h.bounceEventStore != nil {
		smtpCode, smtpMsg := splitBounceReason(reason)
		ev := &storage.BounceEvent{
			UserID:      user.UserID,
			TenantID:    user.TenantID,
			Recipient:   originalTo,
			SMTPCode:    smtpCode,
			SMTPMessage: smtpMsg,
			BounceType:  bounceType,
		}
		if berr := h.bounceEventStore.Insert(h.ctx, ev); berr != nil {
			slog.Warn("bounce: persist event", "user_id", user.UserID, "error", berr)
		}
	}

	status := "could not be delivered"
	detail := "This is a permanent error. The message will not be retried."
	if !permanent {
		status = "could not be delivered after multiple attempts"
		detail = "The server has exhausted all retry attempts."
	}

	subject := fmt.Sprintf("Undelivered: message to %s", originalTo)
	body := fmt.Sprintf(`<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; line-height: 1.6;">
<p>Your message to <strong>%s</strong> %s.</p>
<p>%s</p>
<p style="padding: 12px; background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; border-radius: 6px; font-family: monospace; font-size: 13px;">%s</p>
<p style="color: #888; font-size: 12px;">— bmail mail delivery system</p>
</div>`, originalTo, status, detail, html.EscapeString(reason))

	recipientPub, err := ecdh.X25519().NewPublicKey(user.PublicKeyEncryption)
	if err != nil {
		slog.Error("bounce: invalid public key", "user_id", user.UserID, "error", err)
		return
	}

	var bounceKEMEK *mlkem.EncapsulationKey768
	if len(user.PublicKeyKEM) > 0 {
		bounceKEMEK, err = bmailcrypto.MLKEMEncapsulationKeyFromBytes(user.PublicKeyKEM)
		if err != nil {
			slog.Warn("bounce: parse KEM pubkey failed, falling back to classical", "user_id", user.UserID, "error", err)
			bounceKEMEK = nil
		}
	}

	encrypted, err := bmailcrypto.EncryptMessageHybrid(recipientPub, bounceKEMEK, []byte(subject), []byte(body))
	if err != nil {
		slog.Error("bounce: encryption failed", "user_id", user.UserID, "error", err)
		return
	}

	msgDomain := "bmail.ag"
	if idx := strings.LastIndex(originalFrom, "@"); idx >= 0 {
		msgDomain = originalFrom[idx+1:]
	}
	rfcMsgID := fmt.Sprintf("<%s@%s>", uuid.New().String(), msgDomain)

	// Publish as an inbound message — the worker stores it in the sender's inbox.
	inbound := map[string]any{
		"from":                  "noreply@" + msgDomain,
		"to":                    originalFrom,
		"tenant_id":             user.TenantID.String(),
		"user_id":               user.UserID.String(),
		"ephemeral_pubkey":      encrypted.EphemeralPubkey,
		"encrypted_message_key": encrypted.EncryptedMessageKey,
		"encrypted_body":        encrypted.EncryptedBody,
		"encrypted_subject":     encrypted.EncryptedSubject,
		"encryption_type":       "received",
		"folder_assignment":     "inbox",
		"message_id_header":     rfcMsgID,
		"in_reply_to":           originalMessageID,
		"spf_result":            "pass",
		"dkim_result":           "pass",
		"dmarc_result":          "pass",
	}
	payload, _ := json.Marshal(inbound)
	natsSubject := fmt.Sprintf("mail.inbound.%s", user.TenantID)
	if err := h.qc.Publish(h.ctx, natsSubject, payload); err != nil {
		slog.Error("bounce: failed to publish via NATS", "user_id", user.UserID, "error", err)
		return
	}
	slog.Info("bounce published via NATS", "user_id", user.UserID, "to", gateway.RedactEmail(originalTo), "permanent", permanent)
}

// ── DKIM Key Generation API ─────────────────────────────────────────────────

// dkimKeyResult is a single DKIM key pair result.
type dkimKeyResult struct {
	SealedPrivateKey []byte `json:"sealed_private_key"` // TEE-sealed private key (opaque blob)
	PublicKey        string `json:"public_key"`         // Base64-encoded public key for DNS
	Selector         string `json:"selector"`
}

// dkimGenerateResponse is the response from POST /dkim/generate.
type dkimGenerateResponse struct {
	Ed25519 *dkimKeyResult `json:"ed25519,omitempty"`
	RSA     *dkimKeyResult `json:"rsa,omitempty"`
}

const defaultDKIMSelector = "vp1"
const defaultRSADKIMSelector = "rsa1"

// handleDKIMGenerate returns an HTTP handler that generates and seals DKIM key pairs.
func handleDKIMGenerate(teeRuntime tee.TEERuntime, apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth check: require DKIM_API_KEY bearer token.
		if apiKey != "" {
			auth := r.Header.Get("Authorization")
			token := strings.TrimPrefix(auth, "Bearer ")
			if token == auth || subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}

		resp := &dkimGenerateResponse{}
		now := time.Now().Unix()

		// Ed25519 key pair.
		edPriv, edPub, err := domain.GenerateDKIMKeyPair()
		if err != nil {
			slog.Error("dkim generate ed25519", "error", err)
			http.Error(w, `{"error":"key generation failed"}`, http.StatusInternalServerError)
			return
		}
		edSealed, err := teeRuntime.Seal([]byte(edPriv))
		if err != nil {
			slog.Error("dkim seal ed25519", "error", err)
			http.Error(w, `{"error":"seal failed"}`, http.StatusInternalServerError)
			return
		}
		resp.Ed25519 = &dkimKeyResult{
			SealedPrivateKey: edSealed,
			PublicKey:        edPub,
			Selector:         fmt.Sprintf("%s-%d", defaultDKIMSelector, now),
		}

		// RSA key pair.
		rsaPrivDER, rsaPub, err := domain.GenerateRSADKIMKeyPair()
		if err != nil {
			slog.Error("dkim generate rsa", "error", err)
			http.Error(w, `{"error":"rsa key generation failed"}`, http.StatusInternalServerError)
			return
		}
		rsaSealed, err := teeRuntime.Seal(rsaPrivDER)
		if err != nil {
			slog.Error("dkim seal rsa", "error", err)
			http.Error(w, `{"error":"rsa seal failed"}`, http.StatusInternalServerError)
			return
		}
		resp.RSA = &dkimKeyResult{
			SealedPrivateKey: rsaSealed,
			PublicKey:        rsaPub,
			Selector:         fmt.Sprintf("%s-%d", defaultRSADKIMSelector, now),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
