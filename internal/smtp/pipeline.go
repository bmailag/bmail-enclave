package smtp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	// Blank import registers charset handlers (iso-8859-1, GB2312, EUC-KR,
	// Big5, Shift_JIS, …) onto message.CharsetReader. Without it, any
	// inbound mail with a non-UTF-8 body part fails parseMessage with
	// "unhandled charset". One line, fixes most of the long tail.
	_ "github.com/emersion/go-message/charset"

	gomail "github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"log/slog"

	"github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/mailparse"
	"github.com/bmailag/bmail/internal/queue"
	"github.com/bmailag/bmail/internal/spam"
	"github.com/bmailag/bmail/internal/storage"
)

// Pipeline processes inbound email: authenticates, encrypts, and queues.
//
// It also runs the per-recipient post-receive logic — block check,
// auto-add contact, rule eval, auto-reply trigger — inside the SGX
// enclave. All of those operations need the cleartext sender address,
// which only exists inside this enclave function; running them here
// means the cleartext never leaves SGX. The worker that consumes the
// enclave's output just stores whatever it's handed.
type Pipeline struct {
	authStore      *storage.AuthStore
	blockStore     *storage.BlockStore
	contactsStore  *storage.ContactsStore
	ruleStore      *storage.RuleStore
	mailStore      *storage.MailStore
	groupStore     *storage.GroupStore // optional: E2E private group delivery (ADR-012)
	folderStore    *storage.FolderStore
	labelStore     *storage.LabelStore
	autoReplyStore *storage.AutoReplyStore
	autoReplyDedup *storage.AutoReplyDedupStore
	calendarStore  *storage.CalendarStore // optional: processes inbound ICS REPLY/CANCEL
	redis          *redis.Client          // optional: publishes calendar SSE notifications
	queue          *queue.QueueClient
	signingKey     ed25519.PrivateKey // for receipt signing
	signingPub     ed25519.PublicKey  // included in receipts for verification
	enclaveID      string             // enclave measurement (MRENCLAVE or sim marker)
	spamFilter     *spam.SpamFilter   // optional spam filter
	tlsActive      bool               // whether inbound TLS is configured
}

// NewPipeline creates a new inbound mail pipeline. Only authStore +
// queue are required for basic operation. The post-receive stores can
// be wired in via SetPostReceiveStores once the smtp-inbound binary has
// them constructed; pipelines created without them fall back to having
// the worker run that logic outside the enclave.
func NewPipeline(authStore *storage.AuthStore, q *queue.QueueClient, signingKey ed25519.PrivateKey, enclaveID string) *Pipeline {
	pub := signingKey.Public().(ed25519.PublicKey)
	return &Pipeline{
		authStore:  authStore,
		queue:      q,
		signingKey: signingKey,
		signingPub: pub,
		enclaveID:  enclaveID,
	}
}

// SetPostReceiveStores wires the per-recipient stores the pipeline
// needs to run block check, auto-add, rule eval, and auto-reply inside
// the enclave. All arguments are optional — if any are nil the
// corresponding logic is skipped and the worker continues to do it.
func (p *Pipeline) SetPostReceiveStores(
	blockStore *storage.BlockStore,
	contactsStore *storage.ContactsStore,
	ruleStore *storage.RuleStore,
	mailStore *storage.MailStore,
	folderStore *storage.FolderStore,
	labelStore *storage.LabelStore,
	autoReplyStore *storage.AutoReplyStore,
	autoReplyDedup *storage.AutoReplyDedupStore,
) {
	p.blockStore = blockStore
	p.contactsStore = contactsStore
	p.ruleStore = ruleStore
	p.mailStore = mailStore
	p.folderStore = folderStore
	p.labelStore = labelStore
	p.autoReplyStore = autoReplyStore
	p.autoReplyDedup = autoReplyDedup
}

// SetGroupStore attaches the group store, enabling E2E private group delivery
// (ADR-012). When nil, group addresses simply never resolve (no group delivery).
func (p *Pipeline) SetGroupStore(gs *storage.GroupStore) {
	p.groupStore = gs
}

// SetTLSActive marks whether the SMTP server has TLS configured.
func (p *Pipeline) SetTLSActive(active bool) {
	p.tlsActive = active
}

// SetSpamFilter attaches a spam filter to the pipeline. When set, incoming
// messages are scored before encryption and the result is included in the
// enclave receipt.
func (p *Pipeline) SetSpamFilter(sf *spam.SpamFilter) {
	p.spamFilter = sf
}

// SetCalendarStore attaches a calendar store to the pipeline. When set,
// inbound emails containing ICS METHOD:REPLY or METHOD:CANCEL attachments
// are automatically processed to update the recipient's calendar events.
func (p *Pipeline) SetCalendarStore(cs *storage.CalendarStore) {
	p.calendarStore = cs
}

// SetRedis wires a Redis client so the pipeline can push
// calendar_event_updated SSE notifications after an inbound ICS REPLY
// updates an event. Optional; omit to fall back to client-side refresh.
func (p *Pipeline) SetRedis(rdb *redis.Client) {
	p.redis = rdb
}

// InboundAttachment is an attachment extracted from an inbound email.
type InboundAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	ContentID   string `json:"content_id,omitempty"` // MIME Content-ID for cid: references
	Data        []byte `json:"data"`                 // raw attachment bytes
}

// EncryptedInboundAttachment holds an attachment that has been E2E encrypted
// in the SMTP enclave. The blob data (EncryptedData) is encrypted with the
// recipient's public key, and the metadata (filename, content_type) is
// encrypted as the "subject" field of the EncryptedMessage.
type EncryptedInboundAttachment struct {
	EphemeralPubkey     []byte `json:"ephemeral_pubkey"`
	EncryptedKey        []byte `json:"encrypted_key"`
	EncryptedData       []byte `json:"encrypted_data"`
	EncryptedMetadata   []byte `json:"encrypted_metadata"` // encrypted JSON: {"filename":"x","content_type":"y"}
	SizeBytes           int64  `json:"size_bytes"`
}

// InboundMessage is the JSON payload published to NATS for inbound mail.
//
// There are no per-field encrypted address envelopes on the wire. The
// full RFC 5322 header set is encrypted inline with the body via
// EncryptMessageWithHeaders → EncryptedHeaders, and the worker just
// stores the blob. The blind index is here so the in-enclave
// block-check / auto-add can be derived without re-running encryption.
type InboundMessage struct {
	SenderBlindIndex string `json:"sender_blind_index,omitempty"`
	EncryptedHeaders []byte `json:"encrypted_headers,omitempty"`

	// Decisions made by the pipeline's in-enclave post-receive logic.
	// The worker applies these on insert — they're already authoritative
	// because they were computed against the cleartext sender inside SGX.
	RuleMoveFolderID    string   `json:"rule_move_folder_id,omitempty"` // UUID of target folder, "" = no rule
	RuleLabelIDs        []string `json:"rule_label_ids,omitempty"`      // UUIDs of labels to add
	RuleMarkRead        bool     `json:"rule_mark_read,omitempty"`
	RuleMarkStarred     bool     `json:"rule_mark_starred,omitempty"`
	// RuleDelete is intentionally NOT a field — the pipeline drops the
	// message before publishing if a rule action says delete.

	TenantID            string               `json:"tenant_id"`
	UserID              string               `json:"user_id"`
	// Group delivery (ADR-012): when GroupID is set, this message was encrypted
	// to the group's shared key and is being fanned out to a member's mailbox.
	// GroupKeyEpoch is the group's key_epoch (stored in messages.key_epoch).
	GroupID             string               `json:"group_id,omitempty"`
	GroupKeyEpoch       int                  `json:"group_key_epoch,omitempty"`
	EphemeralPubkey     []byte               `json:"ephemeral_pubkey"`
	EncryptedMessageKey []byte               `json:"encrypted_message_key"`
	EncryptedBody       []byte               `json:"encrypted_body"`
	EncryptedSubject    []byte               `json:"encrypted_subject"`
	SPFResult           string               `json:"spf_result"`
	DKIMResult          string               `json:"dkim_result"`
	DMARCResult         string               `json:"dmarc_result"`
	Receipt             []byte               `json:"receipt"`
	FolderAssignment    string               `json:"folder_assignment"` // "inbox" or "junk"
	ReceivedAt          time.Time            `json:"received_at"`
	InReplyTo           string               `json:"in_reply_to,omitempty"`
	References          string               `json:"references,omitempty"`
	MessageID           string               `json:"message_id_header,omitempty"`
	EncryptionType      string               `json:"encryption_type"` // "received", "pgp", "smime"
	PlaintextSubject    string               `json:"plaintext_subject,omitempty"` // for non-E2E messages (list view)
	AutocryptAddr       string               `json:"autocrypt_addr,omitempty"`
	AutocryptKeyData    string               `json:"autocrypt_key_data,omitempty"` // base64
	AutocryptPrefer          string                        `json:"autocrypt_prefer,omitempty"`
	Attachments              []InboundAttachment           `json:"attachments,omitempty"`
	EncryptedAttachments     []EncryptedInboundAttachment  `json:"encrypted_attachments,omitempty"`
	// Encrypted original raw RFC 5322 message (for View Source).
	EncryptedRawBody         []byte `json:"encrypted_raw_body,omitempty"`
	EncryptedRawKey          []byte `json:"encrypted_raw_key,omitempty"`
	RawEphemeralPubkey       []byte `json:"raw_ephemeral_pubkey,omitempty"`
	RawBlobFormat            string `json:"raw_blob_format,omitempty"`
	EncryptedRawMeta         []byte `json:"encrypted_raw_meta,omitempty"`
}

// runSecurityChecks performs SPF, DKIM, and DMARC verification on an inbound
// message. Errors in individual checks produce safe default values rather than
// propagating, so the function never returns an error.
func runSecurityChecks(ctx context.Context, from string, clientIP net.IP, rawMessage []byte, helo string) (spfResult, dkimResult, dmarcResult string) {
	fromDomain := ""
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		fromDomain = from[idx+1:]
	}

	spfResult, spfErr := CheckSPF(ctx, clientIP, fromDomain, from)
	if spfErr != nil {
		spfResult = "temperror"
	}

	dkimResult, dkimDomain, dkimErr := CheckDKIM(ctx, rawMessage)
	if dkimErr != nil {
		dkimResult = "none"
	}

	// SPF domain is the MAIL FROM envelope sender domain, not the header From domain.
	spfDomain := ""
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		spfDomain = from[idx+1:]
	}
	dmarcResult, dmarcErr := CheckDMARC(ctx, fromDomain, spfResult, spfDomain, dkimResult, dkimDomain)
	if dmarcErr != nil {
		slog.Debug("DMARC check failed, using default", "domain", fromDomain, "error", dmarcErr)
	}

	return spfResult, dkimResult, dmarcResult
}

// extractAutocrypt parses the Autocrypt header from the message headers, if
// present, returning the sender address, base64-encoded key data, and the
// prefer-encrypt value. All return values are empty strings when no valid
// Autocrypt header is found.
func extractAutocrypt(headers map[string][]string) (addr, keyData, prefer string) {
	acHeaders, ok := headers["Autocrypt"]
	if !ok || len(acHeaders) == 0 {
		return "", "", ""
	}
	parsedAddr, rawKeyData, parsedPrefer, err := crypto.ParseAutocryptHeader(acHeaders[0])
	if err != nil {
		return "", "", ""
	}
	// keyData is now decoded bytes; re-encode for storage.
	return parsedAddr, base64Encode(rawKeyData), parsedPrefer
}

// buildEnclaveReceipt creates an enclave receipt for a processed message, signs
// it with the pipeline's Ed25519 key, and returns the JSON-marshalled receipt.
func buildEnclaveReceipt(p *Pipeline, rawMessage []byte, encrypted *crypto.EncryptedMessage, from, spfResult, dkimResult, dmarcResult string, spamScore float64, folderAssignment string) ([]byte, error) {
	messageHash := sha256.Sum256(rawMessage)
	ciphertextHash := sha256.Sum256(encrypted.EncryptedBody)
	senderHash := crypto.HashSender(from)
	var sigPubArray [32]byte
	copy(sigPubArray[:], p.signingPub)

	receipt := &crypto.EnclaveReceipt{
		MessageHash:      messageHash,
		CiphertextHash:   ciphertextHash,
		SenderHash:       senderHash,
		SigningPublicKey:  sigPubArray,
		Timestamp:        time.Now().UTC(),
		EnclaveID:        p.enclaveID,
		TLSVerified:      p.tlsActive,
		SPFResult:        spfResult,
		DKIMResult:       dkimResult,
		DMARCResult:      dmarcResult,
		SpamScore:        spamScore,
		FolderAssignment: folderAssignment,
	}

	if _, err := crypto.SignReceipt(receipt, p.signingKey); err != nil {
		return nil, fmt.Errorf("sign receipt: %w", err)
	}

	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt: %w", err)
	}
	return receiptJSON, nil
}

// ProcessMessage is the core pipeline: parse, authenticate, encrypt, sign, publish.
func (p *Pipeline) ProcessMessage(ctx context.Context, from string, to string, rawMessage []byte, clientIP net.IP, helo string) error {
	// Zero the raw plaintext after we're done — it must not persist in heap.
	defer crypto.ZeroBytes(rawMessage)

	// 1. Parse the message to extract subject, body, and threading headers.
	parsed, err := parseMessageFull(rawMessage)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}
	subject := parsed.Subject
	body := parsed.Body
	// Zero parsed plaintext after encryption (deferred below).
	defer crypto.ZeroBytes([]byte(subject))
	defer crypto.ZeroBytes(body)

	// 2. Run SPF/DKIM/DMARC checks.
	spfResult, dkimResult, dmarcResult := runSecurityChecks(ctx, from, clientIP, rawMessage, helo)

	// 3. Run spam filter (if configured).
	var spamScore float64
	folderAssignment := "inbox"

	if p.spamFilter != nil {
		headers := parsed.Headers
		if headers == nil {
			headers = make(map[string][]string)
		}
		spamResult := p.spamFilter.CheckMessage(ctx, clientIP, helo, from, headers, body, spfResult, dkimResult, dmarcResult)
		spamScore = spamResult.Score
		folderAssignment = spamResult.FolderAssignment

		// Log individual check scores for debugging spam classification.
		if spamResult.IsSpam || spamScore >= 3.0 {
			checkDetails := make([]any, 0, len(spamResult.Checks)*4+4)
			checkDetails = append(checkDetails, "total", spamScore, "folder", folderAssignment)
			for _, c := range spamResult.Checks {
				checkDetails = append(checkDetails, c.Name, c.Score)
			}
			slog.Warn("spam score breakdown", checkDetails...)
		}
	}

	// Enforce DMARC p=reject policy by forcing messages to junk.
	// This runs AFTER the spam filter so it can't be overridden.
	if dmarcResult == "reject" {
		slog.Info("DMARC policy reject enforced — quarantining to junk", "spf", spfResult, "dkim", dkimResult)
		folderAssignment = "junk"
	}

	// 3b. Extract Autocrypt header for key discovery.
	autocryptAddr, autocryptKeyData, autocryptPrefer := extractAutocrypt(parsed.Headers)

	// 3c. Detect if the incoming message is already encrypted (PGP or S/MIME).
	encryptionType := "received" // default: server encrypts at rest to recipient's key (not true E2E)
	isPGP := crypto.DetectPGPMIME(rawMessage) || crypto.DetectPGPInline(body)
	isSMIME := crypto.DetectSMIME(rawMessage)

	// 4. Resolve recipient (exact / alias / catch-all) + look up their key.
	user, err := p.authStore.ResolveRecipient(ctx, to)
	if err != nil {
		return fmt.Errorf("lookup recipient: %w", err)
	}

	if isPGP {
		encryptionType = "pgp"
	} else if isSMIME {
		encryptionType = "smime"
	}

	recipientPub, err := ecdh.X25519().NewPublicKey(user.PublicKeyEncryption)
	if err != nil {
		return fmt.Errorf("parse recipient public key: %w", err)
	}

	// Parse ML-KEM-768 encapsulation key for hybrid encryption (PQ resistance).
	var kemEK *mlkem.EncapsulationKey768
	if len(user.PublicKeyKEM) > 0 {
		kemEK, err = crypto.MLKEMEncapsulationKeyFromBytes(user.PublicKeyKEM)
		if err != nil {
			slog.Warn("parse user KEM pubkey failed, falling back to classical", "error", err)
			kemEK = nil
		}
	}

	// Parse MIME structure for metadata (byte offsets, headers, content types).
	// This enables the client to extract body/attachments directly from the raw blob.
	rawMeta := buildRawMeta(rawMessage)

	// Encrypt the full original raw RFC 5322 message for "View Source" and range access.
	// Must happen before rawMessage is zeroed by the deferred cleanup.
	// Uses chunked encryption for range-based decryption of large messages.
	encryptedRaw, err := crypto.EncryptRawMessageWithMetaHybrid(recipientPub, kemEK, rawMessage, rawMeta, crypto.DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("encrypt raw message: %w", err)
	}
	rawBlobFormat := crypto.RawBlobFormatChunked(crypto.DefaultChunkSize)

	// For PGP/S/MIME, encrypt the raw message (preserving original ciphertext);
	// for plaintext, encrypt the parsed body.
	var messageBody []byte
	if isPGP || isSMIME {
		messageBody = rawMessage
	} else {
		messageBody = body
	}

	// Build the headers JSON from the parsed RFC 5322 headers and pass
	// it into the encryption call so it shares the body's message key.
	// Display names ("Alice <alice@example.com>") are preserved
	// verbatim. The client decrypts headers + subject + body from one
	// envelope.
	headersJSON, hdrErr := storage.MarshalMessageHeaders(parsed.Headers)
	if hdrErr != nil {
		return fmt.Errorf("marshal headers: %w", hdrErr)
	}
	encrypted, err := crypto.EncryptMessageWithHeadersHybrid(recipientPub, kemEK, []byte(subject), messageBody, headersJSON)
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}

	// 5b. Encrypt inbound attachments with recipient's public key.
	// If any attachment fails to encrypt, the entire message is rejected —
	// nothing is ever stored unencrypted.
	//
	// Memory optimization: process one attachment at a time using index-based
	// access so we can nil the original Data slice after encryption. This lets
	// GC reclaim each (potentially 25 MB) attachment before the next one is
	// encrypted, keeping peak heap usage bounded to ~1 attachment at a time
	// instead of accumulating all of them. Critical for the 512 MB SGX heap.
	var encryptedAtts []EncryptedInboundAttachment
	for i := range parsed.Attachments {
		att := &parsed.Attachments[i]
		metadataJSON := fmt.Sprintf(`{"filename":%q,"content_type":%q,"content_id":%q}`, att.Filename, att.ContentType, att.ContentID)
		sizeBytes := int64(len(att.Data))
		encAtt, encErr := crypto.EncryptMessageHybrid(recipientPub, kemEK, []byte(metadataJSON), att.Data)
		if encErr != nil {
			return fmt.Errorf("encrypt attachment %q: %w", att.Filename, encErr)
		}
		// Zero and release plaintext attachment data immediately after
		// encryption so GC can reclaim the memory before encrypting the
		// next attachment. Using index-based access (not range copy) so
		// the nil propagates back to the original slice element.
		crypto.ZeroBytes(att.Data)
		att.Data = nil
		encryptedAtts = append(encryptedAtts, EncryptedInboundAttachment{
			EphemeralPubkey:   encAtt.EphemeralPubkey,
			EncryptedKey:      encAtt.EncryptedMessageKey,
			EncryptedData:     encAtt.EncryptedBody,
			EncryptedMetadata: encAtt.EncryptedSubject,
			SizeBytes:         sizeBytes,
		})
	}

	// 6. The per-field encrypted address columns are gone from the
	// wire — `encrypted` already carries the headers blob. We still
	// compute the blind index here so the worker can do block-list
	// lookups without re-deriving the key.
	senderBlindIndex := storage.ComputeAddressBlindIndex(storage.BlindScopeMessageSender, user.UserID, from)

	// 7. Run the in-enclave post-receive logic. This is the last place
	// the cleartext sender exists — block check, auto-add, rule eval,
	// and auto-reply all live here so the cleartext never leaves SGX.
	// Decisions feed into the NATS payload below.
	hasAttachments := len(encryptedAtts) > 0
	sizeBytes := int64(len(rawMessage))
	decisions := &inboundDecisions{FolderAssignment: folderAssignment}
	p.applyPostReceive(ctx, user, from, hasAttachments, sizeBytes, parsed.MessageID, decisions)
	if decisions.Drop {
		// A rule action said "delete" — drop the message before
		// publishing. Nothing is persisted.
		slog.Info("inbound message dropped by rule", "user_id", user.UserID)
		return nil
	}
	folderAssignment = decisions.FolderAssignment

	// 7b. Process ICS calendar attachments (METHOD:REPLY / METHOD:CANCEL).
	// This updates the recipient's calendar as a side-effect — the email
	// itself is still delivered normally. Errors are logged and swallowed
	// so calendar processing never blocks email delivery.
	if parsed.CalendarICS != nil && p.calendarStore != nil {
		p.processInboundICS(ctx, user, parsed.CalendarICS)
	}

	// 8. Build and sign the enclave receipt now that the final folder
	// assignment is known (it may have flipped to "junk" because of a
	// block-list match in step 7).
	receiptJSON, err := buildEnclaveReceipt(p, rawMessage, encrypted, from, spfResult, dkimResult, dmarcResult, spamScore, folderAssignment)
	if err != nil {
		return err
	}

	// 9. Publish to NATS. Only encrypted_headers + the blind index ride
	// the wire for addresses. The full RFC 5322 header set lives inside
	// `encrypted.EncryptedHeaders`, decryptable by the recipient with
	// the same envelope as the body.
	msg := InboundMessage{
		TenantID:            user.TenantID.String(),
		UserID:              user.UserID.String(),
		SenderBlindIndex:    senderBlindIndex,
		RuleMoveFolderID:    decisions.MoveFolderID,
		RuleLabelIDs:        decisions.LabelIDs,
		RuleMarkRead:        decisions.MarkRead,
		RuleMarkStarred:     decisions.MarkStarred,
		EphemeralPubkey:     encrypted.EphemeralPubkey,
		EncryptedMessageKey: encrypted.EncryptedMessageKey,
		EncryptedBody:       encrypted.EncryptedBody,
		EncryptedSubject:    encrypted.EncryptedSubject,
		EncryptedHeaders:    encrypted.EncryptedHeaders,
		SPFResult:           spfResult,
		DKIMResult:          dkimResult,
		DMARCResult:         dmarcResult,
		Receipt:             receiptJSON,
		FolderAssignment:    folderAssignment,
		ReceivedAt:          time.Now().UTC(),
		InReplyTo:           parsed.InReplyTo,
		References:          parsed.References,
		MessageID:           parsed.MessageID,
		EncryptionType:      encryptionType,
		AutocryptAddr:       autocryptAddr,
		AutocryptKeyData:    autocryptKeyData,
		AutocryptPrefer:          autocryptPrefer,
		EncryptedAttachments:     encryptedAtts,
		EncryptedRawBody:        encryptedRaw.EncryptedBody,
		EncryptedRawKey:         encryptedRaw.EncryptedMessageKey,
		RawEphemeralPubkey:      encryptedRaw.EphemeralPubkey,
		RawBlobFormat:           rawBlobFormat,
		EncryptedRawMeta:        encryptedRaw.EncryptedMeta,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal inbound message: %w", err)
	}

	// Release encrypted attachment blobs and the encrypted raw body now
	// that they've been serialised into `data`. This can free tens of MB
	// before the NATS publish (which may block on back-pressure).
	for i := range encryptedAtts {
		encryptedAtts[i].EncryptedData = nil
		encryptedAtts[i].EncryptedKey = nil
		encryptedAtts[i].EncryptedMetadata = nil
	}
	encryptedAtts = nil
	msg.EncryptedAttachments = nil
	msg.EncryptedRawBody = nil
	encrypted = nil
	encryptedRaw = nil

	natsSubject := fmt.Sprintf("mail.inbound.%s", user.TenantID.String())
	if err := p.queue.Publish(ctx, natsSubject, data); err != nil {
		// Surface the marshalled payload size so over-cap NATS publish
		// failures are immediately diagnosable from logs (without it
		// the only signal is "maximum payload exceeded" with no idea
		// what tipped over).
		return fmt.Errorf("publish to queue (payload=%d bytes): %w", len(data), err)
	}

	slog.Info("message processed", "folder", folderAssignment, "spf", spfResult, "dkim", dkimResult, "dmarc", dmarcResult, "spam_score", spamScore, "encryption", encryptionType)
	return nil
}

// ProcessGroupMessage delivers an inbound message addressed to an E2E private
// group (ADR-012). Unlike ProcessMessage (which encrypts to a single user's
// key), this encrypts the message ONCE to the group's shared public key and
// fans the identical ciphertext into each member's mailbox, marked with the
// group_id + group key_epoch. The server never holds the group private key, so
// it cannot read the mail. Per-member rules/block/auto-reply are intentionally
// skipped (the cleartext is identical for all members; group mail lands in
// inbox), and members are filtered by joined_at_epoch so no one sees pre-join
// history.
//
// directRecipients are addresses that already received this message directly
// in the same delivery (To/Cc RCPTs). They — and the sender — are skipped in
// the fan-out so nobody gets the same message twice (the Gmail ingestion-dedup
// model: your own post to a group is represented by your Sent copy, and a
// direct copy beats a list copy).
func (p *Pipeline) ProcessGroupMessage(ctx context.Context, from string, group *storage.Group, rawMessage []byte, clientIP net.IP, helo string, directRecipients ...string) error {
	defer crypto.ZeroBytes(rawMessage)
	if p.groupStore == nil {
		return fmt.Errorf("group delivery not configured")
	}

	parsed, err := parseMessageFull(rawMessage)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}
	subject := parsed.Subject
	body := parsed.Body
	defer crypto.ZeroBytes([]byte(subject))
	defer crypto.ZeroBytes(body)

	spfResult, dkimResult, dmarcResult := runSecurityChecks(ctx, from, clientIP, rawMessage, helo)

	folderAssignment := "inbox"
	var spamScore float64
	if p.spamFilter != nil {
		headers := parsed.Headers
		if headers == nil {
			headers = make(map[string][]string)
		}
		sr := p.spamFilter.CheckMessage(ctx, clientIP, helo, from, headers, body, spfResult, dkimResult, dmarcResult)
		spamScore = sr.Score
		folderAssignment = sr.FolderAssignment
	}
	if dmarcResult == "reject" {
		folderAssignment = "junk"
	}

	// Mailing-list headers (RFC 2919 List-Id, RFC 2369 List-Post, plus Reply-To
	// when the sender didn't set one): stamped AFTER SPF/DKIM/spam ran on the
	// original bytes — so verification covers what the sender actually signed —
	// and BEFORE encryption, so both the encrypted header map (bmail clients)
	// and the raw blob (external clients reading an exported .eml) carry them.
	// This is what makes "reply" go to the group everywhere, not just in our
	// own client.
	if parsed.Headers == nil {
		parsed.Headers = make(map[string][]string)
	}
	if stamped, changed := stampGroupListHeaders(parsed.Headers, rawMessage, group.Address); changed {
		rawMessage = stamped
		defer crypto.ZeroBytes(stamped)
	}

	// Encrypt to the GROUP public key (hybrid X25519 + ML-KEM-768).
	groupPub, err := ecdh.X25519().NewPublicKey(group.PublicKeyX25519)
	if err != nil {
		return fmt.Errorf("parse group public key: %w", err)
	}
	var kemEK *mlkem.EncapsulationKey768
	if len(group.PublicKeyKEM) > 0 {
		kemEK, err = crypto.MLKEMEncapsulationKeyFromBytes(group.PublicKeyKEM)
		if err != nil {
			slog.Warn("parse group KEM pubkey failed, falling back to classical", "group_id", group.GroupID, "error", err)
			kemEK = nil
		}
	}

	rawMeta := buildRawMeta(rawMessage)
	encryptedRaw, err := crypto.EncryptRawMessageWithMetaHybrid(groupPub, kemEK, rawMessage, rawMeta, crypto.DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("encrypt raw message: %w", err)
	}
	rawBlobFormat := crypto.RawBlobFormatChunked(crypto.DefaultChunkSize)

	headersJSON, hdrErr := storage.MarshalMessageHeaders(parsed.Headers)
	if hdrErr != nil {
		return fmt.Errorf("marshal headers: %w", hdrErr)
	}
	encrypted, err := crypto.EncryptMessageWithHeadersHybrid(groupPub, kemEK, []byte(subject), body, headersJSON)
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}

	var encryptedAtts []EncryptedInboundAttachment
	for i := range parsed.Attachments {
		att := &parsed.Attachments[i]
		metadataJSON := fmt.Sprintf(`{"filename":%q,"content_type":%q,"content_id":%q}`, att.Filename, att.ContentType, att.ContentID)
		sizeBytes := int64(len(att.Data))
		encAtt, encErr := crypto.EncryptMessageHybrid(groupPub, kemEK, []byte(metadataJSON), att.Data)
		if encErr != nil {
			return fmt.Errorf("encrypt attachment %q: %w", att.Filename, encErr)
		}
		crypto.ZeroBytes(att.Data)
		att.Data = nil
		encryptedAtts = append(encryptedAtts, EncryptedInboundAttachment{
			EphemeralPubkey:   encAtt.EphemeralPubkey,
			EncryptedKey:      encAtt.EncryptedMessageKey,
			EncryptedData:     encAtt.EncryptedBody,
			EncryptedMetadata: encAtt.EncryptedSubject,
			SizeBytes:         sizeBytes,
		})
	}

	receiptJSON, err := buildEnclaveReceipt(p, rawMessage, encrypted, from, spfResult, dkimResult, dmarcResult, spamScore, folderAssignment)
	if err != nil {
		return err
	}

	members, err := p.groupStore.ListMembers(ctx, group.GroupID)
	if err != nil {
		return fmt.Errorf("list group members: %w", err)
	}

	// Ingestion dedup: resolve the sender and any direct To/Cc recipients of
	// this same delivery to user IDs; those members are skipped in the fan-out
	// so nobody stores the same message twice. The sender's record of their own
	// post is their Sent copy; a direct copy supersedes a list copy.
	skipMember := make(map[uuid.UUID]bool, len(directRecipients)+1)
	for _, addr := range append([]string{from}, directRecipients...) {
		if strings.TrimSpace(addr) == "" {
			continue
		}
		if u, uerr := p.authStore.GetUserByAddress(ctx, addr); uerr == nil && u != nil {
			skipMember[u.UserID] = true
		}
	}

	// Serialize the shared encrypted payload once; reuse for every member.
	base := InboundMessage{
		GroupID:             group.GroupID.String(),
		GroupKeyEpoch:       group.KeyEpoch,
		EphemeralPubkey:     encrypted.EphemeralPubkey,
		EncryptedMessageKey: encrypted.EncryptedMessageKey,
		EncryptedBody:       encrypted.EncryptedBody,
		EncryptedSubject:    encrypted.EncryptedSubject,
		EncryptedHeaders:    encrypted.EncryptedHeaders,
		SPFResult:           spfResult,
		DKIMResult:          dkimResult,
		DMARCResult:         dmarcResult,
		Receipt:             receiptJSON,
		FolderAssignment:    folderAssignment,
		ReceivedAt:          time.Now().UTC(),
		InReplyTo:           parsed.InReplyTo,
		References:          parsed.References,
		MessageID:           parsed.MessageID,
		EncryptionType:      "received",
		EncryptedAttachments: encryptedAtts,
		EncryptedRawBody:     encryptedRaw.EncryptedBody,
		EncryptedRawKey:      encryptedRaw.EncryptedMessageKey,
		RawEphemeralPubkey:   encryptedRaw.EphemeralPubkey,
		RawBlobFormat:        rawBlobFormat,
		EncryptedRawMeta:     encryptedRaw.EncryptedMeta,
	}

	tenant := group.TenantID.String()
	natsSubject := fmt.Sprintf("mail.inbound.%s", tenant)
	var delivered, skipped int
	for _, m := range members {
		// joined_at_epoch filter: a member only receives mail from epochs at or
		// after they joined (no pre-join history). Current members satisfy this.
		if m.JoinedAtEpoch > group.KeyEpoch {
			continue
		}
		// Ingestion dedup (see skipMember above).
		if skipMember[m.MemberUserID] {
			skipped++
			continue
		}
		msg := base // shallow copy; byte slices are shared (read-only after this point)
		msg.TenantID = tenant
		msg.UserID = m.MemberUserID.String()
		data, mErr := json.Marshal(msg)
		if mErr != nil {
			slog.Error("marshal group inbound message", "group_id", group.GroupID, "member", m.MemberUserID, "error", mErr)
			continue
		}
		if pErr := p.queue.Publish(ctx, natsSubject, data); pErr != nil {
			slog.Error("publish group message", "group_id", group.GroupID, "member", m.MemberUserID, "error", pErr)
			continue
		}
		delivered++
	}

	slog.Info("group message processed", "group_id", group.GroupID, "members", len(members), "delivered", delivered, "skipped", skipped, "spf", spfResult, "dkim", dkimResult, "dmarc", dmarcResult)
	// delivered == 0 is only an error when nobody was deliberately skipped —
	// e.g. the sender posting to a group where they're the sole member is fine
	// (their Sent copy IS the delivery).
	if delivered == 0 && skipped == 0 {
		return fmt.Errorf("group %s: no members received the message", group.GroupID)
	}
	return nil
}

// stampGroupListHeaders adds mailing-list headers to a group fan-out: List-Id
// (RFC 2919), List-Post (RFC 2369), and Reply-To — the latter only when the
// sender didn't set their own, so an explicit sender Reply-To still wins.
//
// The headers go in two places: the parsed header map (which becomes the
// E2E-encrypted header blob bmail clients read) and PREPENDED to the raw
// message bytes (which external clients see when the raw .eml is exported).
// Prepending leaves every original header and the body byte-identical, so the
// sender's DKIM signature over its signed fields stays verifiable.
//
// Returns the (possibly new) raw bytes and whether anything was added.
func stampGroupListHeaders(headers map[string][]string, rawMessage []byte, groupAddress string) ([]byte, bool) {
	var added []string

	if len(headers["Reply-To"]) == 0 {
		headers["Reply-To"] = []string{groupAddress}
		added = append(added, "Reply-To: "+groupAddress)
	}

	// List-Id (RFC 2919): the group address with '@' folded to '.', in angle
	// brackets — e.g. <team.example.com>.
	listID := "<" + strings.Replace(groupAddress, "@", ".", 1) + ">"
	headers["List-Id"] = []string{listID}
	added = append(added, "List-Id: "+listID)

	listPost := "<mailto:" + groupAddress + ">"
	headers["List-Post"] = []string{listPost}
	added = append(added, "List-Post: "+listPost)

	var b bytes.Buffer
	b.Grow(len(rawMessage) + 160)
	for _, h := range added {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.Write(rawMessage)
	return b.Bytes(), true
}

// parsedMessage holds the result of parsing a raw RFC 5322 message.
type parsedMessage struct {
	Subject     string
	Body        []byte
	InReplyTo   string
	References  string
	MessageID   string
	Headers     map[string][]string
	Attachments []InboundAttachment
	CalendarICS []byte // raw text/calendar content (if present)
}

// parseMessageFull extracts subject, body, attachments, and threading headers.
func parseMessageFull(rawMessage []byte) (*parsedMessage, error) {
	subject, body, attachments, calendarICS, err := parseMessage(rawMessage)
	if err != nil {
		return nil, err
	}
	result := &parsedMessage{Subject: subject, Body: body, Attachments: attachments, CalendarICS: calendarICS}

	// Extract threading headers from raw message.
	reader, err := gomail.CreateReader(bytes.NewReader(rawMessage))
	if err == nil {
		defer reader.Close()
		header := reader.Header

		result.InReplyTo = header.Get("In-Reply-To")
		result.References = header.Get("References")
		result.MessageID = header.Get("Message-Id")

		// Extract all headers into the map.
		result.Headers = make(map[string][]string)
		fields := header.Fields()
		for fields.Next() {
			key := fields.Key()
			val := fields.Value()
			result.Headers[key] = append(result.Headers[key], val)
		}
	}
	return result, nil
}

// parseMessage extracts the subject, body, attachments, and any text/calendar
// content from a raw RFC 5322 message.
func parseMessage(rawMessage []byte) (subject string, body []byte, attachments []InboundAttachment, calendarICS []byte, err error) {
	reader, err := gomail.CreateReader(bytes.NewReader(rawMessage))
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("create mail reader: %w", err)
	}
	defer reader.Close()

	// Extract subject from headers.
	header := reader.Header
	subject, subjectErr := header.Subject()
	if subjectErr != nil {
		slog.Debug("failed to parse subject header, using empty", "error", subjectErr)
	}

	// Read body parts. Prefer HTML over plain text when both are present
	// (multipart/alternative). This avoids concatenating both parts into
	// an unreadable mess.
	var textBody, htmlBody []byte
	const maxAttachmentSize = 25 * 1024 * 1024 // 25MB per attachment

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			partBody, readErr := io.ReadAll(io.LimitReader(part.Body, 10*1024*1024))
			if readErr != nil {
				continue
			}
			if ct == "text/html" {
				htmlBody = partBody
			} else if ct == "text/plain" {
				textBody = partBody
			} else if strings.HasPrefix(ct, "text/calendar") {
				calendarICS = partBody
			} else if strings.HasPrefix(ct, "image/") {
				// Inline image — store as attachment with Content-ID for client-side cid: resolution.
				cid := strings.Trim(h.Get("Content-Id"), "<>")
				filename := "inline-image"
				if cid != "" {
					filename = cid
				}
				attachments = append(attachments, InboundAttachment{
					Filename:    filename,
					ContentType: ct,
					ContentID:   cid,
					Data:        partBody,
				})
			}
		case *gomail.AttachmentHeader:
			filename, _ := h.Filename()
			ct, _, _ := h.ContentType()
			cid := strings.Trim(h.Get("Content-Id"), "<>")
			if filename == "" {
				if cid != "" && strings.HasPrefix(ct, "image/") {
					filename = cid
				} else {
					filename = "attachment"
				}
			}
			if ct == "" {
				ct = "application/octet-stream"
			}
			data, readErr := io.ReadAll(io.LimitReader(part.Body, maxAttachmentSize))
			if readErr != nil {
				slog.Warn("failed to read attachment", "filename", filename, "error", readErr)
				continue
			}
			// Capture text/calendar attachments (.ics files) for calendar processing.
			if calendarICS == nil && (strings.HasPrefix(ct, "text/calendar") || strings.HasSuffix(strings.ToLower(filename), ".ics")) {
				calendarICS = data
			}
			attachments = append(attachments, InboundAttachment{
				Filename:    filename,
				ContentType: ct,
				ContentID:   cid,
				Data:        data,
			})
		}
	}

	if htmlBody != nil {
		body = htmlBody
	} else if textBody != nil {
		body = textBody
	} else {
		// Fallback: read raw body after headers.
		body = extractRawBody(rawMessage)
	}

	return subject, body, attachments, calendarICS, nil
}

// extractRawBody extracts the body from a raw message by finding the blank line
// that separates headers from body.
func extractRawBody(raw []byte) []byte {
	// Find the first blank line (CRLFCRLF or LFLF).
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[idx+2:]
	}
	return raw
}


// rawMetaPart is a single MIME part in the metadata index.
type rawMetaPart struct {
	ContentType      string   `json:"content_type"`
	Charset          string   `json:"charset,omitempty"`
	TransferEncoding string   `json:"transfer_encoding,omitempty"`
	Disposition      string   `json:"disposition,omitempty"`
	Filename         string   `json:"filename,omitempty"`
	Start            int64    `json:"start"`
	Body             int64    `json:"body"`
	End              int64    `json:"end"`
	Children         []int    `json:"children,omitempty"`
}

// rawMetaIndex is the full MIME structure metadata.
type rawMetaIndex struct {
	Parts   []rawMetaPart         `json:"parts"`
	Headers map[string][]string   `json:"headers"`
}

// buildRawMeta parses the raw RFC 5322 message and returns JSON metadata
// describing the MIME structure with byte offsets for each part.
func buildRawMeta(rawMessage []byte) []byte {
	root, err := mailparse.Parse(bytes.NewReader(rawMessage))
	if err != nil {
		// Parsing failed — return minimal metadata with just the root.
		meta := rawMetaIndex{
			Parts: []rawMetaPart{{
				ContentType: "application/octet-stream",
				Start:       0,
				Body:        0,
				End:         int64(len(rawMessage)),
			}},
		}
		data, _ := json.Marshal(meta)
		return data
	}

	var index rawMetaIndex
	index.Headers = map[string][]string(root.Header)

	// Flatten the MIME tree into an indexed array.
	var flattenParts func(p *mailparse.Part) int
	flattenParts = func(p *mailparse.Part) int {
		idx := len(index.Parts)
		part := rawMetaPart{
			ContentType:      p.ContentType,
			Charset:          p.Charset,
			TransferEncoding: p.TransferEncoding,
			Disposition:      p.ContentDisposition,
			Filename:         p.Filename,
			Start:            p.StartPos,
			Body:             p.BodyPos,
			End:              p.EndPos,
		}
		index.Parts = append(index.Parts, part) // placeholder — will update children

		var childIndices []int
		for _, child := range p.Children {
			childIdx := flattenParts(child)
			childIndices = append(childIndices, childIdx)
		}
		if len(childIndices) > 0 {
			index.Parts[idx].Children = childIndices
		}
		return idx
	}
	flattenParts(root)

	data, _ := json.Marshal(index)
	return data
}

// base64Encode encodes bytes to standard base64.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// ── In-enclave post-receive logic ─────────────────────────────────

// ruleCondition / ruleAction mirror the JSON shape stored in
// rules.conditions_encrypted / rules.actions_encrypted. Despite the
// "_encrypted" suffix the columns hold base64-encoded JSON, not E2E
// ciphertext (rules need to be evaluated server-side). The same
// structs used to live in cmd/worker/main.go.
type ruleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ruleAction struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// inboundDecisions captures everything the post-receive logic decides
// about a freshly arrived message: where to file it, which labels to
// attach, whether to mark it read or starred, and (special case)
// whether to drop it on the floor entirely.
type inboundDecisions struct {
	Drop             bool        // a "delete" rule action — message is never persisted
	FolderAssignment string      // "inbox" or "junk" (block check / spam input)
	MoveFolderID     string      // rule-driven move target (overrides FolderAssignment for storage)
	LabelIDs         []string
	MarkRead         bool
	MarkStarred      bool
}

// applyPostReceive runs the per-recipient logic that the worker used to
// own — block check, auto-add contact, rule eval, and auto-reply
// trigger — entirely inside the SGX enclave so the cleartext sender
// never leaves the boundary. Mutates the decision struct in place.
//
// Stores wired via SetPostReceiveStores. When a particular store is
// nil that piece of work is skipped (back-compat for the smtp package
// integration tests that use the minimal pipeline constructor).
func (p *Pipeline) applyPostReceive(ctx context.Context, user *storage.User, fromAddr string, hasAttachments bool, sizeBytes int64, originalRFCMessageID string, decisions *inboundDecisions) {
	// 1. Blocked sender → silently route to junk.
	if p.blockStore != nil {
		blocked, err := p.blockStore.IsBlocked(ctx, user.UserID, fromAddr)
		if err != nil {
			slog.Warn("post-receive block check failed", "error", err)
		} else if blocked {
			decisions.FolderAssignment = "junk"
		}
	}

	// 2. Auto-add the sender to the recipient's contacts. Best effort —
	// failures are logged and ignored.
	if p.contactsStore != nil {
		if err := p.contactsStore.AutoAdd(ctx, user.UserID, user.TenantID, user.PublicKeyEncryption, user.PublicKeyKEM, fromAddr); err != nil {
			slog.Warn("post-receive auto-add contact failed", "error", err)
		}
	}

	// 3. Rule evaluation. Walks the user's enabled rules in priority
	// order, applies the first matching rule's actions to the decisions
	// struct, and stops. Content-based conditions (subject/body) are
	// skipped because the enclave still can't decrypt the body — those
	// are evaluated client-side as a fallback.
	if p.ruleStore != nil {
		p.evalRulesIntoDecisions(ctx, user, fromAddr, hasAttachments, sizeBytes, decisions)
		if decisions.Drop {
			return // skip auto-reply for messages that get deleted
		}
	}

	// 4. Auto-reply trigger.
	if p.autoReplyStore != nil {
		p.maybeSendAutoReply(ctx, user, fromAddr, originalRFCMessageID)
	}
}

// evalRulesIntoDecisions is the moved-from-worker rule engine, ported
// to mutate inboundDecisions instead of touching message rows directly.
// First matching rule wins (matching the legacy worker behaviour).
func (p *Pipeline) evalRulesIntoDecisions(ctx context.Context, user *storage.User, fromAddr string, hasAttachments bool, sizeBytes int64, decisions *inboundDecisions) {
	rules, err := p.ruleStore.ListRules(ctx, user.UserID, user.TenantID)
	if err != nil || len(rules) == 0 {
		return
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		conditions := decodeRuleJSON[ruleCondition](rule.ConditionsEncrypted)
		if len(conditions) == 0 {
			continue
		}
		allMatch := true
		hasServerCondition := false
		for _, c := range conditions {
			switch c.Field {
			case "from":
				hasServerCondition = true
				val := strings.ToLower(c.Value)
				from := strings.ToLower(fromAddr)
				switch c.Operator {
				case "contains":
					if !strings.Contains(from, val) {
						allMatch = false
					}
				case "equals":
					if from != val {
						allMatch = false
					}
				default:
					allMatch = false
				}
			case "has_attachment":
				hasServerCondition = true
				if !hasAttachments {
					allMatch = false
				}
			case "size_gt":
				hasServerCondition = true
				threshold, _ := strconv.ParseInt(c.Value, 10, 64)
				if sizeBytes <= threshold*1024 {
					allMatch = false
				}
			case "size_lt":
				hasServerCondition = true
				threshold, _ := strconv.ParseInt(c.Value, 10, 64)
				if sizeBytes >= threshold*1024 {
					allMatch = false
				}
			case "subject", "body", "to", "cc":
				// Content-based — server can't decrypt; client evaluates these.
				continue
			default:
				continue
			}
		}
		if !hasServerCondition || !allMatch {
			continue
		}

		actions := decodeRuleJSON[ruleAction](rule.ActionsEncrypted)
		for _, a := range actions {
			switch a.Type {
			case "move":
				decisions.MoveFolderID = a.Value
			case "label":
				decisions.LabelIDs = append(decisions.LabelIDs, a.Value)
			case "mark_read":
				decisions.MarkRead = true
			case "star":
				decisions.MarkStarred = true
			case "delete":
				decisions.Drop = true
			case "archive":
				if p.folderStore != nil {
					archive, err := p.folderStore.GetFolderByType(ctx, user.UserID, user.TenantID, storage.FolderArchive)
					if err == nil {
						decisions.MoveFolderID = archive.FolderID.String()
					}
				}
			}
		}
		slog.Info("rule_applied_in_pipeline", "rule_id", rule.RuleID, "user_id", user.UserID)
		return // first matching rule wins
	}
	_ = ctx // referenced unconditionally above; placate the linter if any branch is dropped
}

// decodeRuleJSON decodes the base64-encoded JSON the frontend stores in
// rules.conditions_encrypted / actions_encrypted. Returns nil on any
// parse error so callers can short-circuit cleanly.
func decodeRuleJSON[T any](raw []byte) []T {
	var out []T
	if err := json.Unmarshal(raw, &out); err == nil {
		return out
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(decoded, &out); err != nil {
		return nil
	}
	return out
}

// maybeSendAutoReply checks the recipient's auto-reply settings and,
// if enabled and not deduped, publishes an outbound message and stores
// a sent copy in the recipient's Sent folder (encrypted to their own
// pubkey so they can read it back like any normal sent mail).
func (p *Pipeline) maybeSendAutoReply(ctx context.Context, recipient *storage.User, senderAddress, originalMessageID string) {
	ar, err := p.autoReplyStore.GetAutoReply(ctx, recipient.UserID)
	if err != nil || ar == nil || !ar.Enabled || ar.Body == "" {
		return
	}
	now := time.Now()
	if ar.StartDate != nil && now.Before(*ar.StartDate) {
		return
	}
	if ar.EndDate != nil && now.After(ar.EndDate.Add(24*time.Hour)) {
		return
	}

	// Dedup using the in-DB table (replaces the worker's old Redis
	// dedup). Only proceed if this is the first auto-reply to this
	// sender within the TTL window.
	if p.autoReplyDedup != nil {
		senderBlind := storage.ComputeAddressBlindIndex(storage.BlindScopeMessageSender, recipient.UserID, senderAddress)
		ok, derr := p.autoReplyDedup.TryRecordAutoReply(ctx, recipient.UserID, recipient.TenantID, senderBlind, 24*time.Hour)
		if derr != nil {
			slog.Warn("auto reply dedup failed", "error", derr)
			return
		}
		if !ok {
			return // already sent within TTL
		}
	}

	replySubject := ar.Subject
	if replySubject == "" {
		replySubject = "Auto-reply"
	}
	msgDomain := "bmail.ag"
	if idx := strings.LastIndex(recipient.Address, "@"); idx >= 0 {
		msgDomain = recipient.Address[idx+1:]
	}
	rfcMsgID := fmt.Sprintf("<%s@%s>", uuid.New().String(), msgDomain)

	type outboundPayload struct {
		ToAddress        string `json:"to_address"`
		SenderAddress    string `json:"sender_address"`
		EncryptedBody    string `json:"encrypted_body"`
		EncryptedSubject string `json:"encrypted_subject"`
		TenantID         string `json:"tenant_id"`
		EncryptionType   string `json:"encryption_type"`
		RFCMessageID     string `json:"rfc_message_id"`
		InReplyTo        string `json:"in_reply_to,omitempty"`
		SenderUserID     string `json:"sender_user_id"`
	}
	payload := outboundPayload{
		ToAddress:        senderAddress,
		SenderAddress:    recipient.Address,
		EncryptedBody:    base64.StdEncoding.EncodeToString([]byte(ar.Body)),
		EncryptedSubject: base64.StdEncoding.EncodeToString([]byte(replySubject)),
		TenantID:         recipient.TenantID.String(),
		EncryptionType:   "plaintext",
		RFCMessageID:     rfcMsgID,
		InReplyTo:        originalMessageID,
		SenderUserID:     recipient.UserID.String(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("auto_reply_marshal", "error", err)
		return
	}
	natsSubject := fmt.Sprintf("mail.outbound.%s", recipient.TenantID)
	if err := p.queue.Publish(ctx, natsSubject, payloadBytes); err != nil {
		slog.Error("auto_reply_publish", "error", err)
		return
	}

	// Also store the auto-reply in the recipient's Sent folder,
	// encrypted to their own pubkey, so it shows up in the normal Sent
	// view. Best-effort — if anything fails the outbound reply still
	// got sent.
	if p.mailStore != nil && p.folderStore != nil {
		p.storeAutoReplySentCopy(ctx, recipient, senderAddress, ar.Subject, ar.Body, originalMessageID, rfcMsgID)
	}

	slog.Info("auto_reply_sent_from_enclave")
}

// storeAutoReplySentCopy writes the auto-reply into the recipient's
// Sent folder, encrypted to their own bmail public key. Mirrors the
// shape of a regular outbound bmail-to-bmail sent copy.
func (p *Pipeline) storeAutoReplySentCopy(ctx context.Context, recipient *storage.User, recipientAddr, subject, body, inReplyTo, rfcMsgID string) {
	pub, err := ecdh.X25519().NewPublicKey(recipient.PublicKeyEncryption)
	if err != nil {
		slog.Warn("auto reply sent copy: parse pubkey", "error", err)
		return
	}
	var recipientKEMEK *mlkem.EncapsulationKey768
	if len(recipient.PublicKeyKEM) > 0 {
		recipientKEMEK, err = crypto.MLKEMEncapsulationKeyFromBytes(recipient.PublicKeyKEM)
		if err != nil {
			slog.Warn("auto reply sent copy: parse KEM pubkey, falling back to classical", "error", err)
			recipientKEMEK = nil
		}
	}
	sentFolder, err := p.folderStore.GetFolderByType(ctx, recipient.UserID, recipient.TenantID, storage.FolderSent)
	if err != nil {
		slog.Warn("auto reply sent copy: lookup sent folder", "error", err)
		return
	}

	// Encrypt the auto-reply with a headers blob in the same envelope
	// so the sent copy displays correctly.
	headersJSON, _ := storage.BuildSimpleHeadersJSON(
		recipient.Address,
		[]string{recipientAddr},
		nil, nil, "", rfcMsgID, inReplyTo, "",
	)
	enc, err := crypto.EncryptMessageWithHeadersHybrid(pub, recipientKEMEK, []byte(subject), []byte(body), headersJSON)
	if err != nil {
		slog.Warn("auto reply sent copy: encrypt with headers", "error", err)
		return
	}

	msgID := uuid.New()
	inReplyToPtr := &inReplyTo
	if inReplyTo == "" {
		inReplyToPtr = nil
	}
	rfcMsgIDPtr := &rfcMsgID
	msg := &storage.Message{
		MessageID:           msgID,
		UserID:              recipient.UserID,
		TenantID:            recipient.TenantID,
		FolderID:            sentFolder.FolderID,
		EncryptedSubject:    enc.EncryptedSubject,
		EncryptedMessageKey: enc.EncryptedMessageKey,
		EphemeralPubkey:     enc.EphemeralPubkey,
		EncryptedHeaders:    enc.EncryptedHeaders,
		SenderBlindIndex:    storage.ComputeAddressBlindIndex(storage.BlindScopeMessageSender, recipient.UserID, recipient.Address),
		ReceivedAt:          time.Now().UTC(),
		SizeBytes:           int64(len(body)),
		IsRead:              true,
		KeyEpoch:            recipient.KeyEpoch,
		EncryptionType:      "bmail",
		InReplyTo:           inReplyToPtr,
		RFCMessageID:        rfcMsgIDPtr,
	}
	// Body blob: store inline encrypted body in messages.blob_ref by
	// reusing the EncryptedBody field via the existing blob path is
	// outside this helper; the auto-reply body is small and we keep it
	// in the same shape as legacy worker-side stored sent copies, which
	// also rely on the encrypted_body column populated below.
	msg.BlobRef = ""
	if err := p.mailStore.InsertMessage(ctx, msg); err != nil {
		slog.Warn("auto reply sent copy: insert message", "error", err)
		return
	}
}
