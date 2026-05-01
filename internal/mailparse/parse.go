package mailparse

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"net/textproto"
	"strings"
)

// lineReader reads lines while tracking the byte offset.
type lineReader struct {
	r   *bufio.Reader
	pos int64
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReader(r)}
}

// readLine reads a single line including its line ending (\n or \r\n).
// At EOF it may return data with io.EOF.
func (lr *lineReader) readLine() ([]byte, error) {
	line, err := lr.r.ReadBytes('\n')
	lr.pos += int64(len(line))
	return line, err
}

// Parse reads a MIME message from r and returns the parsed part tree.
// Only headers and byte offsets are stored; body data is not retained.
// Use the offsets with the original data source to extract body content.
func Parse(r io.Reader) (*Part, error) {
	lr := newLineReader(r)
	part, _, err := parsePart(lr, "")
	if err != nil && err != io.EOF {
		return part, err
	}
	return part, nil
}

// parsePart parses one MIME part. terminatingBoundary is the parent's
// boundary that ends this part (empty for the root). Returns the part,
// whether a closing boundary (--boundary--) was hit, and any error.
func parsePart(lr *lineReader, terminatingBoundary string) (*Part, bool, error) {
	part := &Part{
		StartPos: lr.pos,
		Charset:  "us-ascii",
	}

	// Parse headers until blank line or EOF.
	if err := parseHeaders(lr, part); err != nil && err != io.EOF {
		return part, false, err
	}
	part.BodyPos = lr.pos

	extractContentInfo(part)

	// If multipart, parse the children enclosed by our boundary.
	if part.Boundary != "" {
		if err := parseMultipartBody(lr, part); err != nil && err != io.EOF {
			return part, false, err
		}
	}

	// Read remaining content (epilogue / leaf body) until the
	// terminating boundary or EOF.
	closing, err := readUntilBoundary(lr, part, terminatingBoundary)
	return part, closing, err
}

// parseHeaders reads RFC 2822 headers, handling folded continuation lines.
// Headers are stored in a [textproto.MIMEHeader] with canonical key form.
func parseHeaders(lr *lineReader, part *Part) error {
	part.Header = make(textproto.MIMEHeader)

	var currentKey string
	var currentValue strings.Builder

	flush := func() {
		if currentKey != "" {
			part.Header.Add(currentKey, currentValue.String())
			currentKey = ""
			currentValue.Reset()
		}
	}

	for {
		line, err := lr.readLine()
		if len(line) == 0 && err != nil {
			flush()
			return err
		}

		trimmed := bytes.TrimRight(line, "\r\n")

		// Empty line = end of headers.
		if len(trimmed) == 0 {
			flush()
			return nil
		}

		// Continuation line (starts with SP or HTAB).
		if trimmed[0] == ' ' || trimmed[0] == '\t' {
			if currentKey != "" {
				currentValue.WriteByte(' ')
				currentValue.WriteString(strings.TrimSpace(string(trimmed)))
			}
			if err != nil {
				flush()
				return err
			}
			continue
		}

		// New header — flush the previous one.
		flush()

		colonIdx := bytes.IndexByte(trimmed, ':')
		if colonIdx < 0 {
			// Not a valid header line; skip it.
			if err != nil {
				return err
			}
			continue
		}

		currentKey = textproto.CanonicalMIMEHeaderKey(string(trimmed[:colonIdx]))
		currentValue.WriteString(strings.TrimSpace(string(trimmed[colonIdx+1:])))

		if err != nil {
			flush()
			return err
		}
	}
}

// extractContentInfo populates convenience fields from parsed headers.
func extractContentInfo(part *Part) {
	// Content-Type — use mime.ParseMediaType for RFC 2231 support.
	if ct := part.Header.Get("Content-Type"); ct != "" {
		mediaType, params, err := mime.ParseMediaType(ct)
		if err == nil {
			part.ContentType = mediaType
			part.Boundary = params["boundary"]
			if c := params["charset"]; c != "" {
				part.Charset = c
			}
			part.Name = DecodeHeader(params["name"])
		} else {
			// Fallback for malformed values.
			part.ContentType = strings.ToLower(strings.TrimSpace(ct))
		}
	} else {
		part.ContentType = "text/plain"
	}

	// Content-Transfer-Encoding
	if te := part.Header.Get("Content-Transfer-Encoding"); te != "" {
		part.TransferEncoding = strings.ToLower(strings.TrimSpace(te))
	} else if strings.HasPrefix(part.ContentType, "multipart/") {
		part.TransferEncoding = "8bit"
	} else {
		part.TransferEncoding = "7bit"
	}

	// Content-Disposition — mime.ParseMediaType also handles RFC 2183 values.
	if cd := part.Header.Get("Content-Disposition"); cd != "" {
		disposition, params, err := mime.ParseMediaType(cd)
		if err == nil {
			part.ContentDisposition = disposition
			part.Filename = DecodeHeader(params["filename"])
		} else {
			// Fallback: extract the disposition token.
			if i := strings.IndexByte(cd, ';'); i >= 0 {
				part.ContentDisposition = strings.ToLower(strings.TrimSpace(cd[:i]))
			} else {
				part.ContentDisposition = strings.ToLower(strings.TrimSpace(cd))
			}
		}
	}
}

// wordDecoder decodes RFC 2047 encoded words in header values.
var wordDecoder = new(mime.WordDecoder)

// DecodeHeader decodes RFC 2047 encoded words (e.g. =?UTF-8?B?...?=)
// in s, returning s unchanged if decoding fails or is not needed.
func DecodeHeader(s string) string {
	if s == "" {
		return s
	}
	decoded, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

// parseMultipartBody reads through the multipart body delimited by
// part.Boundary, creating child Parts.
func parseMultipartBody(lr *lineReader, part *Part) error {
	boundary := part.Boundary

	// Skip preamble until first opening boundary.
	for {
		line, err := lr.readLine()
		if len(line) > 0 {
			if isBound, isClose := checkBoundary(line, boundary); isBound {
				if isClose {
					return nil // immediate closing boundary, no children
				}
				break
			}
		}
		if err != nil {
			return err
		}
	}

	// Parse successive child parts.
	for {
		child, closing, err := parsePart(lr, boundary)
		if child != nil {
			part.Children = append(part.Children, child)
		}
		if closing || err != nil {
			return err
		}
	}
}

// readUntilBoundary consumes lines until the terminating boundary or EOF,
// setting part.EndPos. For the root part (boundary == ""), it reads to EOF.
// Returns whether the boundary found was a closing one (--boundary--).
func readUntilBoundary(lr *lineReader, part *Part, boundary string) (closing bool, err error) {
	if boundary == "" {
		// Root part: bulk-read to EOF.
		n, err := io.Copy(io.Discard, lr.r)
		lr.pos += n
		part.EndPos = lr.pos
		if err != nil {
			return false, err
		}
		return false, nil
	}

	// The CRLF immediately before a boundary delimiter belongs to the
	// delimiter, not the body (RFC 2046 §5.1.1). Track the previous
	// line's ending length so we can strip it when a boundary is found.
	var prevLineEndLen int64
	first := true

	for {
		lineStart := lr.pos
		line, err := lr.readLine()

		if len(line) == 0 && err != nil {
			part.EndPos = lr.pos
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}

		if isBound, isClose := checkBoundary(line, boundary); isBound {
			if first {
				part.EndPos = lineStart
			} else {
				part.EndPos = lineStart - prevLineEndLen
			}
			return isClose, nil
		}

		first = false
		prevLineEndLen = int64(lineEndingLen(line))

		if err != nil {
			part.EndPos = lr.pos
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}
	}
}

// checkBoundary reports whether line is a MIME boundary for the given
// boundary string. It also reports whether it is a closing boundary.
func checkBoundary(line []byte, boundary string) (isBoundary, isClosing bool) {
	// Per RFC 2046 a boundary line is:  "--" boundary [lwsp] CRLF
	// A closing boundary line is:       "--" boundary "--" [lwsp] CRLF
	trimmed := bytes.TrimRight(line, " \t\r\n")
	if len(trimmed) < 2+len(boundary) || trimmed[0] != '-' || trimmed[1] != '-' {
		return false, false
	}
	if string(trimmed[2:2+len(boundary)]) != boundary {
		return false, false
	}
	rest := trimmed[2+len(boundary):]
	if len(rest) == 0 {
		return true, false
	}
	if len(rest) == 2 && rest[0] == '-' && rest[1] == '-' {
		return true, true
	}
	return false, false
}

// lineEndingLen returns 2 for \r\n, 1 for \n, or 0 for no line ending.
func lineEndingLen(line []byte) int {
	n := len(line)
	if n >= 1 && line[n-1] == '\n' {
		if n >= 2 && line[n-2] == '\r' {
			return 2
		}
		return 1
	}
	return 0
}
