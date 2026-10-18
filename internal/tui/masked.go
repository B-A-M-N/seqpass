// masked.go is part of the trusted intake TUI (package tui): the hidden-field
// decoder for the operator's own terminal.

package tui

import (
	"errors"
)

// Errors a hidden field can end with. They are sentinels so callers and tests
// can distinguish "the operator cancelled" from "the terminal went away".
var (
	ErrCancelled   = errors.New("input cancelled")
	ErrTooLarge    = errors.New("value too large")
	ErrInterrupted = errors.New("interrupted")
)

// maxMaskedLen bounds one hidden field. The relay path rejects oversized
// payloads anyway; this stops a hostile paste from growing memory without
// bound before that rejection happens.
const maxMaskedLen = 64 * 1024

// maskedInput decodes one hidden field from a raw terminal byte stream.
//
// It is separated from the terminal I/O because its behavior is security
// relevant and must be testable without a terminal. Two cases in particular:
//
//   - An escape sequence (arrow key, function key, mouse report) arrives as
//     ESC plus following bytes. Those bytes are not secret material, so the
//     sequence is consumed and discarded. Without this, pressing Up while
//     typing a credential appends "[A" to the value.
//
//   - A terminal with bracketed paste enabled wraps pasted text in
//     ESC [ 2 0 0 ~ ... ESC [ 2 0 1 ~. Those markers are protocol, not
//     content, so they must not be spliced into the secret. Inside a paste
//     the content is taken literally, which also means a newline in the
//     pasted text does not submit a truncated value and strand the rest of
//     the paste in the main key loop. The paste ends the field only when the
//     operator presses Enter afterwards.
//
// The zero value is ready to use. feed consumes one byte and reports whether
// the field is complete.
type maskedInput struct {
	buf []byte

	paste  bool
	esc    bool
	escBuf []byte

	done bool
	err  error
}

// maxEscapeLen bounds one escape sequence. A well-formed sequence is short;
// anything longer is malformed or hostile and is abandoned rather than
// buffered.
const maxEscapeLen = 32

// feed consumes one byte and reports whether the field is complete.
func (m *maskedInput) feed(c byte) bool {
	if m.done {
		return true
	}
	// An escape sequence is parsed even inside a paste, because the paste
	// terminator is itself an escape sequence.
	if m.esc {
		m.feedEscape(c)
		return m.done
	}
	if c == 0x1b {
		m.esc = true
		m.escBuf = m.escBuf[:0]
		return false
	}
	return m.handleContent(c)
}

// handleContent processes one byte that is not (yet known to be) part of an
// escape sequence.
func (m *maskedInput) handleContent(c byte) bool {
	switch {
	case m.paste:
		m.feedPaste(c)
		return m.done
	case c == '\n' || c == '\r':
		m.done = true
		return true
	case c == 0x03 || c == 0x04: // Ctrl+C / Ctrl+D
		m.err = ErrCancelled
		m.done = true
		return true
	case c == 0x7f || c == 0x08: // backspace
		m.backspace()
		return false
	case c < 32:
		// Other control bytes are not secret material.
		return false
	default:
		return m.append(c)
	}
}

func (m *maskedInput) feedEscape(c byte) {
	m.escBuf = append(m.escBuf, c)
	if len(m.escBuf) == 1 {
		// CSI (ESC [) and SS3 (ESC O) introduce multi-byte sequences.
		if c == '[' || c == 'O' {
			return
		}
		// Anything else is ambiguous between an Alt chord (ESC + key) and a
		// bare Escape followed by a separate keypress. There is no way to
		// tell them apart from the byte stream alone, and a hidden field
		// must not silently drop a character the operator typed, so the
		// byte is kept as content and only the Escape is discarded.
		m.esc = false
		m.escBuf = m.escBuf[:0]
		m.handleContent(c)
		return
	}
	if c >= 0x40 && c <= 0x7e {
		// Final byte: the sequence is complete.
		m.esc = false
		switch string(m.escBuf) {
		case "[200~":
			m.paste = true
		case "[201~":
			m.paste = false
			// A line copied out of an editor ends with its newline; keeping
			// it would corrupt the value the operator believes they pasted.
			// Multi-line pastes keep their interior newlines, so only the
			// trailing run is removed.
			m.trimPastedTrailingNewlines()
		}
		return
	}
	if len(m.escBuf) > maxEscapeLen {
		// Malformed or hostile: abandon it instead of growing without bound.
		m.esc = false
		m.escBuf = m.escBuf[:0]
	}
}

func (m *maskedInput) feedPaste(c byte) {
	switch {
	case c == '\r':
		// CRLF normalization: the LF that follows is the real newline.
		return
	case c == 0x03 || c == 0x04:
		m.err = ErrCancelled
		m.done = true
		return
	case c == '\n' || c >= 32:
		m.append(c)
	default:
		// Other control bytes inside a paste are not content.
	}
}

// append adds one byte, or ends the field if the value would be too large.
func (m *maskedInput) append(c byte) bool {
	if len(m.buf) >= maxMaskedLen {
		m.err = ErrTooLarge
		m.done = true
		return true
	}
	m.buf = append(m.buf, c)
	return false
}

// backspace removes the last rune, not the last byte, so deleting into a
// multi-byte character cannot leave an invalid tail in the secret.
func (m *maskedInput) backspace() {
	if len(m.buf) == 0 {
		return
	}
	i := len(m.buf) - 1
	for i > 0 && m.buf[i]&0xC0 == 0x80 {
		i--
	}
	m.buf = m.buf[:i]
}

func (m *maskedInput) trimPastedTrailingNewlines() {
	n := len(m.buf)
	for n > 0 && m.buf[n-1] == '\n' {
		n--
	}
	m.buf = m.buf[:n]
}

// feedAll drives a byte slice through the decoder, for tests and for any
// caller that already has the bytes in hand.
func (m *maskedInput) feedAll(data []byte) bool {
	for _, c := range data {
		if m.feed(c) {
			return true
		}
	}
	return m.done
}

// value returns the decoded field. It is the caller's buffer to clear.
func (m *maskedInput) value() []byte { return m.buf }
