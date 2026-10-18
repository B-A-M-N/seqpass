package tui

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// decode drives a whole byte stream through the decoder.
func decode(data []byte) ([]byte, error) {
	m := &maskedInput{}
	m.feedAll(data)
	if m.err != nil {
		return nil, m.err
	}
	if !m.done {
		return nil, ErrCancelled
	}
	return m.buf, nil
}

func mustDecode(t *testing.T, data []byte) []byte {
	t.Helper()
	v, err := decode(data)
	if err != nil {
		t.Fatalf("decode(%q): %v", data, err)
	}
	return v
}

func TestMaskedInputPlainValue(t *testing.T) {
	if got := mustDecode(t, []byte("hunter2\n")); !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("value = %q", got)
	}
	// Carriage return terminates the same as newline (terminals send one or
	// the other depending on icrnl).
	if got := mustDecode(t, []byte("hunter2\r")); !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("value = %q", got)
	}
	// Spaces are content: a credential may contain them.
	if got := mustDecode(t, []byte("a b c\n")); !bytes.Equal(got, []byte("a b c")) {
		t.Fatalf("value = %q", got)
	}
}

// The defect this state machine exists for: a bracketed-paste terminal must
// not splice the protocol markers into the secret.
func TestMaskedInputBracketedPasteMarkersAreNotContent(t *testing.T) {
	const secret = "s3cr3t-value-2468"
	in := []byte("\x1b[200~" + secret + "\x1b[201~" + "\r")
	if got := mustDecode(t, in); !bytes.Equal(got, []byte(secret)) {
		t.Fatalf("bracketed paste value = %q, want %q", got, secret)
	}
}

// Copying one line out of an editor produces a trailing newline inside the
// paste. It is not part of the value.
func TestMaskedInputBracketedPasteDropsTrailingNewline(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("\x1b[200~" + "tok\n" + "\x1b[201~\r"),
		[]byte("\x1b[200~" + "tok\r\n" + "\x1b[201~\r"),
	} {
		if got := mustDecode(t, in); !bytes.Equal(got, []byte("tok")) {
			t.Fatalf("paste %q decoded to %q", in, got)
		}
	}
}

// A newline inside a paste must not submit a truncated value, because the
// remainder of the paste would then be interpreted as inbox keys.
func TestMaskedInputBracketedPasteNewlineDoesNotSubmit(t *testing.T) {
	in := []byte("\x1b[200~line1\nline2\x1b[201~\r")
	if got := mustDecode(t, in); !bytes.Equal(got, []byte("line1\nline2")) {
		t.Fatalf("multi-line paste decoded to %q", got)
	}
	// A multi-line paste keeps its interior newlines but loses the trailing
	// run, which is what copying a block out of an editor appends.
	in = []byte("\x1b[200~line1\nline2\n\n\x1b[201~\r")
	if got := mustDecode(t, in); !bytes.Equal(got, []byte("line1\nline2")) {
		t.Fatalf("block paste decoded to %q", got)
	}
	// A value that genuinely ends in newlines cannot be distinguished from
	// editor copy behavior, so the trim is total at paste end.
	in = []byte("\x1b[200~tok\n\n\x1b[201~\r")
	if got := mustDecode(t, in); !bytes.Equal(got, []byte("tok")) {
		t.Fatalf("paste decoded to %q", got)
	}
}

func TestMaskedInputEscapeSequencesAreDiscarded(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"up arrow between characters", []byte("ab\x1b[A" + "cd\n"), "abcd"},
		{"left arrow", []byte("\x1b[D" + "x\n"), "x"},
		{"home key", []byte("\x1b[H" + "x\n"), "x"},
		{"function key", []byte("\x1b[11~" + "x\n"), "x"},
		{"ss3 sequence", []byte("\x1bOA" + "x\n"), "x"},
		// An Alt chord and a bare Escape are indistinguishable from the byte
		// stream alone, so only the Escape is dropped and the byte is kept:
		// a hidden field must not silently lose a typed character.
		{"alt chord keeps the byte", []byte("\x1bq" + "x\n"), "qx"},
		{"bare escape keeps the next byte", []byte("\x1b" + "x\n"), "x"},
	}
	for _, tc := range cases {
		if got := mustDecode(t, tc.in); !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("%s: decoded %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A malformed escape sequence must be abandoned rather than buffered without
// bound, and the decoder must still terminate and keep the real content.
func TestMaskedInputOverlongEscapeIsAbandoned(t *testing.T) {
	in := append([]byte("\x1b["), bytes.Repeat([]byte("1"), maxEscapeLen+10)...)
	in = append(in, []byte("x\n")...)
	got, err := decode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("x")) {
		t.Fatalf("value = %q, want it to end with the real content", got)
	}
	if len(got) > maxEscapeLen {
		t.Fatalf("decoder buffered the malformed sequence: %d bytes", len(got))
	}
}

func TestMaskedInputBackspace(t *testing.T) {
	if got := mustDecode(t, []byte("abcd\x7f\x7f\n")); !bytes.Equal(got, []byte("ab")) {
		t.Fatalf("backspace value = %q", got)
	}
	if got := mustDecode(t, []byte("ab\x7f\x7f\x7f\x7f\n")); !bytes.Equal(got, []byte("")) {
		t.Fatalf("over-backspace value = %q", got)
	}
	// DEL 0x7f and BS 0x08 are both backspace.
	if got := mustDecode(t, []byte("abc\x08\n")); !bytes.Equal(got, []byte("ab")) {
		t.Fatalf("0x08 value = %q", got)
	}
	// A multi-byte rune is removed whole, never half.
	if got := mustDecode(t, []byte("aé\x7f\n")); !bytes.Equal(got, []byte("a")) {
		t.Fatalf("utf8 backspace value = %q", got)
	}
	// And a multi-byte rune survives intact.
	if got := mustDecode(t, []byte("aé\n")); !bytes.Equal(got, []byte("aé")) {
		t.Fatalf("utf8 value = %q", got)
	}
}

func TestMaskedInputAborts(t *testing.T) {
	for _, c := range []byte{0x03, 0x04} {
		if _, err := decode([]byte("partial" + string(c))); !errors.Is(err, ErrCancelled) {
			t.Fatalf("byte %#x: err = %v, want ErrCancelled", c, err)
		}
	}
	// An abort inside a paste also aborts, and never submits.
	if _, err := decode([]byte("\x1b[200~partial\x03")); !errors.Is(err, ErrCancelled) {
		t.Fatalf("ctrl+c inside paste: err = %v", err)
	}
}

func TestMaskedInputSizeCap(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxMaskedLen+1)
	big = append(big, '\n')
	if _, err := decode(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Exactly at the cap is accepted.
	atCap := append(bytes.Repeat([]byte("a"), maxMaskedLen), '\n')
	if got := mustDecode(t, atCap); len(got) != maxMaskedLen {
		t.Fatalf("at-cap length = %d", len(got))
	}
}

// Control bytes other than the ones with a defined meaning are not content:
// a stray Tab or Bell must not become part of a credential.
func TestMaskedInputIgnoresOtherControlBytes(t *testing.T) {
	if got := mustDecode(t, []byte("a\tb\x07c\n")); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("value = %q", got)
	}
}

func TestNeutralizeStripsLayoutWeapons(t *testing.T) {
	cases := map[string]string{
		"plain":                 "plain",
		"esc: \x1b[31mred":      "esc: \uFFFD[31mred",
		"bell\x07":              "bell\uFFFD",
		"bidi \u202Ereversed":   "bidi \uFFFDreversed",
		"zero-width \u200Bhere": "zero-width \uFFFDhere",
	}
	for in, want := range cases {
		if got := neutralize(in); got != want {
			t.Errorf("neutralize(%q) = %q, want %q", in, got, want)
		}
	}
	// An empty field renders empty (only the agent-supplied purpose gets a
	// placeholder, because "no reason given" is meaningful there).
	if got := neutralize(""); got != "" {
		t.Fatalf("neutralize(\"\") = %q", got)
	}
	if got := sanitize("   "); got != "(no reason given)" {
		t.Fatalf("sanitize(blank) = %q", got)
	}
	if got := sanitize("go\x1b[2Jhome"); got != "go\uFFFD[2Jhome" {
		t.Fatalf("sanitize(escape) = %q", got)
	}
}

func TestExpiresLabel(t *testing.T) {
	if got := expiresLabel(time.Now().Add(90 * time.Second).Format(time.RFC3339Nano)); got != "in 1m30s" {
		t.Fatalf("label = %q", got)
	}
	if got := expiresLabel(time.Now().Add(-time.Second).Format(time.RFC3339Nano)); got != "EXPIRED" {
		t.Fatalf("expired label = %q", got)
	}
	// An unparseable value is shown neutralized rather than dropped.
	if got := expiresLabel("not-a-time\x1b[2J"); got != "not-a-time\uFFFD[2J" {
		t.Fatalf("fallback label = %q", got)
	}
}

func TestUintFieldRejectsBadInput(t *testing.T) {
	if v, ok := uintField(float64(7)); !ok || v != 7 {
		t.Fatalf("valid number = %d, %v", v, ok)
	}
	for _, bad := range []interface{}{nil, "7", true, -1.0, 1e18} {
		if _, ok := uintField(bad); ok {
			t.Errorf("uintField(%v) accepted", bad)
		}
	}
}

// Polling must not erase the line that tells the operator what just happened.
func TestStickyStatusSurvivesPolling(t *testing.T) {
	s := &session{}
	s.setSticky("authorized req-1 op=op-9")
	s.setTransient("0 pending — auto-refresh 2s")
	if s.status != "authorized req-1 op=op-9" {
		t.Fatalf("poll overwrote a sticky status: %q", s.status)
	}
	// Once the sticky window passes, the ambient status takes over again.
	s.stickyUntil = time.Now().Add(-time.Second)
	s.setTransient("0 pending — auto-refresh 2s")
	if s.status != "0 pending — auto-refresh 2s" {
		t.Fatalf("ambient status did not resume: %q", s.status)
	}
}

func TestSigNumFallsBackToSIGINT(t *testing.T) {
	if got := sigNum(nil); got.String() != "interrupt" {
		t.Fatalf("sigNum(nil) = %v", got)
	}
}
