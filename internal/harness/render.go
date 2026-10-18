package harness

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// MaxUntrustedAnnotation bounds agent-supplied prose in a trusted host
// surface. This is a defense-in-depth UI contract, in addition to the
// broker's admission bound.
const MaxUntrustedAnnotation = 500

// SanitizeAnnotation rejects control/ANSI sequences and bounds length.
// It never attempts to decide whether prose is trustworthy; callers must
// retain the UntrustedAnnotation marker.
func SanitizeAnnotation(s string) (string, error) {
	if len(s) > MaxUntrustedAnnotation {
		return "", fmt.Errorf("untrusted annotation too long")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == 127, r == '\x1b':
			return "", fmt.Errorf("untrusted annotation contains escape/control data")
		case r == '\n' || r == '\t':
			b.WriteRune('\u2423') // visible open-box boundary for layout-affecting whitespace
		case r == '\r':
			return "", fmt.Errorf("untrusted annotation contains carriage return")
		case unicode.IsControl(r) || isBidiControl(r):
			return "", fmt.Errorf("untrusted annotation contains escape/control data")
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

func isBidiControl(r rune) bool {
	switch r {
	case '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	}
	return false
}

// TrustedRequestView is the only structure permitted to initiate a
// protected-input UI action. Hosts must construct it from broker state,
// never by parsing assistant/tool text.
type TrustedRequestView struct {
	RequestID           string
	RequestRevision     uint64
	DataKind            string
	DestinationID       string
	DestinationName     string
	Endpoint            string
	DestinationDigest   string
	DestinationRevision int
	Consumption         string
	MaxDeliveries       uint32
	ExpiresAt           string
	Mode                SecureInputMode
	Assurance           string
	AgentPrincipal      string
	HumanPrincipal      string
	SessionID           string
	ThreadID            string
	TrustedHostRender   bool
	UntrustedPurpose    string
}

// FromReview converts a broker-supplied review DTO. Purpose failure fails
// the trusted view rather than falling back to raw text.
func TrustedRequestFromReview(review TrustedReviewDTO) (TrustedRequestView, error) {
	if !review.TrustedHostRender || review.PurposeUntrusted == false && review.Purpose != "" {
		return TrustedRequestView{}, fmt.Errorf("review is not marked as a trusted host render")
	}
	purpose := review.Purpose
	if purpose != "" {
		clean, err := SanitizeAnnotation(purpose)
		if err != nil {
			return TrustedRequestView{}, err
		}
		purpose = clean
	}
	return TrustedRequestView{
		RequestID:           review.RequestID,
		RequestRevision:     review.RequestRevision,
		DataKind:            review.DataKind,
		DestinationID:       review.DestinationID,
		DestinationName:     review.DestinationName,
		Endpoint:            review.Endpoint,
		DestinationDigest:   review.DestinationDigest,
		DestinationRevision: review.DestinationRevision,
		Consumption:         review.Consumption,
		MaxDeliveries:       review.MaxDeliveries,
		ExpiresAt:           review.ExpiresAt.UTC().Format(time.RFC3339),
		Mode:                review.Mode,
		Assurance:           review.Assurance,
		AgentPrincipal:      review.AgentPrincipal,
		HumanPrincipal:      review.HumanPrincipal,
		SessionID:           review.SessionID,
		ThreadID:            review.ThreadID,
		TrustedHostRender:   true,
		UntrustedPurpose:    purpose,
	}, nil
}

// CanInitiateProtectedInput is the explicit gate for opening a protected
// input mode. It requires the broker-provided render marker, an active
// input transport, and verified input mode; model text can never satisfy it.
func (v TrustedRequestView) CanInitiateProtectedInput() bool {
	return v.TrustedHostRender && v.RequestID != "" && v.RequestRevision != 0 &&
		v.DestinationID != "" && v.DestinationDigest != "" && v.DestinationRevision != 0 &&
		v.Consumption != "" && v.AgentPrincipal != "" && v.HumanPrincipal != "" &&
		v.SessionID != "" &&
		(v.Mode == InputExternalTTY || v.Mode == InputHostNative || v.Mode == InputURL)
}
