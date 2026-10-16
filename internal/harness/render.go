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
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteRune(r)
		case unicode.IsControl(r):
			return "", fmt.Errorf("untrusted annotation contains escape/control data")
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// TrustedRequestView is the only structure permitted to initiate a
// protected-input UI action. Hosts must construct it from broker state,
// never by parsing assistant/tool text.
type TrustedRequestView struct {
	RequestID         string
	DataKind          string
	DestinationName   string
	Endpoint          string
	ExpiresAt         string
	Mode              SecureInputMode
	Assurance         string
	TrustedHostRender bool
	UntrustedPurpose  string
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
		RequestID:         review.RequestID,
		DataKind:          review.DataKind,
		DestinationName:   review.DestinationName,
		Endpoint:          review.Endpoint,
		ExpiresAt:         review.ExpiresAt.UTC().Format(time.RFC3339),
		Mode:              review.Mode,
		Assurance:         review.Assurance,
		TrustedHostRender: true,
		UntrustedPurpose:  purpose,
	}, nil
}

// CanInitiateProtectedInput is the explicit gate for opening a protected
// input mode. It requires the broker-provided render marker, an active
// input transport, and verified input mode; model text can never satisfy it.
func (v TrustedRequestView) CanInitiateProtectedInput() bool {
	return v.TrustedHostRender && v.RequestID != "" &&
		(v.Mode == InputExternalTTY || v.Mode == InputHostNative || v.Mode == InputURL)
}
