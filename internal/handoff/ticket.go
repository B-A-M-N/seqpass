// Package handoff implements opaque, short-lived recipient-pull ticket creation.
package handoff

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

const (
	DefaultTTL = 5 * time.Minute
	MinTTL     = 30 * time.Second
	MaxTTL     = 15 * time.Minute
)

func New(operationID, destinationID string, recipientUID uint32, now time.Time, ttl time.Duration) (*types.HandoffTicket, error) {
	if operationID == "" || destinationID == "" || ttl < MinTTL || ttl > MaxTTL {
		return nil, fmt.Errorf("invalid handoff ticket parameters")
	}
	ticketID := make([]byte, 32)
	nonce := make([]byte, 32)
	if _, err := rand.Read(ticketID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &types.HandoffTicket{
		Version: 1, TicketID: base64.RawURLEncoding.EncodeToString(ticketID),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), OperationID: operationID,
		DestinationID: destinationID, RecipientUID: recipientUID, IssuedAt: now,
		ExpiresAt: now.Add(ttl), State: "issued",
	}, nil
}
