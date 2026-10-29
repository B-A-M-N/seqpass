package capsule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretbridge/secretbridge/internal/types"
)

const RecipientTrustVersion = 2

// RecipientTrust is installed by the trusted recipient administrator. The
// courier supplies capsule bytes only; it cannot choose keys, destination,
// target, journal, or broker receipt endpoint at import time.
type RecipientTrust struct {
	Version             int                       `json:"version"`
	DestinationID       string                    `json:"destination_id"`
	DestinationRevision int                       `json:"destination_revision"`
	RecipientKeyID      string                    `json:"recipient_key_id"`
	RecipientPrivateKey string                    `json:"recipient_private_key"`
	IssuerKeyID         string                    `json:"issuer_key_id"`
	IssuerPublicKey     []byte                    `json:"issuer_public_key"`
	ReceiptKeyID        string                    `json:"receipt_key_id"`
	ReceiptPrivateKey   string                    `json:"receipt_private_key"`
	ReceiptPublicKey    []byte                    `json:"receipt_public_key"`
	Target              types.AppCredentialTarget `json:"target"`
	BrokerSocket        string                    `json:"broker_socket,omitempty"`
	OpenCodeCommand     string                    `json:"opencode_command,omitempty"`
	CodexCommand        string                    `json:"codex_command,omitempty"`
	CodexHome           string                    `json:"codex_home,omitempty"`
	FIGatewaySocket     string                    `json:"fi_gateway_socket,omitempty"`
	FIGatewayPeerUID    *uint32                   `json:"fi_gateway_peer_uid,omitempty"`
}

// DefaultRecipientTrustPath resolves a registered target under the current
// recipient account's passwd home, never from HOME/XDG environment overrides.
func DefaultRecipientTrustPath(home, destinationID string) (string, error) {
	if !validID(destinationID) || !filepath.IsAbs(home) {
		return "", ErrInvalid
	}
	return filepath.Join(home, ".config", "seqpass", "recipients", destinationID+".json"), nil
}

func (c RecipientTrust) Validate() error {
	if c.Version != RecipientTrustVersion || !validID(c.DestinationID) || c.DestinationRevision <= 0 ||
		!validID(c.RecipientKeyID) || !filepath.IsAbs(c.RecipientPrivateKey) || !validID(c.IssuerKeyID) ||
		len(c.IssuerPublicKey) != 32 || !validID(c.ReceiptKeyID) || !filepath.IsAbs(c.ReceiptPrivateKey) || len(c.ReceiptPublicKey) != 32 ||
		(c.BrokerSocket != "" && !filepath.IsAbs(c.BrokerSocket)) || c.Target.Validate() != nil {
		return ErrInvalid
	}
	if c.RecipientKeyID == c.ReceiptKeyID || c.RecipientKeyID == c.IssuerKeyID || c.IssuerKeyID == c.ReceiptKeyID || bytes.Equal(c.IssuerPublicKey, c.ReceiptPublicKey) {
		return ErrInvalid
	}
	if c.Target.UpdateMethod == "opencode-auth-import-v2" && !filepath.IsAbs(c.OpenCodeCommand) {
		return ErrInvalid
	}
	if c.Target.App == "codex" && (!filepath.IsAbs(c.CodexCommand) || (c.CodexHome != "" && !filepath.IsAbs(c.CodexHome))) {
		return ErrInvalid
	}
	if c.Target.App == "fi-gateway" && !filepath.IsAbs(c.FIGatewaySocket) {
		return ErrInvalid
	}
	if c.Target.App != "fi-gateway" && c.FIGatewayPeerUID != nil {
		return ErrInvalid
	}
	return nil
}

// StoreRecipientTrust creates a recipient-local registration exactly once.
// Replacing trust is a separate operator action and cannot happen as a side
// effect of courier import.
func StoreRecipientTrust(path string, c RecipientTrust) error {
	if err := c.Validate(); err != nil || !filepath.IsAbs(path) {
		return ErrInvalid
	}
	if err := validateKeyParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("recipient trust directory is not private: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

// LoadRecipientTrust accepts only an owner-only file in a directory controlled
// by root or the recipient UID, rejects symlinks, and strictly decodes fields.
func LoadRecipientTrust(path string) (RecipientTrust, error) {
	var c RecipientTrust
	if err := validatePrivateKeyFile(path); err != nil {
		return c, fmt.Errorf("recipient trust registration is not protected: %w", err)
	}
	f, err := openPrivateKeyFile(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	var b bytes.Buffer
	if _, err := io.CopyN(&b, f, 64*1024+1); err != nil && err != io.EOF {
		return c, err
	}
	if b.Len() == 0 || b.Len() > 64*1024 {
		return c, ErrInvalid
	}
	dec := json.NewDecoder(strings.NewReader(b.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.Decode(new(any)) != io.EOF || c.Validate() != nil {
		return RecipientTrust{}, ErrInvalid
	}
	return c, nil
}
