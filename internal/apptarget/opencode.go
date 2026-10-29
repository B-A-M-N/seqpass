package apptarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

const OpenCodeAuthJSONV1 = "opencode-auth-json-v1"

// OpenCodeAuth stores the API key in OpenCode's own auth.json account store.
// Its path is supplied only by recipient-local wiring.
type OpenCodeAuth struct{ Path string }

func (OpenCodeAuth) App() string { return "opencode" }

func (a OpenCodeAuth) Apply(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateOpenCodeTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	if !utf8.Valid(credential) || strings.ContainsRune(string(credential), '\x00') {
		return transfer.Committed{}, fmt.Errorf("credential is not valid OpenCode API-key text")
	}
	unlock, err := lockConfig(a.Path)
	if err != nil {
		return transfer.Committed{}, err
	}
	defer unlock()
	doc, err := readAuth(a.Path)
	if err != nil {
		return transfer.Committed{}, err
	}
	account, err := accountObject(doc, target.Account)
	if err != nil {
		return transfer.Committed{}, err
	}
	account["type"] = "api"
	account["key"] = string(credential)
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return transfer.Committed{}, err
	}
	if err := atomicPrivateWrite(a.Path, append(encoded, '\n')); err != nil {
		return transfer.Committed{}, err
	}
	got, err := a.readCredential(target)
	if err != nil {
		return transfer.Committed{}, err
	}
	digest := transfer.PayloadDigest(got)
	zero(got)
	want := transfer.PayloadDigest(credential)
	if digest != want {
		return transfer.Committed{Digest: digest}, errors.New("OpenCode credential readback did not match")
	}
	return transfer.Committed{Applied: true, Digest: want}, nil
}

// Reconcile is read-only. It never repeats the config write after an
// ambiguous recipient crash.
func (a OpenCodeAuth) Reconcile(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateOpenCodeTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	got, err := a.readCredential(target)
	if err != nil {
		return transfer.Committed{}, err
	}
	digest := transfer.PayloadDigest(got)
	zero(got)
	want := transfer.PayloadDigest(credential)
	if digest != want {
		return transfer.Committed{Digest: digest}, nil
	}
	return transfer.Committed{Applied: true, Digest: want}, nil
}

func validateOpenCodeTarget(t types.AppCredentialTarget) error {
	if t.App != "opencode" || t.UpdateMethod != OpenCodeAuthJSONV1 || t.Slot != "api_key" || t.Account == "" || t.ID != "opencode:"+t.Account+":api_key" || t.SourceRef == "" || t.SourceRevision <= 0 {
		return fmt.Errorf("unsupported or incomplete OpenCode credential target")
	}
	return nil
}

func (a OpenCodeAuth) readCredential(target types.AppCredentialTarget) ([]byte, error) {
	doc, err := readAuth(a.Path)
	if err != nil {
		return nil, err
	}
	account, err := accountObject(doc, target.Account)
	if err != nil {
		return nil, err
	}
	key, ok := account["key"].(string)
	if !ok || key == "" {
		return nil, fmt.Errorf("OpenCode target credential is absent")
	}
	return []byte(key), nil
}

func readAuth(path string) (map[string]any, error) {
	if err := validatePath(path, true); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, fmt.Errorf("OpenCode auth.json is not a JSON object")
	}
	return doc, nil
}

func accountObject(doc map[string]any, account string) (map[string]any, error) {
	providerRaw, ok := doc[account]
	if !ok {
		provider := map[string]any{}
		doc[account] = provider
		return provider, nil
	}
	provider, ok := providerRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenCode account entry is not an object")
	}
	return provider, nil
}

func targetCredentialDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func DefaultOpenCodeAuthPath(home string) string {
	return filepath.Join(home, ".local", "share", "opencode", "auth.json")
}
