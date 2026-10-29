package apptarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

const OpenCodeAuthImportV2 = "opencode-auth-import-v2"

// OpenCodeV2Auth manages saved API keys through OpenCode v2's supported CLI.
// V2 stores credentials in its database and no longer reads auth.json after
// the legacy migration.
type OpenCodeV2Auth struct {
	CommandPath string
	HomeDir     string
}

// NewOpenCodeAdapter selects an explicitly registered adapter revision. The
// v2 command path is recipient-local trusted configuration, never PATH input.
func NewOpenCodeAdapter(target types.AppCredentialTarget, home, commandPath string) (Adapter, error) {
	switch target.UpdateMethod {
	case OpenCodeAuthJSONV1:
		return OpenCodeAuth{Path: DefaultOpenCodeAuthPath(home)}, nil
	case OpenCodeAuthImportV2:
		if commandPath == "" {
			return nil, fmt.Errorf("OpenCode v2 requires an explicit recipient-local command path")
		}
		adapter := OpenCodeV2Auth{CommandPath: commandPath, HomeDir: home}
		if err := adapter.validateCommand(); err != nil {
			return nil, err
		}
		return adapter, nil
	default:
		return nil, fmt.Errorf("unsupported OpenCode adapter revision")
	}
}

func (OpenCodeV2Auth) App() string { return "opencode" }

func (a OpenCodeV2Auth) Apply(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateOpenCodeV2Target(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := a.validateCommand(); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	if !utf8.Valid(credential) || len(credential) == 0 || bytes.ContainsRune(credential, '\x00') {
		return transfer.Committed{}, fmt.Errorf("credential is not valid OpenCode API-key text")
	}

	id := openCodeV2CredentialID(target)
	if current, found, err := a.readManagedCredential(ctx, target, id); err != nil {
		return transfer.Committed{}, err
	} else if found {
		if bytes.Equal(current, credential) {
			zero(current)
			return transfer.Committed{Applied: true, Digest: transfer.PayloadDigest(credential)}, nil
		}
		zero(current)
		if err := a.run(ctx, []string{"auth", "logout", target.Account, id, "--standalone"}, nil, io.Discard); err != nil {
			return transfer.Committed{}, fmt.Errorf("OpenCode could not remove the prior SeqPass-managed account")
		}
	}

	input, err := json.Marshal([]openCodeV2ImportEntry{{
		ID: id, IntegrationID: target.Account, Label: openCodeV2CredentialLabel(target), Active: true,
		Value: openCodeV2Key{Type: "key", Key: string(credential)},
	}})
	if err != nil {
		return transfer.Committed{}, err
	}
	defer zero(input)
	if err := a.run(ctx, []string{"auth", "import", "--standalone"}, bytes.NewReader(input), io.Discard); err != nil {
		return transfer.Committed{}, fmt.Errorf("OpenCode did not import the SeqPass-managed credential")
	}
	committed, err := a.Reconcile(ctx, target, operationID, credential)
	if err != nil {
		return transfer.Committed{}, err
	}
	if !committed.Applied {
		return committed, errors.New("OpenCode credential readback did not match")
	}
	return committed, nil
}

// Reconcile reads OpenCode's credential export and never writes to the app.
func (a OpenCodeV2Auth) Reconcile(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateOpenCodeV2Target(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := a.validateCommand(); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	current, found, err := a.readManagedCredential(ctx, target, openCodeV2CredentialID(target))
	if err != nil {
		return transfer.Committed{}, err
	}
	defer zero(current)
	if !found || !bytes.Equal(current, credential) {
		return transfer.Committed{}, nil
	}
	digest := transfer.PayloadDigest(credential)
	return transfer.Committed{Applied: true, Digest: digest}, nil
}

func validateOpenCodeV2Target(t types.AppCredentialTarget) error {
	if t.App != "opencode" || t.UpdateMethod != OpenCodeAuthImportV2 || t.Slot != "api_key" || t.Account == "" || t.ID != "opencode:"+t.Account+":api_key" || t.SourceRef == "" || t.SourceRevision <= 0 {
		return fmt.Errorf("unsupported or incomplete OpenCode v2 credential target")
	}
	return nil
}

func (a OpenCodeV2Auth) validateCommand() error {
	if !filepath.IsAbs(a.CommandPath) {
		return fmt.Errorf("OpenCode v2 command path must be absolute")
	}
	info, err := os.Stat(a.CommandPath)
	if err != nil {
		return fmt.Errorf("OpenCode v2 command is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("OpenCode v2 command is not an executable regular file")
	}
	return nil
}

func (a OpenCodeV2Auth) readManagedCredential(ctx context.Context, target types.AppCredentialTarget, id string) ([]byte, bool, error) {
	output := &bytes.Buffer{}
	if err := a.run(ctx, []string{"auth", "export", target.Account, "--standalone"}, nil, output); err != nil {
		return nil, false, fmt.Errorf("OpenCode credential readback failed")
	}
	defer zero(output.Bytes())
	var entries []openCodeV2ExportEntry
	if err := json.Unmarshal(output.Bytes(), &entries); err != nil {
		return nil, false, fmt.Errorf("OpenCode credential export was invalid")
	}
	for _, entry := range entries {
		if entry.ID != id || entry.IntegrationID != target.Account {
			continue
		}
		if entry.Value.Type != "key" || entry.Value.Key == "" {
			return nil, false, fmt.Errorf("SeqPass-managed OpenCode account has an unsupported credential type")
		}
		return []byte(entry.Value.Key), true, nil
	}
	return nil, false, nil
}

func (a OpenCodeV2Auth) run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if a.HomeDir == "" || !filepath.IsAbs(a.HomeDir) {
		return fmt.Errorf("OpenCode v2 recipient home must be an explicit absolute path")
	}
	cmd := exec.CommandContext(ctx, a.CommandPath, args...)
	cmd.Env = openCodeV2Environment(os.Environ(), a.HomeDir)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func openCodeV2Environment(parent []string, home string) []string {
	allowed := map[string]bool{
		"PATH": true, "XDG_CONFIG_HOME": true,
		"XDG_DATA_HOME": true, "XDG_STATE_HOME": true, "TMPDIR": true,
		"OPENCODE_DB": true,
	}
	env := make([]string, 0, len(allowed))
	for _, item := range parent {
		key, _, ok := strings.Cut(item, "=")
		if ok && allowed[key] {
			env = append(env, item)
		}
	}
	return append(env, "HOME="+home)
}

func openCodeV2CredentialID(target types.AppCredentialTarget) string {
	sum := sha256.Sum256([]byte("seqpass/opencode/v2/" + target.ID))
	return "seqpass-" + hex.EncodeToString(sum[:12])
}

func openCodeV2CredentialLabel(target types.AppCredentialTarget) string {
	return "SeqPass " + target.ID
}

type openCodeV2ImportEntry struct {
	ID            string        `json:"id"`
	IntegrationID string        `json:"integrationID"`
	Label         string        `json:"label"`
	Active        bool          `json:"active"`
	Value         openCodeV2Key `json:"value"`
}

type openCodeV2ExportEntry struct {
	ID            string        `json:"id"`
	IntegrationID string        `json:"integrationID"`
	Value         openCodeV2Key `json:"value"`
}

type openCodeV2Key struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}
