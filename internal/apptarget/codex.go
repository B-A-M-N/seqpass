package apptarget

import (
	"bytes"
	"context"
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

const CodexAuthFileV1 = "codex-auth-file-v1"

// CodexAuthFile writes API-key credentials through Codex's supported login
// command into a recipient-pinned CODEX_HOME. The command path and home are
// supplied only by recipient-local enrollment.
type CodexAuthFile struct {
	CommandPath string
	HomeDir     string
	CodexHome   string
}

func (CodexAuthFile) App() string { return "codex" }

func (a CodexAuthFile) Apply(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateCodexTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := a.validate(); err != nil {
		return transfer.Committed{}, err
	}
	if !validCredentialLine(credential) {
		return transfer.Committed{}, fmt.Errorf("credential is not valid Codex API-key text")
	}
	path := filepath.Join(a.CodexHome, "auth.json")
	unlock, err := lockConfig(path)
	if err != nil {
		return transfer.Committed{}, err
	}
	defer unlock()
	if current, found, err := a.readCredential(target); err != nil {
		return transfer.Committed{}, err
	} else if found {
		if bytes.Equal(current, credential) {
			zero(current)
			return transfer.Committed{Applied: true, Digest: transfer.PayloadDigest(credential)}, nil
		}
		zero(current)
	}
	if err := a.run(ctx, credential); err != nil {
		return transfer.Committed{}, fmt.Errorf("Codex did not save the recipient API key")
	}
	got, found, err := a.readCredential(target)
	if err != nil {
		return transfer.Committed{}, err
	}
	defer zero(got)
	if !found || !bytes.Equal(got, credential) {
		return transfer.Committed{}, errors.New("Codex credential readback did not match")
	}
	digest := transfer.PayloadDigest(credential)
	return transfer.Committed{Applied: true, Digest: digest}, nil
}

// Reconcile reads the registered CODEX_HOME auth file. It never invokes login
// or changes Codex state after an ambiguous recipient crash.
func (a CodexAuthFile) Reconcile(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateCodexTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := a.validate(); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	path := filepath.Join(a.CodexHome, "auth.json")
	unlock, err := lockConfig(path)
	if err != nil {
		return transfer.Committed{}, err
	}
	defer unlock()
	got, found, err := a.readCredential(target)
	if err != nil {
		return transfer.Committed{}, err
	}
	defer zero(got)
	if !found || !bytes.Equal(got, credential) {
		return transfer.Committed{}, nil
	}
	return transfer.Committed{Applied: true, Digest: transfer.PayloadDigest(credential)}, nil
}

func validateCodexTarget(t types.AppCredentialTarget) error {
	if t.Validate() != nil || t.App != "codex" || t.UpdateMethod != CodexAuthFileV1 {
		return fmt.Errorf("unsupported or incomplete Codex credential target")
	}
	return nil
}

func (a CodexAuthFile) validate() error {
	if !filepath.IsAbs(a.CommandPath) || !filepath.IsAbs(a.HomeDir) || !filepath.IsAbs(a.CodexHome) {
		return fmt.Errorf("Codex command and homes must be explicit absolute paths")
	}
	info, err := os.Stat(a.CommandPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("Codex command is unavailable")
	}
	if err := validatePath(filepath.Join(a.CodexHome, "auth.json"), true); err != nil {
		return err
	}
	return nil
}

func (a CodexAuthFile) run(ctx context.Context, credential []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, a.CommandPath, "-c", `cli_auth_credentials_store="file"`, "login", "--with-api-key")
	cmd.Env = codexChildEnvironment(os.Environ(), a.HomeDir, a.CodexHome)
	input := make([]byte, len(credential)+1)
	copy(input, credential)
	input[len(credential)] = '\n'
	defer zero(input)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func codexChildEnvironment(parent []string, home, codexHome string) []string {
	var path, tmpdir string
	for _, item := range parent {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		switch key {
		case "PATH":
			path = value
		case "TMPDIR":
			tmpdir = value
		}
	}
	env := []string{"HOME=" + home, "CODEX_HOME=" + codexHome}
	if path != "" {
		env = append(env, "PATH="+path)
	}
	if tmpdir != "" {
		env = append(env, "TMPDIR="+tmpdir)
	}
	return env
}

func (a CodexAuthFile) readCredential(target types.AppCredentialTarget) ([]byte, bool, error) {
	path := filepath.Join(a.CodexHome, "auth.json")
	if err := validatePath(path, true); err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer zero(b)
	var record codexAuthRecord
	if err := json.Unmarshal(b, &record); err != nil {
		return nil, false, fmt.Errorf("Codex auth file is not a supported credential record")
	}
	if record.AuthMode != "apikey" || record.APIKey == "" {
		return nil, false, nil
	}
	return []byte(record.APIKey), true, nil
}

type codexAuthRecord struct {
	AuthMode string `json:"auth_mode"`
	APIKey   string `json:"OPENAI_API_KEY"`
}

func validCredentialLine(credential []byte) bool {
	return len(credential) > 0 && utf8.Valid(credential) &&
		!bytes.ContainsAny(credential, "\x00\r\n")
}
