package apptarget

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/secretbridge/secretbridge/internal/transfer"
	"github.com/secretbridge/secretbridge/internal/types"
)

const FIGatewayCredentialManagerV1 = "fi-gateway-credential-manager-v1"

// FIGatewayCredentialManager applies an approved provider credential through
// FI Gateway's recipient-only Unix socket. The gateway owns durable storage,
// active-version selection, rotation and readback; no HTTP/public endpoint is
// involved in credential intake.
type FIGatewayCredentialManager struct {
	SocketPath      string
	ExpectedPeerUID *uint32
}

func (FIGatewayCredentialManager) App() string { return "fi-gateway" }

func (a FIGatewayCredentialManager) Apply(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateFIGatewayTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if !validCredentialLine(credential) || !utf8.Valid(credential) {
		return transfer.Committed{}, fmt.Errorf("credential is not valid gateway API-key text")
	}
	response, err := a.call(ctx, gatewayCredentialRequest{
		Operation: "apply", OperationID: operationID, TargetID: target.ID, Provider: target.Provider,
		Account: target.Account, Credential: string(credential),
	})
	if err != nil {
		return transfer.Committed{}, err
	}
	if !response.OK || !response.Applied || response.Provider != target.Provider ||
		response.Account != target.Account || response.CredentialID == "" || response.Version <= 0 {
		return transfer.Committed{}, fmt.Errorf("gateway did not confirm the registered credential target")
	}
	// A successful write acknowledgment proves storage acceptance only.
	// Read the exact active slot back before reporting the application as
	// committed to SeqPass; a later routing qualification is still separate.
	verified, err := a.Reconcile(ctx, target, operationID, credential)
	if err != nil {
		return transfer.Committed{}, err
	}
	if !verified.Applied {
		return transfer.Committed{}, fmt.Errorf("gateway did not select the installed credential as active")
	}
	return verified, nil
}

func (a FIGatewayCredentialManager) Reconcile(ctx context.Context, target types.AppCredentialTarget, operationID string, credential []byte) (transfer.Committed, error) {
	if err := validateFIGatewayTarget(target); err != nil {
		return transfer.Committed{}, err
	}
	if err := ctx.Err(); err != nil {
		return transfer.Committed{}, err
	}
	response, err := a.call(ctx, gatewayCredentialRequest{
		Operation: "reconcile", OperationID: operationID, TargetID: target.ID, Provider: target.Provider,
		Account: target.Account, Credential: string(credential),
	})
	if err != nil {
		return transfer.Committed{}, err
	}
	if !response.OK || response.Provider != "" && response.Provider != target.Provider ||
		response.Account != "" && response.Account != target.Account {
		return transfer.Committed{}, fmt.Errorf("gateway rejected credential reconciliation")
	}
	if !response.Applied {
		return transfer.Committed{}, nil
	}
	return transfer.Committed{Applied: true, Digest: transfer.PayloadDigest(credential)}, nil
}

func validateFIGatewayTarget(target types.AppCredentialTarget) error {
	if err := target.Validate(); err != nil || target.App != "fi-gateway" ||
		target.UpdateMethod != FIGatewayCredentialManagerV1 {
		return fmt.Errorf("unsupported or incomplete FI Gateway credential target")
	}
	return nil
}

func (a FIGatewayCredentialManager) validate() error {
	return validateFIGatewaySocketPath(a.SocketPath)
}

type gatewayCredentialRequest struct {
	Operation   string `json:"op"`
	OperationID string `json:"operation_id"`
	TargetID    string `json:"target_id"`
	Provider    string `json:"provider"`
	Account     string `json:"account"`
	Credential  string `json:"credential"`
}

type gatewayCredentialResponse struct {
	OK           bool   `json:"ok"`
	Applied      bool   `json:"applied"`
	Changed      bool   `json:"changed"`
	Error        string `json:"error"`
	CredentialID string `json:"credential_id"`
	Provider     string `json:"provider"`
	Account      string `json:"account"`
	Version      int    `json:"version"`
	Fingerprint  string `json:"fingerprint"`
}

func (a FIGatewayCredentialManager) call(ctx context.Context, request gatewayCredentialRequest) (gatewayCredentialResponse, error) {
	var response gatewayCredentialResponse
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if !filepath.IsAbs(a.SocketPath) {
		return response, fmt.Errorf("registered gateway socket path must be absolute")
	}
	if err := validateFIGatewaySocketPath(a.SocketPath); err != nil {
		return response, fmt.Errorf("registered gateway credential socket is unavailable")
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", a.SocketPath)
	if err != nil {
		return response, fmt.Errorf("could not reach the registered gateway credential receiver")
	}
	defer connection.Close()
	if err := verifyFIGatewayPeer(connection, a.ExpectedPeerUID); err != nil {
		return response, fmt.Errorf("gateway credential socket peer identity did not match the recipient")
	}
	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = connection.SetDeadline(deadline)
	encoded, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	if _, err := connection.Write(append(encoded, '\n')); err != nil {
		return response, fmt.Errorf("gateway credential request failed")
	}
	line, err := bufio.NewReader(io.LimitReader(connection, 4097)).ReadBytes('\n')
	if err != nil || len(line) > 4096 {
		return response, fmt.Errorf("gateway credential receiver returned an invalid response")
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return response, fmt.Errorf("gateway credential receiver returned an invalid response")
	}
	if !response.OK && response.Error != "" {
		return response, fmt.Errorf("gateway credential receiver refused the request")
	}
	return response, nil
}

func validateFIGatewaySocketPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("gateway credential socket path must be explicit and absolute")
	}
	clean := filepath.Clean(path)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	foundSocket := false
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("gateway credential socket path contains a symlink")
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return fmt.Errorf("gateway credential socket parent is not a directory")
			}
			if err := validateDirectory(info); err != nil {
				return err
			}
			continue
		}
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("gateway credential socket must be owner-only")
		}
		foundSocket = true
		if err := validateFileOwner(info); err != nil {
			return err
		}
	}
	if !foundSocket {
		return fmt.Errorf("gateway credential socket path is missing")
	}
	return nil
}
