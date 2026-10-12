// Package secretbridge is the importable harness interface for SeqPass.
//
// Coding harnesses import this package (or register `seqpass mcp` via MCP)
// instead of constructing the privileged broker service. All operations go
// over the broker Unix socket; the broker derives identity from peer
// credentials. No function here returns secret plaintext.
package secretbridge

import (
	"github.com/secretbridge/secretbridge/internal/ipc"
	"github.com/secretbridge/secretbridge/internal/secureops"
	"github.com/secretbridge/secretbridge/internal/service"
	"github.com/secretbridge/secretbridge/internal/types"
)

type (
	SecretReference = types.SecretReference
	Destination     = types.Destination
	UseRequest      = types.UseRequest
	TransferRequest = types.TransferRequest
	AuditLog        = types.AuditLog
	// CatalogEntry pairs a secret reference with its discoverable
	// operations (G06): ready means directly usable, scoped needs an
	// exact target/resource.
	CatalogEntry = service.CatalogEntry
	CatalogOp    = service.CatalogOp
	ParamInfo    = secureops.ParamInfo
)

// Client is the harness-facing broker client.
type Client struct {
	cli *ipc.Client
}

// Dial connects to the broker socket (default: ~/.seqpass/broker.sock,
// override with SEQ_PASS_SOCKET).
func Dial(socket string) (*Client, error) {
	cli, err := ipc.Dial(socket)
	if err != nil {
		return nil, err
	}
	return &Client{cli: cli}, nil
}

func (c *Client) Close() error { return c.cli.Close() }

// Catalog lists references with their discoverable operations for the
// authenticated identity (G06). Disallowed operations stay hidden.
func (c *Client) Catalog() ([]CatalogEntry, error) {
	data, err := c.cli.Call(ipc.MethodCatalog, nil)
	if err != nil {
		return nil, err
	}
	return decodeCatalog(data)
}

// Use submits an allowlisted credentialed operation; returns opaque ID.
func (c *Client) Use(secretRef, operation, target string, params map[string]string) (string, error) {
	p := map[string]interface{}{
		"secret_ref": secretRef,
		"operation":  operation,
		"target":     target,
	}
	if params != nil {
		m := map[string]interface{}{}
		for k, v := range params {
			m[k] = v
		}
		p["params"] = m
	}
	data, err := c.cli.Call(ipc.MethodUseSubmit, p)
	if err != nil {
		return "", err
	}
	return decodeOpID(data)
}

// Transfer requests broker-to-recipient delivery; returns opaque ID.
func (c *Client) Transfer(secretRef, destinationID string) (string, error) {
	data, err := c.cli.Call(ipc.MethodTransferSubmit, map[string]interface{}{
		"secret_ref":     secretRef,
		"destination_id": destinationID,
	})
	if err != nil {
		return "", err
	}
	return decodeOpID(data)
}

// Status polls the caller's own operation status (approval-visible from harness).
func (c *Client) Status(opType, opID string) (string, error) {
	data, err := c.cli.Call(ipc.MethodStatus, map[string]interface{}{
		"op_type": opType,
		"op_id":   opID,
	})
	if err != nil {
		return "", err
	}
	if m, ok := data.(map[string]interface{}); ok {
		if s, ok := m["status"].(string); ok {
			return s, nil
		}
	}
	return "", nil
}
