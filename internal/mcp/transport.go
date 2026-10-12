package mcp

import (
	"errors"

	"github.com/mark3labs/mcp-go/server"
)

// StartStdio serves MCP over stdio and returns when the session closes.
// The adapter exits without terminating the independent broker.
func (s *Server) StartStdio() error {
	return server.ServeStdio(s.mcp)
}

func (s *Server) StartHTTP(_ string) error {
	return errors.New("seqpass: HTTP transport removed; use `seqpass mcp` over stdio")
}

func (s *Server) StartUDS(_ string) error {
	return errors.New("seqpass: MCP over UDS not supported; use stdio (`seqpass mcp`)")
}
