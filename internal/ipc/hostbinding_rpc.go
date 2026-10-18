package ipc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

// parseHostBindingAction extracts the action verb from host binding RPC params.
func parseHostBindingAction(p map[string]interface{}) string {
	if a, ok := p["action"].(string); ok {
		return a
	}
	return ""
}

// parseHostBindingFields extracts the common binding identity fields.
func parseHostBindingFields(p map[string]interface{}) (human, agent, hostKind string) {
	human = strParam(p, "human_principal")
	agent = strParam(p, "agent_principal")
	hostKind = strParam(p, "host_kind")
	return
}

// parseHostBindingExpiry extracts and validates the expiry duration for
// create/renew actions. Returns a zero time.Time for inspect/revoke.
func parseHostBindingExpiry(p map[string]interface{}) (time.Time, error) {
	if ttl, ok := uintParam(p, "ttl_seconds"); ok && ttl > 0 {
		exp := time.Now().Add(time.Duration(ttl) * time.Second)
		if exp.Sub(time.Now()) > 24*time.Hour {
			return time.Time{}, fmt.Errorf("binding ttl exceeds 24 hours")
		}
		return exp, nil
	}
	return time.Time{}, nil
}

// dispatchHostBindingCreate handles admin.host_binding_create RPC methods:
// create, inspect, renew, and revoke operations on host principal bindings.
// This is only reachable from the admin socket with an explicitly authorized
// administrative identity (CanAdminPrincipal).
func (s *Server) dispatchHostBindingCreate(p map[string]interface{}) Response {
	human, agent, hostKind := parseHostBindingFields(p)
	action := parseHostBindingAction(p)
	if hostKind == "" {
		return Response{OK: false, Error: "missing host_kind"}
	}
	switch action {
	case "create":
		if human == "" || agent == "" {
			return Response{OK: false, Error: "missing human_principal or agent_principal"}
		}
		exp, err := parseHostBindingExpiry(p)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		if exp.IsZero() {
			return Response{OK: false, Error: "missing ttl_seconds"}
		}
		b := &types.HostPrincipalBinding{
			HumanPrincipal: human, AgentPrincipal: agent,
			HostKind: hostKind, ExpiresAt: exp,
		}
		if err := s.svc.DB().CreateHostPrincipalBinding(b); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"human_principal": b.HumanPrincipal,
			"agent_principal": b.AgentPrincipal,
			"host_kind":       b.HostKind,
			"expires_at":      b.ExpiresAt,
			"revision":        b.Revision,
		}}
	case "inspect":
		if human == "" {
			return Response{OK: false, Error: "missing human_principal"}
		}
		b, err := s.svc.DB().ResolveHostPrincipalBinding(human, hostKind, time.Now())
		if err != nil {
			return Response{OK: false, Error: "internal error"}
		}
		if b == nil {
			return Response{OK: false, Error: "no active binding"}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"human_principal": b.HumanPrincipal,
			"agent_principal": b.AgentPrincipal,
			"host_kind":       b.HostKind,
			"expires_at":      b.ExpiresAt,
			"revision":        b.Revision,
		}}
	case "renew":
		if human == "" || agent == "" {
			return Response{OK: false, Error: "missing human_principal or agent_principal"}
		}
		exp, err := parseHostBindingExpiry(p)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		if exp.IsZero() {
			return Response{OK: false, Error: "missing ttl_seconds"}
		}
		if err := s.svc.DB().RenewHostPrincipalBinding(human, agent, hostKind, exp); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"human_principal": human,
			"agent_principal": agent,
			"host_kind":       hostKind,
			"expires_at":      exp,
		}}
	case "revoke":
		if human == "" || agent == "" {
			return Response{OK: false, Error: "missing human_principal or agent_principal"}
		}
		if err := s.svc.DB().RevokeHostPrincipalBinding(human, agent, hostKind); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Data: map[string]interface{}{
			"human_principal": human, "agent_principal": agent,
			"host_kind": hostKind, "status": "revoked",
		}}
	default:
		return Response{OK: false, Error: "invalid action (create|inspect|renew|revoke)"}
	}
}

// parseHostBindingResult is a convenience for tests and external callers
// that need a typed response from dispatchHostBindingCreate.
func parseHostBindingResult(data interface{}) (*types.HostPrincipalBinding, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var b types.HostPrincipalBinding
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("invalid binding response: %w", err)
	}
	return &b, nil
}
