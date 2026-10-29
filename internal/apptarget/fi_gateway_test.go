package apptarget

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/types"
)

func TestFIGatewayAdapterAppliesAndReconcilesThroughPinnedSocket(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("FI Gateway recipient uses a Unix-domain socket")
	}
	root, err := os.MkdirTemp("../..", ".fi-gateway-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "gateway.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	target := types.AppCredentialTarget{
		ID: "fi-gateway:openrouter:primary:api_key", App: "fi-gateway",
		Provider: "openrouter", Account: "primary", Slot: "api_key",
		UpdateMethod: FIGatewayCredentialManagerV1,
		SourceRef:    "vault/openrouter", SourceRevision: 3,
	}
	peerUID := uint32(os.Geteuid())
	adapter, err := NewRecipientAdapter(target, t.TempDir(), RecipientOptions{FIGatewaySocket: path, FIGatewayPeerUID: &peerUID})
	if err != nil {
		t.Fatal(err)
	}
	gotAdapter, ok := adapter.(FIGatewayCredentialManager)
	if !ok {
		t.Fatalf("factory returned %T", adapter)
	}
	requestResults := make(chan gatewayCredentialRequest, 3)
	go func() {
		for i := 0; i < 3; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var request gatewayCredentialRequest
			_ = json.NewDecoder(bufio.NewReader(conn)).Decode(&request)
			requestResults <- request
			response := `{"ok":true,"applied":true,"changed":true,"credential_id":"crd-example","provider":"openrouter","account":"primary","version":1}`
			if request.Operation == "reconcile" {
				response = `{"ok":true,"applied":true,"provider":"openrouter","account":"primary","credential_id":"crd-example","version":1}`
			}
			_, _ = conn.Write([]byte(response + "\n"))
			_ = conn.Close()
		}
	}()

	credential := []byte("synthetic-gateway-key")
	result, err := gotAdapter.Apply(context.Background(), target, "handoff-1", credential)
	if err != nil || !result.Applied {
		t.Fatalf("apply: result=%+v err=%v", result, err)
	}
	applyRequest := <-requestResults
	if applyRequest.Operation != "apply" || applyRequest.TargetID != target.ID || applyRequest.Provider != target.Provider ||
		applyRequest.Account != target.Account || applyRequest.Credential != string(credential) {
		t.Fatalf("wrong gateway request: %#v", applyRequest)
	}
	readbackRequest := <-requestResults
	if readbackRequest.Operation != "reconcile" || readbackRequest.OperationID != "handoff-1" {
		t.Fatalf("apply did not perform active-slot readback: %#v", readbackRequest)
	}
	result, err = gotAdapter.Reconcile(context.Background(), target, "handoff-1", credential)
	if err != nil || !result.Applied {
		t.Fatalf("reconcile: result=%+v err=%v", result, err)
	}
	reconcileRequest := <-requestResults
	if reconcileRequest.Operation != "reconcile" || reconcileRequest.OperationID != "handoff-1" {
		t.Fatalf("wrong reconciliation request: %#v", reconcileRequest)
	}
}

func TestFIGatewayPeerUIDPinRejectsOtherServiceIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	wantUID := uint32(os.Geteuid()) + 1
	if err := verifyFIGatewayPeer(conn, &wantUID); err == nil {
		t.Fatal("accepted a gateway peer with the wrong configured service UID")
	}
}

func TestFIGatewayTargetRequiresClosedProviderAndAccountIdentity(t *testing.T) {
	target := types.AppCredentialTarget{
		ID: "fi-gateway:openrouter:primary:api_key", App: "fi-gateway",
		Provider: "openrouter", Account: "primary", Slot: "api_key",
		UpdateMethod: FIGatewayCredentialManagerV1, SourceRef: "vault/ref", SourceRevision: 1,
	}
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	target.ID = "fi-gateway:other:primary:api_key"
	if err := target.Validate(); err == nil {
		t.Fatal("accepted target ID that did not bind the provider")
	}
	target.ID = "fi-gateway:openrouter:primary:api_key"
	target.Provider = "../openrouter"
	if err := target.Validate(); err == nil {
		t.Fatal("accepted path-like provider identity")
	}
}
