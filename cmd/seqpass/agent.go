package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/secretbridge/secretbridge/internal/adapter"
	"github.com/secretbridge/secretbridge/internal/ipc"
)

// The generic agent CLI (objective 5/SP-18). It is the non-MCP transport for
// the same contract: discover capabilities, request protected input, poll
// status, cancel. It holds no vault and never receives a credential value;
// every call goes to the broker, which derives the principal from peer
// credentials.
//
// There is deliberately no flag that accepts a secret, and no command that
// prints one.

func agentCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agent subcommands: capabilities|request|status|cancel")
		fmt.Fprintln(os.Stderr, "  capabilities            discover permitted operations and accepted data kinds")
		fmt.Fprintln(os.Stderr, "  request --destination ID --data-kind KIND [--purpose TEXT] [--ttl-seconds N]")
		fmt.Fprintln(os.Stderr, "  status --request-id ID  poll sanitized request state")
		fmt.Fprintln(os.Stderr, "  cancel --request-id ID  withdraw a request before fulfillment")
		os.Exit(1)
	}
	switch args[0] {
	case "capabilities":
		agentCapabilities(args[1:])
	case "request":
		agentRequest(args[1:])
	case "status":
		agentStatus(args[1:])
	case "cancel":
		agentCancel(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown agent subcommand %q\n", args[0])
		os.Exit(1)
	}
}

func agentCapabilities(args []string) {
	fs := flag.NewFlagSet("agent capabilities", flag.ExitOnError)
	_ = fs.Parse(args)
	cli := dialAgent()
	defer cli.Close()
	health, err := cli.Call(ipc.MethodHealth, nil)
	must(err)
	catalog, err := cli.Call(ipc.MethodCatalog, nil)
	must(err)
	hm := mapOf(health)
	cap := adapter.NewCapability(
		adapter.TransportCLI,
		strField(hm, "assurance"),
		strField(hm, "input_mode"),
		strField(hm, "input_reason"),
		adapter.OperationFromCatalog(catalog),
	)
	printJSON(cap)
}

func agentRequest(args []string) {
	fs := flag.NewFlagSet("agent request", flag.ExitOnError)
	dest := fs.String("destination", "", "registered recipient ID (required)")
	kind := fs.String("data-kind", "", "password|one_time_code|api_key|token|pin|text (required)")
	purpose := fs.String("purpose", "", "short human-readable reason shown to the user")
	ttl := fs.Float64("ttl-seconds", 0, "how long the request stays fulfillable")
	_ = fs.Parse(args)
	if *dest == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "agent request: --destination and --data-kind are required")
		os.Exit(1)
	}
	params := map[string]interface{}{
		"destination_id": *dest,
		"data_kind":      *kind,
		"purpose":        *purpose,
	}
	if *ttl > 0 {
		params["ttl_seconds"] = *ttl
	}
	cli := dialAgent()
	defer cli.Close()
	data, err := cli.Call(ipc.MethodRelayRequest, params)
	must(err)
	m := mapOf(data)
	reqID := strField(m, "request_id")
	if reqID == "" {
		fatal("broker did not return a request ID")
	}
	emitEvent(adapter.Event{
		Type:       adapter.EventStateChanged,
		RequestID:  reqID,
		State:      adapter.StateAwaitingUser,
		NextAction: "protected_input",
		Assurance:  strField(m, "assurance"),
		Message:    "the user must authorize delivery through the trusted intake surface (seqpass relay fulfill)",
	})
}

func agentStatus(args []string) {
	fs := flag.NewFlagSet("agent status", flag.ExitOnError)
	reqID := fs.String("request-id", "", "relay request ID (required)")
	_ = fs.Parse(args)
	if *reqID == "" {
		fmt.Fprintln(os.Stderr, "agent status: --request-id is required")
		os.Exit(1)
	}
	data := agentCall(ipc.MethodRelayStatus, map[string]interface{}{"request_id": *reqID})
	m := mapOf(data)
	state, err := adapter.Normalize(strField(m, "status"))
	if err != nil {
		// Fail closed: an unqualified broker state is never reported.
		fatal("broker reported an unqualified request state")
	}
	sanitized := adapter.Scrub(m)
	sanitized["status"] = string(state)
	sanitized["settled"] = state.Settled()
	sanitized["succeeded"] = state.Succeeded()
	emitEvent(adapter.Event{
		Type:       adapter.EventStateChanged,
		RequestID:  *reqID,
		State:      state,
		Outcome:    strField(m, "outcome"),
		NextAction: strField(m, "next_action"),
		Assurance:  strField(m, "input_assurance"),
	})
	printJSON(sanitized)
}

func agentCancel(args []string) {
	fs := flag.NewFlagSet("agent cancel", flag.ExitOnError)
	reqID := fs.String("request-id", "", "relay request ID (required)")
	_ = fs.Parse(args)
	if *reqID == "" {
		fmt.Fprintln(os.Stderr, "agent cancel: --request-id is required")
		os.Exit(1)
	}
	data := agentCall(ipc.MethodRelayCancel, map[string]interface{}{"request_id": *reqID})
	emitEvent(adapter.Event{
		Type:      adapter.EventStateChanged,
		RequestID: *reqID,
		State:     adapter.StateRejected,
		Outcome:   "cancelled_by_agent",
	})
	printJSON(adapter.Scrub(mapOf(data)))
}

func agentCall(method string, params map[string]interface{}) interface{} {
	cli := dialAgent()
	defer cli.Close()
	data, err := cli.Call(method, params)
	must(err)
	return data
}

// emitEvent prints one validated, sanitized adapter event. An event that
// fails validation is never printed.
func emitEvent(e adapter.Event) {
	frame, err := adapter.Encode(e)
	if err != nil {
		fatal("refusing to emit an invalid event: " + err.Error())
	}
	var pretty interface{}
	if err := json.Unmarshal(frame, &pretty); err != nil {
		fatal("event encoding failed")
	}
	raw, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(raw))
}

func mapOf(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

func strField(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}
