package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretbridge/secretbridge/internal/config"
)

// installCmd writes (or prints) the endpoint configuration an agent adapter
// needs: `seqpass install opencode|pi|mcp`.
//
// Security properties (objective §8):
//   - The generated configuration contains ONLY endpoints (socket paths).
//     Session IDs and tokens are minted by host.register at runtime and must
//     never live in a config file this command produces.
//   - No guessed locations: for hosts whose READMEs do not document a config
//     file path, the snippet is printed and --out names the target file.
//     An existing, differing file is never overwritten without --force, so a
//     stale endpoint cannot be silently "repaired" into a new one.
//   - Endpoints resolve through the shared installation configuration
//     (config.Load) with flag overrides, so the adapter cannot be pointed at
//     a different installation than the broker the operator started.
func installCmd(args []string) {
	base := loadBase()
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	printF := fs.Bool("print", false, "print what would be written; do not touch the filesystem")
	outF := fs.String("out", "", "target file for the adapter config (required to write opencode/pi snippets; optional for mcp)")
	forceF := fs.Bool("force", false, "overwrite an existing, differing config file")
	intakeF := fs.String("intake-socket", base.IntakeSocket, "broker intake socket for the adapter config")
	hostF := fs.String("host-socket", base.HostSocket, "broker host socket for the adapter config")
	sockF := fs.String("socket", base.SocketPath, "broker agent socket (pi agentSocket / MCP SEQ_PASS_SOCKET)")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "install: exactly one adapter argument is required; valid adapters: opencode, pi, mcp")
		os.Exit(2)
	}

	snippet, err := adapterSnippet(fs.Arg(0), *intakeF, *hostF, *sockF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install: %v\n", err)
		os.Exit(2)
	}

	// Fail closed on endpoints the adapter requires but the installation
	// has not declared: writing a config that dials nothing would fail at
	// runtime with a worse error than this one.
	if fs.Arg(0) == "opencode" || fs.Arg(0) == "pi" {
		if *intakeF == "" || *hostF == "" {
			fmt.Fprintf(os.Stderr, "install %s: the %s adapter requires the intake and host sockets; start the broker with --host-socket PATH (or set --intake-socket/--host-socket here)\n", fs.Arg(0), fs.Arg(0))
			os.Exit(1)
		}
	}

	target := *outF
	if fs.Arg(0) == "mcp" && target == "" {
		// MCP hosts differ in where their server registry lives (Codex
		// TOML, Claude CLI, ...). Without a documented shared file the
		// stanza is printed for the operator to register, as the usage
		// text already instructs.
		os.Stdout.Write(snippet)
		return
	}
	if fs.Arg(0) != "mcp" && target == "" {
		// Neither integration README documents a config file location.
		// Never guess one silently: print the snippet and say so.
		os.Stdout.Write(snippet)
		fmt.Fprintln(os.Stderr, "install "+fs.Arg(0)+": this host has no documented config file location; pass --out FILE to write the snippet above")
		return
	}

	if *printF {
		os.Stdout.Write(snippet)
		return
	}
	if err := writeAdapterConfig(target, snippet, *forceF); err != nil {
		fmt.Fprintf(os.Stderr, "install %s: %v\n", fs.Arg(0), err)
		os.Exit(1)
	}
	fmt.Printf("install %s: wrote %s (endpoints only — no credentials or session tokens)\n", fs.Arg(0), target)
}

// adapterSnippet validates the adapter name and renders its endpoint
// configuration. The adapter name is checked before anything else so an
// unknown name is refused with the valid choices, never silently treated as
// an empty configuration.
func adapterSnippet(adapter, intake, host, sock string) ([]byte, error) {
	switch adapter {
	case "opencode":
		if intake == "" || host == "" {
			return nil, fmt.Errorf("the opencode adapter requires the intake and host sockets; start the broker with --host-socket PATH (or set --intake-socket/--host-socket)")
		}
		return opencodeSnippet(intake, host)
	case "pi":
		if intake == "" || host == "" {
			return nil, fmt.Errorf("the pi adapter requires the intake and host sockets; start the broker with --host-socket PATH (or set --intake-socket/--host-socket)")
		}
		return piSnippet(intake, host, sock)
	case "mcp":
		return mcpSnippet(sock)
	default:
		return nil, fmt.Errorf("unknown adapter %q; valid adapters: opencode, pi, mcp", adapter)
	}
}

// writeAdapterConfig writes snippet to path with the same idempotency and
// --force contract as the init config generation: identical content is a
// no-op, differing content is refused without --force.
func writeAdapterConfig(path string, snippet []byte, force bool) error {
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(snippet) {
			fmt.Printf("install: %s is already configured\n", path)
			return nil
		}
		if !force {
			return fmt.Errorf("refusing to overwrite differing %s (pass --force)", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create %s: %w", filepath.Dir(path), err)
	}
	// Write through a sibling temp file and rename, so a crash mid-write
	// can never leave a truncated config the host would misread.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, snippet, 0600); err != nil {
		return fmt.Errorf("cannot write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot install %s: %w", path, err)
	}
	return nil
}

// opencodeSnippet renders the plugin options the OpenCode V2 adapter reads
// (integrations/opencode/index.ts): intakeSocket and hostSocket. sessionID
// and sessionToken are deliberately absent — they are minted by host.register
// when the plugin connects and must never be persisted here.
func opencodeSnippet(intake, host string) ([]byte, error) {
	return renderJSON(map[string]string{
		"intakeSocket": intake,
		"hostSocket":   host,
	})
}

// piSnippet renders the SeqPassExtensionConfig the Pi adapter reads
// (integrations/pi/seqpass.ts): intakeSocket, hostSocket and agentSocket.
// agentSocket is the broker's agent socket; the adapter fails closed without
// it for relay RPCs because the intake/host and agent endpoints have
// different authorization allowlists (SP-07).
func piSnippet(intake, host, agent string) ([]byte, error) {
	m := map[string]string{
		"intakeSocket": intake,
		"hostSocket":   host,
	}
	if agent != "" {
		m["agentSocket"] = agent
	}
	return renderJSON(m)
}

// mcpSnippet renders the exact JSON stanza that registers `seqpass mcp`
// (the stdio MCP server, cmd/seqpass/mcp.go) with hosts that accept the
// mcpServers form. The command is this binary's own absolute path, so the
// stanza launches the same installation it was generated by. The socket is
// exported as an endpoint — an environment endpoint, never a credential.
func mcpSnippet(sock string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "seqpass"
		fmt.Fprintln(os.Stderr, "install mcp: cannot resolve this binary's path; using \"seqpass\" from PATH")
	}
	return renderJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"seqpass": map[string]interface{}{
				"command": exe,
				"args":    []string{"mcp"},
				"env": map[string]string{
					config.EnvSocket: sock,
				},
			},
		},
	})
}

func renderJSON(v interface{}) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
