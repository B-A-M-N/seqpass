package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretbridge/secretbridge/internal/config"
)

// The "next steps" commands that init prints must run as printed. A missing
// flag in the printed text is a broken installation: the operator pastes it
// and the broker refuses, or worse, starts with a narrower identity set than
// the one the operator declared.
func TestPrintedNextStepsCarryEveryDeclaredFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		mutate   func(*config.Deployment)
		contains []string
	}{
		{
			name: "development memory vault, best-effort",
			mutate: func(d *config.Deployment) {
				d.VaultType = config.VaultMemoryTest
				d.Dev = true
				d.AgentUIDs = []uint32{1001}
			},
			contains: []string{"--vault memory-test", "--dev", "--assurance best-effort", "--agent-uid 1001"},
		},
		{
			name: "production vault, isolated claim",
			mutate: func(d *config.Deployment) {
				d.VaultType = config.VaultAegisKeys
				d.AssuranceMode = config.AssuranceIsolated
				d.AgentUIDs = []uint32{1001, 1002}
				d.IntakeUIDs = []uint32{1000}
				d.SocketGroup = "seqpass-agents"
				d.AegisKeysSocket = "/srv/ak/.config/aegiskeys/run/broker.sock"
				d.AegisKeysDir = "/srv/ak/.config/aegiskeys"
				d.AegisKeysResolveHelper = "/usr/local/bin/seqpass"
				d.AegisKeysResolveHelperSHA256 = strings.Repeat("a", 64)
			},
			contains: []string{
				"--vault aegiskeys", "--assurance isolated",
				"--aegiskeys-socket '/srv/ak/.config/aegiskeys/run/broker.sock'", "--aegiskeys-dir '/srv/ak/.config/aegiskeys'",
				"--aegiskeys-resolve-helper '/usr/local/bin/seqpass'", "--aegiskeys-resolve-helper-sha256 " + strings.Repeat("a", 64),
				"--agent-uid 1001,1002", "--intake-uid 1000", "--socket-group seqpass-agents",
				"--socket " + "'" + filepath.Join(dir, "production vault, isolated claim", "agent.sock") + "'",
				"--admin-socket " + "'" + filepath.Join(dir, "production vault, isolated claim", "admin.sock") + "'",
				"--intake-socket " + "'" + filepath.Join(dir, "production vault, isolated claim", "intake.sock") + "'",
			},
		},
		{
			// The regression this pins: the isolated broker command used to
			// omit --dev, so the printed doctor line ran and the printed
			// broker line was refused.
			name: "development vault with an isolated claim keeps --dev on the broker line",
			mutate: func(d *config.Deployment) {
				d.VaultType = config.VaultMemoryTest
				d.Dev = true
				d.AssuranceMode = config.AssuranceIsolated
				d.AgentUIDs = []uint32{1001}
				d.IntakeUIDs = []uint32{1000}
				d.SocketGroup = "seqpass-agents"
			},
			contains: []string{"--vault memory-test --dev --assurance isolated", "--agent-uid 1001"},
		},
	}
	for _, tc := range cases {
		d := config.Defaults()
		d.DBPath = filepath.Join(dir, tc.name, "meta.db")
		d.SocketPath = filepath.Join(dir, tc.name, "agent.sock")
		d.AdminSocket = filepath.Join(dir, tc.name, "admin.sock")
		d.IntakeSocket = filepath.Join(dir, tc.name, "intake.sock")
		tc.mutate(&d)
		out := captureStdout(t, func() {
			printNextSteps(d)
		})
		for _, want := range tc.contains {
			if !strings.Contains(out, want) {
				t.Errorf("%s: printed steps missing %q:\n%s", tc.name, want, out)
			}
		}
		if strings.Contains(out, "--dev --dev") {
			t.Errorf("%s: printed steps duplicate --dev:\n%s", tc.name, out)
		}
	}
}
