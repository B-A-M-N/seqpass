package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secretbridge/secretbridge/internal/config"
)

func TestDefaultPathsUseInstallationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"db_path":"/var/lib/seqpass/metadata.db","socket_path":"/run/seqpass-agent/broker.sock","admin_socket":"/run/seqpass/admin.sock","intake_socket":"/run/seqpass/intake.sock"}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfig, path)

	db, agent, admin, intake := defaultPaths()
	if db != "/var/lib/seqpass/metadata.db" || agent != "/run/seqpass-agent/broker.sock" || admin != "/run/seqpass/admin.sock" || intake != "/run/seqpass/intake.sock" {
		t.Fatalf("default paths = (%q, %q, %q, %q)", db, agent, admin, intake)
	}
}
