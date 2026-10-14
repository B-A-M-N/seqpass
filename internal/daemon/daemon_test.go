package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/secretbridge/secretbridge/internal/ipc"
)

// sandboxAncestorUntrusted reports whether this sandbox exposes a
// high-level ancestor (e.g. /home) as nobody:nogroup. The broker refuses
// such ancestors by design, so socket-based tests must skip there.
func sandboxAncestorUntrusted() bool {
	fi, err := os.Lstat("/home")
	return err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 && fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())
}

// G05: two brokers cannot own one database. The second is refused before
// it can reconcile the live first broker's operations into failure.
func TestSecondBrokerRefused(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	mk := func(sock string) (*Daemon, error) {
		return New(Config{
			DBPath:      filepath.Join(dir, "m.db"),
			SocketPath:  filepath.Join(dir, sock),
			AdminSocket: filepath.Join(dir, sock+".admin"),
			VaultType:   "memory-test",
		})
	}
	first, err := mk("a.sock")
	if err != nil {
		t.Fatalf("first broker: %v", err)
	}
	defer first.Shutdown()
	if _, err := mk("b.sock"); err == nil {
		t.Fatal("second broker on the same database started")
	}
}

// P1-2: a second broker through a pathname alias to the same database
// is refused — alias spellings never yield a second ownership.
func TestSecondBrokerViaAliasRefused(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "m.db")
	first, err := New(Config{
		DBPath:      real,
		SocketPath:  filepath.Join(dir, "a.sock"),
		AdminSocket: filepath.Join(dir, "a.sock.admin"),
		VaultType:   "memory-test",
	})
	if err != nil {
		t.Fatalf("first broker: %v", err)
	}
	defer first.Shutdown()
	alias := filepath.Join(dir, "alias.db")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{
		DBPath:      alias,
		SocketPath:  filepath.Join(dir, "b.sock"),
		AdminSocket: filepath.Join(dir, "b.sock.admin"),
		VaultType:   "memory-test",
	}); err == nil {
		t.Fatal("alias-path broker acquired a second ownership")
	}
}

// P1-5: shutdown with a worker that will not stop is a loud failure,
// not a graceful result — and the database lease is retained so no
// successor can reconcile the still-live work as its own.
func TestShutdownTimeoutRetainsLease(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	old := shutdownWorkerTimeout
	shutdownWorkerTimeout = 50 * time.Millisecond
	defer func() { shutdownWorkerTimeout = old }()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	mk := func(sock string) (*Daemon, error) {
		return New(Config{
			DBPath:      filepath.Join(dir, "m.db"),
			SocketPath:  filepath.Join(dir, sock),
			AdminSocket: filepath.Join(dir, sock+".admin"),
			VaultType:   "memory-test",
		})
	}
	d, err := mk("a.sock")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a worker stuck in external I/O, ignoring cancellation.
	d.workerWg.Add(1)
	d.worker = func() {}
	defer func() {
		d.workerWg.Done()
		_ = d.svc.Close()
		d.lease.Release()
	}()
	if err := d.Shutdown(); err == nil {
		t.Fatal("shutdown reported graceful with a live worker")
	}
	// The lease is still held: no successor may start.
	if _, err := mk("b.sock"); err == nil {
		t.Fatal("successor started while the old worker is still live")
	}
}

// QR-02: the broker serves the trusted intake domain on its own
// owner-only socket alongside agent and admin.
func TestIntakeSocketServed(t *testing.T) {
	if sandboxAncestorUntrusted() {
		t.Skip("sandbox reports an untrusted ancestor; Unix socket fixture needs trusted ancestors")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{
		DBPath:     filepath.Join(dir, "m.db"),
		SocketPath: filepath.Join(dir, "a.sock"),
		VaultType:  "memory-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	st, err := os.Stat(filepath.Join(dir, "a.sock.intake"))
	if err != nil {
		t.Fatalf("intake socket missing: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("intake socket mode = %o, want 0600", perm)
	}
	// Default identity wiring: with no explicit UID lists, the
	// broker's own user reaches the intake domain (regression: an
	// intake default resolved before admin defaults denied everyone).
	cli, err := ipc.Dial(filepath.Join(dir, "a.sock.intake"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Call(ipc.MethodHealth, nil); err != nil {
		t.Fatalf("intake health denied: %v", err)
	}
	health, err := cli.Call(ipc.MethodHealth, nil)
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := health.(map[string]interface{}); !ok || data["assurance_mode"] != AssuranceBestEffort {
		t.Fatalf("default deployment overstated assurance: %#v", health)
	}
}

func TestIsolatedAssuranceRejectsUIDOverlap(t *testing.T) {
	valid := Config{
		AssuranceMode: AssuranceIsolated,
		AdminUIDs:     []uint32{100},
		IntakeUIDs:    []uint32{100},
		AgentUIDs:     []uint32{200},
	}
	if err := validateIsolationTopology(valid, 100); err != nil {
		t.Fatalf("valid dedicated broker/agent topology refused: %v", err)
	}
	separateHuman := valid
	separateHuman.IntakeUIDs = []uint32{300}
	separateHuman.IntakeGroup = "seqpass-intake"
	if err := validateIsolationTopology(separateHuman, 100); err != nil {
		t.Fatalf("valid separate intake identity/group refused: %v", err)
	}
	separateHuman.IntakeGroup = separateHuman.SocketGroup
	if err := validateIsolationTopology(separateHuman, 100); err == nil {
		t.Fatal("isolated mode accepted the agent group for trusted intake")
	}

	shared := valid
	shared.AgentUIDs = []uint32{100}
	if err := validateIsolationTopology(shared, 100); err == nil {
		t.Fatal("isolated mode accepted broker/agent UID overlap")
	}
	shared = valid
	shared.AgentUIDs = []uint32{200}
	shared.IntakeUIDs = []uint32{200}
	if err := validateIsolationTopology(shared, 100); err == nil {
		t.Fatal("isolated mode accepted agent/intake UID overlap")
	}
	shared = valid
	shared.AdminUIDs = []uint32{300}
	if err := validateIsolationTopology(shared, 100); err == nil {
		t.Fatal("isolated mode accepted an admin UID that cannot access owner-only socket")
	}
	shared = valid
	shared.IntakeUIDs = []uint32{300}
	if err := validateIsolationTopology(shared, 100); err == nil {
		t.Fatal("isolated mode accepted a separate intake UID without a protected intake group")
	}
}

// C14: the broker requires an explicit vault type; nothing is silently
// defaulted to an ephemeral store.
func TestDaemonRequiresExplicitVault(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		DBPath:     filepath.Join(dir, "m.db"),
		SocketPath: filepath.Join(dir, "b.sock"),
	})
	if err == nil {
		t.Fatal("daemon accepted an empty vault type")
	}
}
