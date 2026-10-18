package isolation

import (
	"os"
	"syscall"
	"time"
)

// SocketFact is the observed identity and permission of one protected
// socket.
type SocketFact struct {
	Path   string      `json:"path"`
	Exists bool        `json:"exists"`
	UID    uint32      `json:"uid"`
	GID    uint32      `json:"gid"`
	Mode   os.FileMode `json:"mode"`
}

// Fingerprint is a point-in-time observation of the security-relevant
// topology. Comparing two fingerprints detects drift: a changed effective
// identity, a socket that vanished, or a socket whose owner/permissions no
// longer match what was verified at startup.
type Fingerprint struct {
	CapturedAt time.Time    `json:"captured_at"`
	EUID       uint32       `json:"euid"`
	EGID       uint32       `json:"egid"`
	Sockets    []SocketFact `json:"sockets"`
}

// CaptureFingerprint observes the current identity and socket facts.
func CaptureFingerprint(euid, egid uint32, paths []string) Fingerprint {
	fp := Fingerprint{CapturedAt: time.Now().UTC(), EUID: euid, EGID: egid}
	for _, p := range paths {
		fp.Sockets = append(fp.Sockets, socketFact(p))
	}
	return fp
}

func socketFact(path string) SocketFact {
	fact := SocketFact{Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		return fact
	}
	fact.Exists = true
	fact.Mode = fi.Mode().Perm()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fact.UID = st.Uid
		fact.GID = st.Gid
	}
	return fact
}

// Drift compares a previously verified fingerprint with the current one and
// returns a non-empty, human-readable list of security-relevant changes. An
// empty result means the boundary is unchanged.
func (prev Fingerprint) Drift(now Fingerprint) []string {
	var drift []string
	if prev.EUID != now.EUID {
		drift = append(drift, "effective uid changed")
	}
	if prev.EGID != now.EGID {
		drift = append(drift, "effective gid changed")
	}
	index := map[string]SocketFact{}
	for _, s := range prev.Sockets {
		index[s.Path] = s
	}
	for _, s := range now.Sockets {
		before, seen := index[s.Path]
		if !seen {
			continue
		}
		switch {
		case before.Exists && !s.Exists:
			drift = append(drift, "protected socket disappeared: "+s.Path)
		case before.Exists && s.Exists && (before.UID != s.UID || before.GID != s.GID):
			drift = append(drift, "protected socket ownership changed: "+s.Path)
		case before.Exists && s.Exists && before.Mode != s.Mode:
			drift = append(drift, "protected socket permissions changed: "+s.Path)
		}
	}
	return drift
}
