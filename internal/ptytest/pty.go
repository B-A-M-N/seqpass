// Package ptytest opens BSD-style ptys with pure syscalls (no new
// dependencies) so F06 regression tests can drive hidden terminal input,
// cancellation, terminal restore and session recording without a human.
package ptytest

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// termios mirrors the full struct termios layout (60 bytes: four flag
// words, line discipline, 32 control chars, two speeds) so TCGETS/TCSETS
// round-trip every field instead of reading past a short struct.
type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [32]uint8
	Ispeed uint32
	Ospeed uint32
}

// tcgets reads the line discipline flags of fd.
func tcgets(fd uintptr) (termios, error) {
	var t termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd,
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return t, errno
	}
	return t, nil
}

// EchoOn reports whether the ECHO flag is set on fd.
func EchoOn(f *os.File) (bool, error) {
	t, err := tcgets(f.Fd())
	if err != nil {
		return false, err
	}
	return t.Lflag&syscall.ECHO != 0, nil
}

// PTY is one master/slave pair. The test drives Master; the code under
// test owns Slave (passed as *os.File, like /dev/tty would be).
type PTY struct {
	Master *os.File
	Slave  *os.File
	Name   string
	ch     chan []byte
}

// Open allocates a pty pair via /dev/ptmx.
func Open() (*PTY, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open ptmx: %w", err)
	}
	closeOnErr := func() { _ = master.Close() }
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		closeOnErr()
		return nil, fmt.Errorf("TIOCGPTN: %w", errno)
	}
	var lck int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&lck))); errno != 0 {
		closeOnErr()
		return nil, fmt.Errorf("TIOCSPTLCK: %w", errno)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	slave, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		closeOnErr()
		return nil, fmt.Errorf("open slave %s: %w", name, err)
	}
	p := &PTY{Master: master, Slave: slave, Name: name, ch: make(chan []byte, 64)}
	p.startReader()
	return p, nil
}

// Close releases both ends.
func (p *PTY) Close() {
	if p.Master != nil {
		_ = p.Master.Close()
	}
	if p.Slave != nil {
		_ = p.Slave.Close()
	}
}

// SetRawISIGOff clears ISIG on the slave so a Ctrl+C byte arrives as data
// (in production cooked mode it raises SIGINT instead). Used to exercise
// the explicit Ctrl+C-byte cancellation branch.
func (p *PTY) SetRawISIGOff() error {
	fd := p.Slave.Fd()
	t, err := tcgets(fd)
	if err != nil {
		return err
	}
	t.Lflag &^= uint32(syscall.ISIG)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd,
		uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// startReader pumps the master stream into ch with a blocking Go Read
// (proven to deliver on ptmx). Polling tricks are avoided on purpose:
// read deadlines do not interrupt ptmx reads and O_NONBLOCK cannot be
// set on ptmx in this environment, so waiting happens in select below —
// never inside a read. Closing the pty ends the reader via EIO.
func (p *PTY) startReader() {
	go func() {
		defer close(p.ch)
		buf := make([]byte, 4096)
		for {
			n, err := p.Master.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
			p.ch <- cp
			}
			if err != nil {
				return
			}
		}
	}()
}

// ReadAvailable drains whatever the master can deliver within wait,
// returning the raw transcript (what a session recording would capture).
func (p *PTY) ReadAvailable(wait time.Duration) []byte {
	return p.WaitFor("\x00-never-present-\xff", wait)
}

// WaitFor blocks until marker appears in the master stream or timeout
// elapses, returning everything seen so far.
func (p *PTY) WaitFor(marker string, timeout time.Duration) []byte {
	var out []byte
	need := []byte(marker)
	deadline := time.Now().Add(timeout)
	for {
		select {
		case chunk, ok := <-p.ch:
			if !ok {
				return out
			}
			out = append(out, chunk...)
			if contains(out, need) {
				return out
			}
		case <-time.After(time.Until(deadline)):
			return out
		}
	}
}

func contains(hay, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
