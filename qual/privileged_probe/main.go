//go:build linux

// Package main is a small OS-identity probe used only by TestQualPrivileged.
// It has no project imports so it can run independently as the agent UID.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

type result struct {
	EffectiveUID       uint32            `json:"effective_uid"`
	EffectiveGID       uint32            `json:"effective_gid"`
	Groups             []uint32          `json:"supplementary_gids"`
	AssuranceMode      string            `json:"assurance_mode,omitempty"`
	HealthOK           bool              `json:"health_ok"`
	AdminMethodDenied  bool              `json:"admin_method_denied"`
	AegisSocketConnect bool              `json:"aegis_socket_connect,omitempty"`
	SocketDenied       map[string]string `json:"socket_denial"`
	FileUnreadable     map[string]string `json:"file_denial"`
	Errors             []string          `json:"errors,omitempty"`
}

func main() {
	gids, _ := os.Getgroups()
	groups := make([]uint32, 0, len(gids))
	for _, gid := range gids {
		groups = append(groups, uint32(gid))
	}
	out := result{
		EffectiveUID: uint32(os.Geteuid()), EffectiveGID: uint32(os.Getegid()), Groups: groups,
		SocketDenied: map[string]string{}, FileUnreadable: map[string]string{},
	}
	if len(os.Args) < 2 {
		out.Errors = append(out.Errors, "missing probe mode")
	} else {
		switch os.Args[1] {
		case "ipc":
			if err := probeIPC(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "trusted IPC probe failed")
				os.Exit(2)
			}
			return
		case "service":
			probeService(&out, os.Args[2:])
		case "agent":
			probeAgent(&out, os.Args[2:])
		default:
			out.Errors = append(out.Errors, "unknown probe mode")
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if len(out.Errors) != 0 || !out.AegisSocketConnect && len(os.Args) > 1 && os.Args[1] == "service" || len(os.Args) > 1 && os.Args[1] == "agent" && (!out.HealthOK || !out.AdminMethodDenied) {
		os.Exit(2)
	}
}

// probeIPC is a small independent client for trusted test-side requests. Its
// request body comes from stdin so a synthetic credential never appears in
// argv or environment; it is invoked only under the configured service UID.
func probeIPC(args []string) error {
	if len(args) != 2 {
		return errors.New("bad IPC arguments")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return err
	}
	params := map[string]interface{}{}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return errors.New("invalid IPC params")
		}
	}
	conn, err := dial(args[0])
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := map[string]interface{}{"id": "qual-trusted", "method": args[1], "params": params}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(line)
	return err
}

func probeService(out *result, args []string) {
	if len(args) != 2 {
		out.Errors = append(out.Errors, "bad service arguments")
		return
	}
	want, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || out.EffectiveUID != uint32(want) {
		out.Errors = append(out.Errors, "service UID mismatch")
	}
	conn, err := dial(args[1])
	if err != nil {
		out.Errors = append(out.Errors, "service cannot connect to AegisKeys socket")
		return
	}
	out.AegisSocketConnect = true
	_ = conn.Close()
}

func probeAgent(out *result, args []string) {
	if len(args) < 8 || len(args) > 9 {
		out.Errors = append(out.Errors, "bad agent arguments")
		return
	}
	want, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || out.EffectiveUID != uint32(want) {
		out.Errors = append(out.Errors, "agent UID mismatch")
	}
	response, err := call(args[1], "health")
	if err != nil {
		out.Errors = append(out.Errors, "agent health call failed")
	} else if response["ok"] == true {
		data, _ := response["data"].(map[string]interface{})
		out.AssuranceMode, _ = data["assurance_mode"].(string)
		out.HealthOK = data["status"] == "ok"
	}
	adminResponse, err := call(args[1], "ops.pending")
	if err == nil {
		out.AdminMethodDenied = adminResponse["ok"] == false && adminResponse["error"] == "access denied"
	}
	for name, path := range map[string]string{"admin": args[2], "intake": args[3], "aegiskeys": args[4]} {
		conn, err := dial(path)
		if conn != nil {
			_ = conn.Close()
		}
		out.SocketDenied[name] = denialClass(err)
		if !permissionDenied(out.SocketDenied[name]) {
			out.Errors = append(out.Errors, "socket access was not denied: "+name)
		}
	}
	fileTargets := map[string]string{"aegiskeys_vault": args[5], "aegiskeys_metadata": args[6], "seqpass_db": args[7]}
	if len(args) == 9 {
		fileTargets["trusted_payload"] = args[8]
	}
	for name, path := range fileTargets {
		file, err := os.Open(path)
		if file != nil {
			_ = file.Close()
		}
		out.FileUnreadable[name] = denialClass(err)
		if !permissionDenied(out.FileUnreadable[name]) {
			out.Errors = append(out.Errors, "file access was not denied: "+name)
		}
	}
}

func call(path, method string) (map[string]interface{}, error) {
	conn, err := dial(path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "{\"id\":\"qual\",\"method\":%q}\n", method); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var response map[string]interface{}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func dial(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 2*time.Second)
}

func denialClass(err error) string {
	if errors.Is(err, syscall.EACCES) {
		return "EACCES"
	}
	if errors.Is(err, syscall.EPERM) {
		return "EPERM"
	}
	if err == nil {
		return "connected"
	}
	return "other"
}

func permissionDenied(value string) bool {
	return value == "EACCES" || value == "EPERM"
}
