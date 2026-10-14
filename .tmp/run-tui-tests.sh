#!/bin/sh
export TMPDIR="$PWD/.tmp/tmp"
export GOFLAGS=-mod=mod
export GOCACHE="$PWD/.tmp/go-build"
mkdir -p "$GOCACHE" "$TMPDIR"
chmod 1777 "$TMPDIR"
chmod 700 .tmp
go test ./internal/tui "$@"
