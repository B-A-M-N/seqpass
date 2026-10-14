#!/bin/sh
export TMPDIR="$PWD/.tmp/tmp"
export GOCACHE="$PWD/.tmp/go-build"
mkdir -p "$GOCACHE" "$TMPDIR"
chmod 700 "$TMPDIR"
exec go test "$@"
