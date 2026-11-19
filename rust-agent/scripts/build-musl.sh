#!/usr/bin/env sh
set -eu

TARGET="x86_64-unknown-linux-musl"

if command -v rustup >/dev/null 2>&1; then
    rustup target add "$TARGET" >/dev/null 2>&1 || true
fi

cargo build --release --target "$TARGET"

BIN="target/$TARGET/release/x-ui-agent-rs"
ls -lh "$BIN"
file "$BIN" || true
