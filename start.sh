#!/bin/sh
# Linux / macOS launcher
cd "$(dirname "$0")"
[ -d node_modules ] || npm install --omit=dev
node server.js
