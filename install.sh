#!/usr/bin/env bash
# Alias → install-and-start.sh (All-in-One: System-Deps + venv + pip + Start).
exec "$(cd "$(dirname "$0")" && pwd)/install-and-start.sh" "$@"
