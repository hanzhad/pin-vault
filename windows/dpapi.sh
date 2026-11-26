#!/usr/bin/env bash
#
# The outer layer of pin-vault's files, on a Windows host: DPAPI, via
# powershell.exe over WSL interop. `wrap` reads bytes on stdin and writes the
# protected blob; `unwrap` the reverse. The key is derived from the Windows
# logon and never written anywhere — the blob is useless copied off this
# machine or opened under another account.
#
# This is what makes a short PIN acceptable in pin-vault: without it, a
# copied blob could be brute-forced offline at leisure; with it, the only place
# the PIN can be tried is here, as this user.
#
# Bytes cross as base64 on stdin/stdout so that neither PowerShell's console
# encoding nor a stray newline can alter them. Nothing is passed as an
# argument.
set -euo pipefail

ps=$(command -v powershell.exe 2>/dev/null || true)
[ -n "$ps" ] || ps=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
[ -x "$ps" ] || { echo "✗ powershell.exe not reachable — WSL interop is off?" >&2; exit 69; }

case "${1:-}" in
  wrap)   op=Protect ;;
  unwrap) op=Unprotect ;;
  *) echo "usage: dpapi.sh wrap|unwrap  (bytes on stdin)" >&2; exit 64 ;;
esac

script='
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$in = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
$out = [Security.Cryptography.ProtectedData]::'"$op"'($in, $null, "CurrentUser")
[Console]::Out.Write([Convert]::ToBase64String($out))
'
base64 -w0 | "$ps" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$script" | tr -d '\r\n' | base64 -d
