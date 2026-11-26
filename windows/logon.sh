#!/usr/bin/env bash
#
# What the Windows logon task opens a window for: asks for the PIN and runs
# `pin-vault unlock`, and nothing else. It does not wait for anything and does
# not look at what the receivers do with their tokens: a receiver that has to
# wait does it in a process of its own. Success closes the window. A failure
# stays open showing what pin-vault said until a key is pressed, and exits
# non-zero. With nothing in the vault there is no PIN to ask: it says so and
# closes.
#
# The task runs `wsl --exec` with no ~/.profile, so pin-vault is not on PATH
# unless it is linked there; the copy it ships with is found from here.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)

vault=${PIN_VAULT_HOME:-$HOME/.local/share/pin-vault}
if ! compgen -G "$vault/*.bin" >/dev/null; then
  echo "pin-vault: the vault is empty, nothing to unlock. pin-vault add <name> stores a token."
  sleep 3
  exit 0
fi

if command -v pin-vault >/dev/null 2>&1; then pv=pin-vault
else pv=$here/../pin-vault; fi

"$pv" unlock
rc=$?
if [ "$rc" -ne 0 ]; then
  printf '\npin-vault unlock failed (exit %s). Press enter to close.\n' "$rc"
  read -r _ || true
  exit "$rc"
fi
