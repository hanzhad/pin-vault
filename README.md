# pin-vault

One PIN, every token a machine needs handed over after a reboot. Each entry is
stored as `~/.local/share/pin-vault/<name>.bin` (folder mode `0700`), holding the
receiver command (optional), the secret value (up to 64 KiB, single-line or
multi-line), and an optional one-line note, all encrypted under AES-256-CBC with
PBKDF2 (`600000` iterations) and wrapped with a machine-bound outer layer.

Without the PIN only entry names are visible (`pin-vault status`). The PIN is
never stored; a record's SHA-256 integrity digest inside the encryption verifies
the PIN and catches any tampering before a receiver runs.

## Record format & outer layers

- **Format:** `pin-vault3` (`pin-vault3`, receiver, `base64(value)`,
  `base64(note)`, `sha256`). Earlier `pin-vault2` and `pin-vault1` files remain
  readable and upgrade to `pin-vault3` on `update` or `repin`.
- **macOS (`macos/keychain.sh`):** wraps blobs using a 256-bit random key in
  the login Keychain under service `PIN_VAULT_KEYCHAIN_SERVICE` (defaults to
  `pin-vault`).
- **Windows/WSL (`windows/dpapi.sh`):** wraps blobs with Windows DPAPI
  (`CurrentUser` scope) via `powershell.exe` over WSL interop.
- **Custom/Test (`PIN_VAULT_WRAP`):** override outer layer with any executable
  supporting `wrap` and `unwrap` over stdin/stdout (`PIN_VAULT_HOME`,
  `PIN_VAULT_INPUT_FD`, and `PIN_VAULT_KEY_FD` support automated testing).

## Commands

| command | what it does |
| --- | --- |
| `add <name> [--stdin] [--receiver <command>] [--note <text>]` | Store a new entry. Prompts for receiver, note, and hidden token (or reads raw bytes from stdin with `--stdin`). |
| `get [name]` | Decrypt and output the exact value (plus note on stderr when piped, or alternate screen on a TTY). Interactive menu when `name` is omitted. |
| `update [name] [--receiver <cmd> | --note <text> | --token [--stdin]]` | Update one part of an entry while preserving the other two byte-for-byte. |
| `remove <name>` | Delete an entry after verifying the PIN. |
| `status` | List stored entry names without asking for a PIN. |
| `unlock [name]` | Ask the PIN once and pipe each matching entry's value to its receiver command on stdin. |
| `repin` | Re-encrypt every entry in the vault under a new PIN atomically via temporary files. |

## Installation

```sh
ln -s /path/to/pin-vault/pin-vault ~/.local/bin/pin-vault
```

On Windows/WSL, register the logon unlock window from PowerShell:

```powershell
.\windows\install-logon-task.ps1 -InstallDir ~/Projects/pin-vault
```
