# Custom Outer Wrapper (`PIN_VAULT_WRAP`)

On native Linux or headless hosts without macOS Keychain or Windows DPAPI, set `PIN_VAULT_WRAP` to an executable that implements `wrap` and `unwrap` subcommands over `stdin` / `stdout`.

## Contract

- `pin-vault` calls `"$PIN_VAULT_WRAP" wrap` when writing a `.bin` entry:
  - **stdin:** ciphertext bytes from `openssl`
  - **stdout:** wrapped bytes to write to `~/.local/share/pin-vault/<name>.bin`
- `pin-vault` calls `"$PIN_VAULT_WRAP" unwrap` when reading a `.bin` entry:
  - **stdin:** contents of `~/.local/share/pin-vault/<name>.bin`
  - **stdout:** raw ciphertext bytes for `openssl`
- Non-zero exit aborts the operation without exposing or executing the receiver.

## Example: Linux Secret Service (`secret-tool`)

Store a 32-byte machine key in your desktop keyring once:

```sh
head -c 32 /dev/urandom | base64 | secret-tool store --label="pin-vault outer key" service pin-vault account outer
```

Then point `PIN_VAULT_WRAP` at a small wrapper script:

```sh
#!/usr/bin/env bash
set -euo pipefail
key="$(secret-tool lookup service pin-vault account outer)"
case "${1:-}" in
  wrap)   exec openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -pass "pass:$key" ;;
  unwrap) exec openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass "pass:$key" ;;
  *)      exit 64 ;;
esac
```

For headless servers, `systemd-creds encrypt` / `decrypt` works with the same `wrap`/`unwrap` interface.

## Test & Automation Environment Variables

- `PIN_VAULT_HOME` — override `~/.local/share/pin-vault` storage directory.
- `PIN_VAULT_WRAP` — override platform outer-layer detection.
- `PIN_VAULT_INPUT_FD` — read scripted input lines from an open file descriptor instead of `/dev/tty` (used by `tests/test-pin-vault.sh`).
- `PIN_VAULT_KEY_FD` — read arrow-key navigation bytes from an open file descriptor in tests.
