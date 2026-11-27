# Architecture & Record Format

## Record Format (`pin-vault3`)

Each entry is stored at `~/.local/share/pin-vault/<name>.bin` (directory mode `0700`, file mode `0600`).

Inside the outer machine-bound wrapper and `AES-256-CBC` encryption, a `pin-vault3` payload contains 5 newline-delimited fields:

1. `pin-vault3` (format header)
2. `receiver` (optional command line executed on `unlock`)
3. `base64(value)` (single-line base64 of up to 64 KiB raw secret bytes, preserving newlines)
4. `base64(note)` (optional one-line note)
5. `sha256` (hex digest of lines 1–4)

### Backward Compatibility

Earlier `pin-vault2` (no note field; digest over 3 lines) and `pin-vault1` (plain one-line secret) files remain readable and upgrade automatically to `pin-vault3` on `update` or `repin`.

## Cryptographic & Process Hygiene

- **Key derivation:** `PBKDF2` with `600,000` iterations (`openssl enc -aes-256-cbc -pbkdf2 -iter 600000`).
- **Integrity before execution:** Because `openssl enc` has no authenticated mode and passing an HMAC key on the CLI would expose it in `ps`, integrity is verified via an inside-encryption `SHA-256` digest. `unlock` and `get` run a verification decrypt first and reject wrong PINs or tampered ciphertext before invoking any receiver.
- **No PIN stored on disk:** Not even a hash of the PIN is saved; successful decryption + digest verification is the proof.
- **No secrets in argv or env:** The PIN and secret pass into `openssl` over a dedicated file descriptor (`fd:3`), and `unlock` pipes the decrypted value to the receiver via `stdin`. The receiver command string is split and invoked directly (`"${argv[@]}"`) without `sh -c`.

## Outer Machine-Bound Layers

| Platform | Implementation | Mechanism |
| --- | --- | --- |
| macOS | `macos/keychain.sh` | Wraps blobs using a 256-bit random key in the login Keychain (`PIN_VAULT_KEYCHAIN_SERVICE`, default `pin-vault`). |
| Windows / WSL | `windows/dpapi.sh` | Wraps blobs with Windows DPAPI (`CurrentUser` scope) via `powershell.exe`. |
| Custom / Linux | `PIN_VAULT_WRAP` | Any executable implementing `wrap` and `unwrap` over `stdin`/`stdout`. |
