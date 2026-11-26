#!/usr/bin/env bash
#
# The outer layer of pin-vault's files on a mac: the counterpart of
# windows/dpapi.sh. `wrap` reads bytes on stdin and writes the protected blob;
# `unwrap` the reverse.
#
# The Keychain stores secrets rather than encrypting streams, so the layer is a
# random 256-bit key kept in the login Keychain and an AES pass under it. The
# property is DPAPI's: the blob is useless copied off this machine or opened
# under another account, so the PIN inside can only be tried here, as this
# user.
#
# One key serves every file. `wrap` reads the key from the Keychain and mints
# one only when there is none, so a second token never unseats the first, and
# there is no moment at which an older blob is unreadable because a newer key
# replaced its key. Minting uses `add` without `-U`: if another `wrap` got
# there first the add fails and the key that is there is read back.
# PIN_VAULT_KEYCHAIN_SERVICE defaults to `pin-vault` and can be overridden
# when opening blobs wrapped under an existing Keychain service name.
#
# `-iter 1000` here against the 600000 on the PIN is deliberate, not a
# leftover. That one stretches a PIN — a small secret whose only defence is
# being slow to guess. This one stretches a 256-bit random key, where stretching
# buys nothing an attacker cannot already skip. Raising it would cost time and
# add no security.
#
# The key reaches `security` through its interactive mode on stdin and reaches
# openssl on a file descriptor — never as an argument.
set -euo pipefail
service=${PIN_VAULT_KEYCHAIN_SERVICE:-pin-vault}
account=$(id -un)

find_key() { security find-generic-password -s "$service" -a "$account" -w 2>/dev/null; }

case "${1:-}" in
  wrap)
    if ! key=$(find_key); then
      key=$(openssl rand -hex 32)
      printf 'add-generic-password -s %s -a %s -w %s\n' "$service" "$account" "$key" | security -i >/dev/null 2>&1 || true
      key=$(find_key) || { echo "✗ could not store a key in the login Keychain — is it unlocked?" >&2; exit 69; }
    fi
    openssl enc -aes-256-cbc -pbkdf2 -iter 1000 -md sha256 -salt -pass fd:3 3< <(printf '%s' "$key")
    ;;
  unwrap)
    key=$(find_key) \
      || { echo "✗ no key in the login Keychain — a file wrapped with it cannot be opened; delete that file from the pin-vault folder, then pin-vault add stores it again" >&2; exit 69; }
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000 -md sha256 -pass fd:3 3< <(printf '%s' "$key")
    ;;
  *) echo "usage: keychain.sh wrap|unwrap  (bytes on stdin)" >&2; exit 64 ;;
esac
