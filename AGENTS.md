# Agent Rules (hanzhad/pin-vault)

- **Workflow:** Work on a feature branch, open a pull request with full context, and ensure CI (`test` + `scan`) passes before merging.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`).
- **Public safety:** Every change must pass `python3 scripts/scan.py --tree .` and `python3 scripts/scan.py --history`. Never commit tokens, credentials, personal emails, private repo references, or host-specific home paths.
- **Dependencies:** Keep runtime dependencies minimal (Bash >= 3.2, `openssl`, `awk`, `base64`, Python 3 stdlib for tooling) and portable across macOS, Windows/WSL, and Linux (via `PIN_VAULT_WRAP`).
