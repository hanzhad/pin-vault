#!/usr/bin/env bash
# pin-vault end-to-end test suite through the command with
# a fake outer layer: a reversible byte rotation stands in for DPAPI, a fake
# `security` for the Keychain. Every token and PIN below is made up here.
#
# Seams the tool must honour, all variables that carry no secret:
#   PIN_VAULT_HOME      the data folder (the real one is ~/.local/share/pin-vault)
#   PIN_VAULT_WRAP      the outer layer: a program with `wrap` and `unwrap`
#   PIN_VAULT_INPUT_FD  a file descriptor number; when set, every prompt reads
#                       one line from it, in prompt order, instead of /dev/tty
#   PIN_VAULT_KEY_FD    a file descriptor number; when set, `get` with no name
#                       shows the arrow-key menu, reads raw keys from it and
#                       draws on stderr instead of /dev/tty. The PIN still comes
#                       from PIN_VAULT_INPUT_FD when that is set too
# Prompt order: add, first run: PIN, PIN again, receiver, note, token; later:
# PIN, receiver, note, token (an empty note line means none). get, unlock,
# update, remove, repin: PIN first. update with no flag asks with the menu what
# to change (token, receiver, note), then for the new value.
#
# Multi-line values, the behaviour the checks below pin:
#   add <name> --stdin  the value is all of stdin, byte for byte (trailing and
#                       inner newlines kept, whitespace not stripped). The PIN
#                       and receiver questions are asked as for any add, the
#                       token question is not. Empty stdin, or more than 64 KiB
#                       (65536 bytes is allowed), is refused and stores nothing.
#                       Without --stdin, add is as before: one hidden line,
#                       whitespace stripped, stdin ignored
#   pin-vault1 files    open under get, unlock, update and repin, are not
#                       rewritten by reading, and a store makes them 3
#
# Notes and update:
#   pin-vault3 records  every write (add, update, repin)
#                       makes   pin-vault3, receiver, base64(value),
#                       base64(note), sha256   as five lines, the note line
#                       empty for none, the digest over the first four, all
#                       inside the encryption. pin-vault2 files read as an
#                       entry with no note, are not rewritten by reading
#   update <name>       one part changes, the others come back byte for byte:
#                       --receiver <command>, --note <text> (empty removes),
#                       --token (hidden prompt, or all of stdin with --stdin).
#                       Only the PIN is asked when a flag is given; with none,
#                       the arrow menu. Two part flags, or --stdin without
#                       --token, refuse before the PIN. edit is gone
#   add                 refuses an existing name before the PIN, naming update;
#                       takes --note <text>, which skips the note question
#   get                 a note shows with the value: on stderr in a pipe, so
#                       stdout stays the exact value
#   get, unlock         deliver the exact bytes; a typed token has no newline
#   the value, encoded or not, is in no argument or environment of any process
#   the tool starts, base64 included
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
PV=$here/pin-vault
KEYCHAIN=$here/macos/keychain.sh
LOGON=$here/windows/logon.sh
INSTALL_LOGON=$here/windows/install-logon-task.ps1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
REAL_OPENSSL=$(command -v openssl)

ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; fail=1; }
# A check that expects a refusal holds trivially when the tool is absent, so
# every check but the ones about other scripts first needs the tool to exist.
NO_PV=0
assert() {
  local l=$1; shift
  if [ "$NO_PV" = 0 ] && [ ! -x "$PV" ]; then bad "$l (no pin-vault)"; return; fi
  if "$@" 2>/dev/null; then ok "$l"; else bad "$l"; fi
}

mkdir -p "$tmp/bin" "$tmp/spy"
# Fake outer layer: rotate every byte by one. Reversible, binary-safe, and a
# flipped byte in the file reaches the inner layer. Logs its own arguments and
# environment to $SPY_LOG when set, so a leak into a process the tool starts shows.
cat >"$tmp/wrap" <<'W'
#!/bin/sh
if [ -n "${SPY_LOG:-}" ]; then { echo "ARGS:$*"; tr '\0' '\n' </proc/$$/environ; } >>"$SPY_LOG"; fi
case "$1" in
  wrap)   tr '\000-\377' '\001-\377\000' ;;
  unwrap) tr '\001-\377\000' '\000-\377' ;;
  *) exit 64 ;;
esac
W
chmod +x "$tmp/wrap"
# Spy openssl: logs arguments and environment, then runs the real one.
cat >"$tmp/spy/openssl" <<W
#!/bin/sh
if [ -n "\${SPY_LOG:-}" ]; then { echo "ARGS:\$*"; tr '\0' '\n' </proc/\$\$/environ; } >>"\$SPY_LOG"; fi
exec $REAL_OPENSSL "\$@"
W
chmod +x "$tmp/spy/openssl"

home=$tmp/home
rc=0
fresh() { rm -rf "$home" "$tmp"/got.* "$tmp/ran.log"; : >"$tmp/ran.log"; }

# recv_ok <name>: writes stdin to $tmp/got.<name>. recv_fail <name>: reads it and exits 3.
recv_ok() { printf '#!/bin/sh\ncat > "%s/got.%s"\necho %s >> "%s/ran.log"\n' "$tmp" "$1" "$1" "$tmp" >"$tmp/bin/r-$1"; chmod +x "$tmp/bin/r-$1"; }
recv_fail() { printf '#!/bin/sh\ncat >/dev/null\necho %s >> "%s/ran.log"\necho "receiver %s refused" >&2\nexit 3\n' "$1" "$tmp" "$1" >"$tmp/bin/r-$1"; chmod +x "$tmp/bin/r-$1"; }
# A receiver that dumps what could leak: its own and its parent's and
# grandparent's arguments and environment.
recv_spy() {
  cat >"$tmp/bin/r-$1" <<S
#!/bin/sh
cat > "$tmp/got.$1"
for p in \$\$ \$PPID \$(awk '/^PPid/{print \$2}' /proc/\$PPID/status); do
  tr '\0' '\n' </proc/\$p/cmdline; tr '\0' '\n' </proc/\$p/environ
done >> "$tmp/spy.log"
S
  chmod +x "$tmp/bin/r-$1"
}
recv() { echo "$tmp/bin/r-$1"; }

# pv <input lines, \n separated> <args...>: runs the tool with the lines on fd 7.
pv() {
  local in=$1; shift
  printf '%b' "$in" >"$tmp/in"
  PIN_VAULT_HOME=$home PIN_VAULT_WRAP=$tmp/wrap PIN_VAULT_INPUT_FD=7 \
    timeout 120 "$PV" "$@" 7<"$tmp/in" >"$tmp/out" 2>"$tmp/err" </dev/null
  rc=$?
}
# pk <keys> <input lines> <args...>: like pv, with the menu's keys on fd 8, in
# printf %b form. Up is \033[A, Down \033[B, Enter \n.
pk() {
  local keys=$1 in=$2; shift 2
  printf '%b' "$keys" >"$tmp/keys"; printf '%b' "$in" >"$tmp/in"
  PIN_VAULT_HOME=$home PIN_VAULT_WRAP=$tmp/wrap PIN_VAULT_INPUT_FD=7 PIN_VAULT_KEY_FD=8 \
    timeout 120 "$PV" "$@" 7<"$tmp/in" 8<"$tmp/keys" >"$tmp/out" 2>"$tmp/err" </dev/null
  rc=$?
}
out() { cat "$tmp/out" 2>/dev/null; }
errs() { cat "$tmp/err" 2>/dev/null; }
# enroll <pin> <name> <receiver-or-empty> <token>: add, first run or later.
enroll() {
  if compgen -G "$home/*.bin" >/dev/null; then pv "$1\n$3\n\n$4\n" add "$2"
  else pv "$1\n$1\n$3\n\n$4\n" add "$2"; fi
}
tok() { printf '%s' "$(cat "$tmp/got.$1" 2>/dev/null)"; }
sum() { cat "$home"/*.bin 2>/dev/null | cksum; }
fsum() { [ -f "$1" ] && cksum <"$1"; }
# flip <file> <offset>: xor one byte with 1, in place.
flip() {
  local b; b=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "\$(printf %03o $((b ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
ranlog() { cat "$tmp/ran.log" 2>/dev/null; }

PIN=hunter22
T1=tok-alpha-1111
T2=tok-bravo-2222
T3=tok-charlie-3333

echo "== the tool exists =="
assert "pin-vault is an executable file" test -x "$PV"

echo "== production default is 600000; PIN_VAULT_TEST_ITER overrides for tests =="
unset PIN_VAULT_TEST_ITER
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
assert "prod default 600000: add exits 0" test "$rc" -eq 0 -a -f "$home/gate.bin"
pv "$PIN\n" get gate
assert "prod default 600000: get returns token" test "$rc" -eq 0 -a "$(out)" = "$T1"
pv "$PIN\n" unlock gate
assert "prod default 600000: unlock delivers token" test "$rc" -eq 0 -a "$(tok gate)" = "$T1"
assert "prod default 600000: ciphertext decrypts with -iter 600000" \
  bash -c '"$1" unwrap <"$2" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass fd:3 3< <(printf "%s" "$3") >/dev/null 2>&1' _ "$tmp/wrap" "$home/gate.bin" "$PIN"

for bad_iter in "" "abc" "0" "-5" "999"; do
  fresh; recv_ok gate
  PIN_VAULT_TEST_ITER="$bad_iter" enroll $PIN gate "$(recv gate)" $T1
  if [ "$rc" -eq 0 ]; then
    assert "invalid PIN_VAULT_TEST_ITER=$bad_iter: falls back to 600000" \
      bash -c '"$1" unwrap <"$2" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass fd:3 3< <(printf "%s" "$3") >/dev/null 2>&1' _ "$tmp/wrap" "$home/gate.bin" "$PIN"
  else
    assert "invalid PIN_VAULT_TEST_ITER=$bad_iter: rejected without storing" test ! -e "$home/gate.bin"
  fi
done

export PIN_VAULT_TEST_ITER=1000
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
assert "PIN_VAULT_TEST_ITER=1000: add exits 0" test "$rc" -eq 0 -a -f "$home/gate.bin"
assert "PIN_VAULT_TEST_ITER=1000: ciphertext decrypts with -iter 1000" \
  bash -c '"$1" unwrap <"$2" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000 -md sha256 -pass fd:3 3< <(printf "%s" "$3") >/dev/null 2>&1' _ "$tmp/wrap" "$home/gate.bin" "$PIN"
assert "PIN_VAULT_TEST_ITER=1000: ciphertext does not decrypt with -iter 600000" \
  bash -c '! ("$1" unwrap <"$2" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass fd:3 3< <(printf "%s" "$3") >/dev/null 2>&1)' _ "$tmp/wrap" "$home/gate.bin" "$PIN"

echo "== add =="
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
assert "add, first run: exits 0" test "$rc" -eq 0
assert "add: creates <name>.bin" test -f "$home/gate.bin"
assert "add: folder is mode 0700" test "$(stat -c %a "$home" 2>/dev/null)" = 700
assert "add: the file does not hold the token in the clear" test "$(grep -c -a -- "$T1" "$home/gate.bin" 2>/dev/null)" = 0
assert "add: the file does not hold the receiver path in the clear" test "$(grep -c -a -- "$(recv gate)" "$home/gate.bin" 2>/dev/null)" = 0
assert "add: nothing but <name>.bin files in the folder (no list, no config)" test -z "$(ls "$home" 2>/dev/null | grep -v '\.bin$')"

fresh
pv "abc12\nabc12\nrecv\n$T1\n" add gate
assert "add: a PIN under 6 characters is refused" test "$rc" -ne 0
assert "add: a refused PIN stores nothing" test ! -e "$home/gate.bin"
assert "add: the refusal says what to do next" test -n "$(errs)"
fresh
pv "hunter22\nhunter23\nrecv\n$T1\n" add gate
assert "add: two different PINs are refused" test "$rc" -ne 0
assert "add: differing PINs store nothing" test ! -e "$home/gate.bin"

fresh; recv_ok gate; recv_ok other
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN other "$(recv other)" $T2
assert "add, later run: asks the PIN once, then receiver and token" test "$rc" -eq 0 -a -f "$home/other.bin"
other_before=$(fsum "$home/other.bin")
gate_before=$(fsum "$home/gate.bin")
pv "wrongpin\n$(recv gate)\n\n$T3\n" add gate
assert "add on an existing name: refused, exit not 0" test "$rc" -ne 0
assert "add on an existing name: the refusal names update" test "$(errs | grep -c 'update')" -ge 1
assert "add on an existing name: refused before the PIN is asked" test "$(errs | grep -c -i -e 'wrong PIN' -e 'no PIN given')" -eq 0
assert "add on an existing name: changes nothing" test "$(fsum "$home/gate.bin")" = "$gate_before" -a "$(fsum "$home/other.bin")" = "$other_before"
pv "$PIN\n" get gate
assert "add on an existing name: the old token is still there" test "$(out)" = "$T1"
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
before=$(sum)
pv "wrongpin\n$(recv gate)\n$T2\n" add second
assert "add, later run: a wrong PIN is refused" test "$rc" -ne 0
assert "add, later run: a wrong PIN writes nothing" test "$(sum)" = "$before" -a ! -e "$home/second.bin"

echo "== get =="
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
pv "$PIN\n" get gate
assert "get into a pipe: the token on stdout" test "$(out)" = "$T1"
assert "get: exits 0" test "$rc" -eq 0
pv "wrongpin\n" get gate
assert "get: a wrong PIN prints no token" test -z "$(out | grep -- "$T1")" -a "$rc" -ne 0

echo "== get with no name: the arrow-key menu =="
fresh
enroll $PIN alpha "" $T1
enroll $PIN bravo "" $T2
enroll $PIN charlie "" $T3
CUR_OFF=$(printf '\033[?25l'); CUR_ON=$(printf '\033[?25h')
pk '\n' "$PIN\n" get
assert "menu: Enter alone picks the first entry" test "$(out)" = "$T1" -a "$rc" -eq 0
pk '\033[B\n' "$PIN\n" get
assert "menu: Down then Enter picks the second, in listing order" test "$(out)" = "$T2" -a "$rc" -eq 0
pk '\033OB\n' "$PIN\n" get
assert "menu: the O form of Down works too" test "$(out)" = "$T2"
pk '\033[B\033[B\n' "$PIN\n" get
assert "menu: Down twice picks the third" test "$(out)" = "$T3"
pk '\033[A\n' "$PIN\n" get
assert "menu: Up from the first wraps to the last" test "$(out)" = "$T3"
pk '\033[B\033[B\033[B\n' "$PIN\n" get
assert "menu: Down from the last wraps to the first" test "$(out)" = "$T1"
pk '\033[B\033[A\033[B\n' "$PIN\n" get
assert "menu: Up undoes Down" test "$(out)" = "$T2"
pk '\033[B\n' "$PIN\n" get
assert "menu: stdout carries only the token, the menu is on stderr" test "$(out)" = "$T2" -a "$(errs | grep -c bravo)" -ge 1
assert "menu: the cursor is hidden and restored" test "$(errs | grep -c -F "$CUR_OFF")" -ge 1 -a "$(errs | grep -c -F "$CUR_ON")" -ge 1
pk '\033' "$PIN\n" get
assert "menu: Esc cancels, non-zero, no PIN consumed, nothing on stdout" test "$rc" -ne 0 -a -z "$(out)"
assert "menu: Esc restores the cursor" test "$(errs | grep -c -F "$CUR_ON")" -ge 1
pk 'q' "$PIN\n" get
assert "menu: q cancels, non-zero, no PIN consumed, nothing on stdout" test "$rc" -ne 0 -a -z "$(out)"
pk '\033[B\003' "$PIN\n" get
assert "menu: Ctrl-C cancels too" test "$rc" -ne 0 -a -z "$(out)"
pk '' "$PIN\n" get
assert "menu: keys running out cancels" test "$rc" -ne 0 -a -z "$(out)"
pk '\033[B\n' "wrongpin\n" get
assert "menu: a wrong PIN after the pick still prints no token" test "$rc" -ne 0 -a -z "$(out)"
pk '\033[B\n' "$PIN\n" get charlie
assert "menu: a name on the command line skips the menu" test "$(out)" = "$T3"
pv "2\n$PIN\n" get
assert "numbered list: kept when PIN_VAULT_INPUT_FD is set alone" test "$(out)" = "$T2"

echo "== status =="
fresh; recv_ok gate; recv_ok engine
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
pv "" status
assert "status: exits 0 without a PIN" test "$rc" -eq 0
assert "status: lists every name" test "$(out | grep -c -w -e gate -e engine)" -ge 2
assert "status: names only, no token and no receiver" test -z "$(out | grep -e "$T1" -e "$T2" -e "$tmp/bin")"

echo "== unlock =="
fresh; recv_ok gate; recv_ok engine
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
enroll $PIN plain "" $T3
pv "$PIN\n" unlock
assert "unlock: exits 0 when every receiver took its token" test "$rc" -eq 0
assert "unlock: the PIN is typed once, each receiver gets its own token" test "$(tok gate)" = "$T1" -a "$(tok engine)" = "$T2"
assert "unlock: an entry with no receiver is skipped, without failing" test "$(ranlog | wc -l)" -eq 2
rm -f "$tmp"/got.*; : >"$tmp/ran.log"
pv "$PIN\n" unlock engine
assert "unlock <name>: only that entry" test "$(tok engine)" = "$T2" -a ! -e "$tmp/got.gate"

echo "== a failing receiver =="
fresh; recv_ok gate-a; recv_fail gate-b; recv_ok gate-c
enroll $PIN gate-a "$(recv gate-a)" $T1
enroll $PIN gate-b "$(recv gate-b)" $T2
enroll $PIN gate-c "$(recv gate-c)" $T3
pv "$PIN\n" unlock
assert "failing receiver: the next one still gets its token" test "$(tok gate-a)" = "$T1" -a "$(tok gate-c)" = "$T3"
assert "failing receiver: the failing one did run" test "$(ranlog | grep -c gate-b)" -eq 1
assert "failing receiver: exit code is not 0" test "$rc" -ne 0
assert "failing receiver: the failure is shown by name" test -n "$(out; errs)" -a "$( (out; errs) | grep -c gate-b)" -ge 1
pv "$PIN\n" unlock gate-b
assert "unlock <name> of a failing receiver: exit code is not 0" test "$rc" -ne 0

echo "== a wrong PIN, and a changed file =="
fresh; recv_ok gate; recv_ok engine
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
pv "$PIN\n" unlock
assert "control: the right PIN unlocks both" test "$rc" -eq 0 -a "$(ranlog | wc -l)" -eq 2
rm -f "$tmp"/got.*; : >"$tmp/ran.log"
before=$(sum)
pv "wrong-1\nwrong-2\nwrong-3\n$PIN\n" unlock
assert "three wrong PINs: the tool closes, exit code not 0" test "$rc" -ne 0
assert "three wrong PINs: no receiver ran, even with a fourth try on offer" test "$(ranlog | wc -l)" -eq 0
assert "three wrong PINs: the files are untouched" test "$(sum)" = "$before"
pv "wrong-1\n$PIN\n" unlock
assert "one wrong PIN, then the right one: unlocks" test "$rc" -eq 0 -a "$(ranlog | wc -l)" -eq 2
rm -f "$tmp"/got.*; : >"$tmp/ran.log"
pv "wrongpin\n" unlock gate
assert "wrong PIN: no receiver ran" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0

# One byte of the file changed, wherever it is: outer layer, salt, ciphertext,
# tail. Detected before any receiver runs, with the right PIN.
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
size=$([ -f "$home/gate.bin" ] && wc -c <"$home/gate.bin" || echo 0)
pv "$PIN\n" unlock gate
assert "control: the untouched file unlocks" test "$rc" -eq 0 -a "$(tok gate)" = "$T1"
cp "$home/gate.bin" "$tmp/gate.orig" 2>/dev/null
for off in 0 1 7 8 15 16 31 $((size / 2)) $((size - 17)) $((size - 2)) $((size - 1)); do
  [ "$off" -ge 0 ] && [ "$off" -lt "$size" ] || continue
  rm -f "$tmp"/got.*; : >"$tmp/ran.log"
  cp "$tmp/gate.orig" "$home/gate.bin" 2>/dev/null; flip "$home/gate.bin" "$off"
  pv "$PIN\n" unlock gate
  assert "flipped byte $off of $size: unlock fails, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0 -a ! -e "$tmp/got.gate"
  pv "$PIN\n" get gate
  assert "flipped byte $off of $size: get prints no token" test "$rc" -ne 0 -a -z "$(out | grep -- "$T1")"
done
head -c $((size - 1)) "$tmp/gate.orig" 2>/dev/null >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "truncated file: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"
{ cat "$tmp/gate.orig"; printf x; } 2>/dev/null >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "appended byte: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"

echo "== update --receiver =="
fresh; recv_ok gate; recv_ok gate2
enroll $PIN gate "$(recv gate)" $T1
pv "$PIN\n" update gate --receiver "$(recv gate2)"
assert "update --receiver: exits 0 on the PIN and the new receiver alone" test "$rc" -eq 0
pv "$PIN\n" unlock gate
assert "update --receiver: the token goes to the new receiver, not the old" test "$(tok gate2)" = "$T1" -a ! -e "$tmp/got.gate"
pv "$PIN\n" get gate
assert "update --receiver: the token is unchanged" test "$(out)" = "$T1"
after=$(fsum "$home/gate.bin")
pv "wrongpin\n" update gate --receiver "$(recv gate)"
assert "update --receiver: a wrong PIN is refused and changes nothing" test "$rc" -ne 0 -a "$(fsum "$home/gate.bin")" = "$after"

echo "== remove =="
fresh; recv_ok gate; recv_ok engine
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
keep=$(fsum "$home/engine.bin")
pv "wrongpin\n" remove gate
assert "remove: a wrong PIN keeps the file" test "$rc" -ne 0 -a -f "$home/gate.bin"
pv "$PIN\n" remove gate
assert "remove: exits 0 and deletes the file" test "$rc" -eq 0 -a ! -e "$home/gate.bin"
assert "remove: leaves the other file as it was" test "$(fsum "$home/engine.bin")" = "$keep"
pv "" status
assert "remove: status no longer lists it" test -z "$(out | grep -w gate)" -a -n "$(out | grep -w engine)"

echo "== repin =="
fresh; recv_ok gate; recv_ok engine
NEW=correct-horse
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
pv "$PIN\n$NEW\n$NEW\n" repin
assert "repin: exits 0 (old PIN, new PIN, and again if asked)" test "$rc" -eq 0
assert "repin: leaves no temporary file behind" test "$(ls "$home" 2>/dev/null | grep -vc '\.bin$')" -eq 0
pv "$PIN\n" get gate
assert "repin: the old PIN no longer opens a file" test "$rc" -ne 0 -a -z "$(out)"
pv "$NEW\n" get gate
assert "repin: the new PIN opens the first, same token" test "$(out)" = "$T1"
pv "$NEW\n" get engine
assert "repin: the new PIN opens the second, same token" test "$(out)" = "$T2"
rm -f "$tmp"/got.*; pv "$NEW\n" unlock
assert "repin: the receivers are kept" test "$rc" -eq 0 -a "$(tok gate)" = "$T1" -a "$(tok engine)" = "$T2"
pv "$NEW\nshort\nshort\n" repin
assert "repin: a new PIN under 6 characters is refused" test "$rc" -ne 0
pv "$NEW\n" get gate
assert "repin: a refused new PIN changes nothing" test "$(out)" = "$T1"

# No mix of PINs: one file that cannot be opened makes repin fail and write nothing.
fresh; recv_ok gate; recv_ok engine
enroll $PIN gate "$(recv gate)" $T1
enroll $PIN engine "$(recv engine)" $T2
flip "$home/engine.bin" 20
before=$(sum)
pv "$PIN\n$NEW\n$NEW\n" repin
assert "repin with one damaged file: fails" test "$rc" -ne 0
assert "repin with one damaged file: no file is rewritten" test "$(sum)" = "$before"
assert "repin with one damaged file: no temporary file is left" test "$(ls "$home" 2>/dev/null | grep -vc '\.bin$')" -eq 0
pv "$PIN\n" get gate
assert "repin with one damaged file: the old PIN still opens the intact one" test "$(out)" = "$T1"

echo "== no token or PIN in the arguments or environment of a process the tool starts =="
LT=leak-probe-token-9f3a1c
LP=leak-probe-pin-77b2
NP=leak-probe-newpin-5d41
fresh; recv_spy gate
: >"$tmp/spy.log"
export SPY_LOG=$tmp/spy.log
oldpath=$PATH; export PATH=$tmp/spy:$PATH
enroll $LP gate "$(recv gate)" $LT
pv "$LP\n" update gate --receiver "$(recv gate)"
pv "$LP\n" unlock
unlock_rc=$rc
pv "$LP\n" get gate
pv "$LP\n$NP\n$NP\n" repin
pv "$NP\n" unlock
PATH=$oldpath; unset SPY_LOG
assert "control: the receiver was reached with the token on stdin" test "$unlock_rc" -eq 0 -a "$(tok gate)" = "$LT"
assert "control: the receiver's process dump was written" test -s "$tmp/spy.log"
assert "token: absent from every dumped argument and environment" test "$(grep -c -a -- "$LT" "$tmp/spy.log")" = 0
assert "PIN: absent from every dumped argument and environment" test "$(grep -c -a -e "$LP" -e "$NP" "$tmp/spy.log")" = 0
assert "token and PIN: absent from the folder in the clear" test "$(grep -r -c -a -e "$LT" -e "$LP" "$home" 2>/dev/null | grep -vc ':0$')" = 0

echo "== keychain.sh: a second wrap must not unseat the first =="
NO_PV=1
mkdir -p "$tmp/fakesec" "$tmp/kc"
cat >"$tmp/fakesec/security" <<'S'
#!/bin/bash
# A Keychain of files: one per service and account. add without -U on an
# existing item fails; with -U it replaces, which is what mints a new key.
kc() {
  local cmd=$1 s="" a="" w="" u=0; shift
  while [ $# -gt 0 ]; do
    case $1 in
      -s) s=$2; shift ;; -a) a=$2; shift ;;
      -w) if [ "$cmd" = add-generic-password ]; then w=$2; shift; fi ;;
      -U) u=1 ;;
    esac; shift
  done
  local f=$KC_DIR/$s.$a
  case $cmd in
    add-generic-password) if [ -e "$f" ] && [ $u = 0 ]; then return 45; fi; printf %s "$w" >"$f" ;;
    find-generic-password) [ -e "$f" ] || return 44; cat "$f"; echo ;;
    *) return 1 ;;
  esac
}
if [ "${1:-}" = -i ]; then while read -r line; do kc $line || exit $?; done; else kc "$@"; fi
S
chmod +x "$tmp/fakesec/security"
kcrun() { PATH=$tmp/fakesec:$PATH KC_DIR=$tmp/kc bash "$KEYCHAIN" "$@"; }
rm -f "$tmp"/kc/*
printf 'first secret' | kcrun wrap >"$tmp/w1" 2>/dev/null
printf 'second secret' | kcrun wrap >"$tmp/w2" 2>/dev/null
assert "keychain wrap: both outputs are non-empty" test -s "$tmp/w1" -a -s "$tmp/w2"
assert "keychain unwrap: the first output is still readable after a second wrap" test "$(kcrun unwrap <"$tmp/w1" 2>/dev/null)" = "first secret"
assert "keychain unwrap: the second output is readable" test "$(kcrun unwrap <"$tmp/w2" 2>/dev/null)" = "second secret"
assert "keychain: one key, kept in the default service pin-vault" test "$(ls "$tmp/kc" | grep -c '^pin-vault\.')" -eq 1 -a "$(ls "$tmp/kc" | wc -l)" -eq 1
# A key that is already there is reused, and PIN_VAULT_KEYCHAIN_SERVICE overrides the service.
rm -f "$tmp"/kc/*
oldkey=$(openssl rand -hex 32)
printf %s "$oldkey" >"$tmp/kc/custom-svc.$(id -un)"
printf 'old secret' | openssl enc -aes-256-cbc -pbkdf2 -iter 1000 -md sha256 -salt -pass fd:3 3< <(printf '%s' "$oldkey") >"$tmp/w0"
printf 'new secret' | PIN_VAULT_KEYCHAIN_SERVICE=custom-svc kcrun wrap >"$tmp/w3" 2>/dev/null
assert "keychain wrap: reuses an existing key under PIN_VAULT_KEYCHAIN_SERVICE" test "$(PIN_VAULT_KEYCHAIN_SERVICE=custom-svc kcrun unwrap <"$tmp/w0" 2>/dev/null)" = "old secret"
assert "keychain wrap: the new blob is readable too" test "$(PIN_VAULT_KEYCHAIN_SERVICE=custom-svc kcrun unwrap <"$tmp/w3" 2>/dev/null)" = "new secret"

echo "== multi-line values: add --stdin =="
NO_PV=0
# pvs <input lines> <stdin file> <args...>: like pv, with a file as the tool's stdin.
pvs() {
  local in=$1 sf=$2; shift 2
  printf '%b' "$in" >"$tmp/in"
  PIN_VAULT_HOME=$home PIN_VAULT_WRAP=$tmp/wrap PIN_VAULT_INPUT_FD=7 \
    timeout 120 "$PV" "$@" 7<"$tmp/in" >"$tmp/out" 2>"$tmp/err" <"$sf"
  rc=$?
}
# plain <name> <pin>: the decrypted record, as the tool is meant to have written it.
plain() {
  "$tmp/wrap" unwrap <"$home/$1.bin" \
    | openssl enc -d -aes-256-cbc -pbkdf2 -iter "${PIN_VAULT_TEST_ITER:-600000}" -md sha256 -pass fd:3 3< <(printf '%s' "$2") 2>/dev/null
}
dgst3() { printf '%s\n%s\n%s\n' "$1" "$2" "$3" | openssl dgst -sha256 | awk '{print $NF}'; }
# is_v2 <name> <pin> <value file>: four lines, pin-vault2, base64 of the value
# on one line, a digest over the first three.
is_v2() {
  local m r b d
  plain "$1" "$2" >"$tmp/plain" || return 1
  m=$(sed -n 1p "$tmp/plain"); r=$(sed -n 2p "$tmp/plain"); b=$(sed -n 3p "$tmp/plain"); d=$(sed -n 4p "$tmp/plain")
  [ "$m" = pin-vault2 ] && [ "$(wc -l <"$tmp/plain")" -eq 4 ] \
    && [ "$b" = "$(base64 -w0 <"$3")" ] && [ "$d" = "$(dgst3 "$m" "$r" "$b")" ]
}
# is_v1 <name> <pin>: still a pin-vault1 record.
is_v1() { [ "$(plain "$1" "$2" | sed -n 1p)" = pin-vault1 ]; }
dgst4() { printf '%s\n%s\n%s\n%s\n' "$1" "$2" "$3" "$4" | openssl dgst -sha256 | awk '{print $NF}'; }
b64s() { printf '%s' "$1" | base64 -w0; }
# is_v3 <name> <pin> <value file> <note>: five lines, pin-vault3, receiver,
# base64 of the value, base64 of the note (an empty line for none), and a
# digest over the first four.
is_v3() {
  local m b n d
  plain "$1" "$2" >"$tmp/plain" || return 1
  m=$(sed -n 1p "$tmp/plain"); b=$(sed -n 3p "$tmp/plain"); n=$(sed -n 4p "$tmp/plain"); d=$(sed -n 5p "$tmp/plain")
  [ "$m" = pin-vault3 ] && [ "$(wc -l <"$tmp/plain")" -eq 5 ] \
    && [ "$b" = "$(base64 -w0 <"$3")" ] && [ "$n" = "$(b64s "$4")" ] \
    && [ "$d" = "$(dgst4 "$m" "$(sed -n 2p "$tmp/plain")" "$b" "$n")" ]
}
# seal_raw <name> <pin>: the plaintext on stdin, sealed the way the tool does.
seal_raw() {
  mkdir -p "$home"; chmod 0700 "$home"
  openssl enc -e -aes-256-cbc -pbkdf2 -iter "${PIN_VAULT_TEST_ITER:-600000}" -md sha256 -salt -pass fd:3 3< <(printf '%s' "$2") 2>/dev/null \
    | "$tmp/wrap" wrap >"$home/$1.bin"
}
# mk_v2 <name> <pin> <receiver> <value file>: a version 2 file.
mk_v2() {
  local b; b=$(base64 -w0 <"$4")
  printf 'pin-vault2\n%s\n%s\n%s\n' "$3" "$b" "$(dgst3 pin-vault2 "$3" "$b")" | seal_raw "$1" "$2"
}
# mk_v3 <name> <pin> <receiver> <value file> <note> [the note the digest covers]
mk_v3() {
  local b n; b=$(base64 -w0 <"$4"); n=$(b64s "$5")
  printf 'pin-vault3\n%s\n%s\n%s\n%s\n' "$3" "$b" "$n" "$(dgst4 pin-vault3 "$3" "$b" "$(b64s "${6-$5}")")" | seal_raw "$1" "$2"
}
# addn <pin> <name> <receiver> <note> <value file>: add --stdin with a note
# typed at its prompt, first run or later.
addn() {
  if compgen -G "$home/*.bin" >/dev/null; then pvs "$1\n$3\n$4\n" "$5" add "$2" --stdin
  else pvs "$1\n$1\n$3\n$4\n" "$5" add "$2" --stdin; fi
}
# mk_v1 <name> <pin> <receiver> <token>: a version 1 file.
mk_v1() {
  local d; mkdir -p "$home"; chmod 0700 "$home"
  d=$(dgst3 pin-vault1 "$3" "$4")
  printf 'pin-vault1\n%s\n%s\n%s\n' "$3" "$4" "$d" \
    | openssl enc -e -aes-256-cbc -pbkdf2 -iter "${PIN_VAULT_TEST_ITER:-600000}" -md sha256 -salt -pass fd:3 3< <(printf '%s' "$2") 2>/dev/null \
    | "$tmp/wrap" wrap >"$home/$1.bin"
}
# first_v2 <pin> <name> <receiver> <value file>: add --stdin, first run.
first_v2() { pvs "$1\n$1\n$3\n\n" "$4" add "$2" --stdin; }
later_v2() { pvs "$1\n$3\n\n" "$4" add "$2" --stdin; }

ML=$tmp/ml
printf 'line one\n  indented  line two\t\n\nlast line, CR at the end\r\n' >"$ML"
MLNT=$tmp/ml-nonl
printf 'no\n\nnewline at the end  ' >"$MLNT"
PAD=$tmp/pad
printf '  padded value \t\n' >"$PAD"
T1F=$tmp/t1.val; printf '%s' "$T1" >"$T1F"
T2F=$tmp/t2.val; printf '%s' "$T2" >"$T2F"
: >"$tmp/empty"

fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$ML"
assert "add --stdin, first run: exits 0 on PIN, PIN again and receiver alone" test "$rc" -eq 0 -a -f "$home/gate.bin"
pv "$PIN\n" get gate
assert "add --stdin: get gives the multi-line value back byte for byte (cmp)" cmp -s "$tmp/out" "$ML"
rm -f "$tmp"/got.*
pv "$PIN\n" unlock gate
assert "add --stdin: the receiver chosen at the prompt gets the exact bytes (cmp)" cmp -s "$tmp/got.gate" "$ML"
assert "add --stdin: the stored value is version 3" is_v3 gate $PIN "$ML" ""
assert "add --stdin: the file holds no line of the value in the clear" test "$(grep -c -a -F -e 'indented  line two' "$home/gate.bin")" = 0

fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$MLNT"
pv "$PIN\n" get gate
assert "add --stdin: a value with no trailing newline stays without one (cmp)" cmp -s "$tmp/out" "$MLNT"
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$PAD"
pv "$PIN\n" get gate
assert "add --stdin: whitespace is not stripped (cmp)" cmp -s "$tmp/out" "$PAD"
assert "add --stdin: a padded value is version 3 too" is_v3 gate $PIN "$PAD" ""

# A real pipe, not a file: get into `cmp` straight.
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$ML"
printf '%s\n' "$PIN" >"$tmp/in"
PIN_VAULT_HOME=$home PIN_VAULT_WRAP=$tmp/wrap PIN_VAULT_INPUT_FD=7 timeout 120 "$PV" get gate 7<"$tmp/in" 2>/dev/null </dev/null | cmp -s - "$ML"
assert "get into a pipe: cmp on the pipe itself agrees" test "${PIPESTATUS[1]}" -eq 0

# Later runs: the PIN, then the receiver, on an existing vault.
fresh; recv_ok gate; recv_ok other
enroll $PIN gate "$(recv gate)" $T1
later_v2 $PIN other "$(recv other)" "$ML"
assert "add --stdin, later run: exits 0 on the PIN and the receiver" test "$rc" -eq 0 -a -f "$home/other.bin"
pv "$PIN\n" get other
assert "add --stdin, later run: the value comes back (cmp)" cmp -s "$tmp/out" "$ML"
pvs "wrongpin\n$(recv other)\n" "$ML" add third --stdin
assert "add --stdin, later run: a wrong PIN is refused and stores nothing" test "$rc" -ne 0 -a ! -e "$home/third.bin"

# Refusals store nothing, and an existing entry is left as it was.
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$tmp/empty"
assert "add --stdin, empty stdin: refused" test "$rc" -ne 0
assert "add --stdin, empty stdin: stores nothing" test ! -e "$home/gate.bin"
assert "add --stdin, empty stdin: says why" test -n "$(errs)"
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
before=$(fsum "$home/gate.bin")
later_v2 $PIN gate "$(recv gate)" "$tmp/empty"
assert "add --stdin, empty stdin on an existing name: refused, file unchanged" test "$rc" -ne 0 -a "$(fsum "$home/gate.bin")" = "$before"

head -c 70000 /dev/zero | tr '\0' 'x' | fold -w 100 | head -c 65536 >"$tmp/big-ok"
head -c 65537 /dev/zero | tr '\0' 'y' >"$tmp/big-over"
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$tmp/big-ok"
assert "add --stdin: exactly 64 KiB (65536 bytes) is accepted" test "$rc" -eq 0 -a -f "$home/gate.bin"
pv "$PIN\n" get gate
assert "add --stdin: the 64 KiB value comes back (cmp)" cmp -s "$tmp/out" "$tmp/big-ok"
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$tmp/big-over"
assert "add --stdin: 65537 bytes is refused" test "$rc" -ne 0
assert "add --stdin: a too large value stores nothing" test ! -e "$home/gate.bin" -a -z "$(ls "$home" 2>/dev/null)"
assert "add --stdin: the refusal says why" test -n "$(errs)"
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
before=$(fsum "$home/gate.bin")
later_v2 $PIN gate "$(recv gate)" "$tmp/big-over"
assert "add --stdin: a too large value leaves an existing entry unchanged" test "$rc" -ne 0 -a "$(fsum "$home/gate.bin")" = "$before"
pv "$PIN\n" get gate
assert "add --stdin: and the old token still opens" test "$(out)" = "$T1"

echo "== multi-line values: add without --stdin is as before =="
fresh; recv_ok gate
pvs "$PIN\n$PIN\n$(recv gate)\n\n  tok en\t1 \n" "$ML" add gate
pv "$PIN\n" get gate
assert "add without --stdin: stdin is ignored, the typed line is the token, spaces stripped" test "$rc" -eq 0 -a "$(out)" = "toke""n1" -a "$(wc -c <"$tmp/out")" -eq 6
printf '%s' "toke""n1" >"$tmp/typed.val"
assert "add without --stdin: a typed token is written as version 3" is_v3 gate $PIN "$tmp/typed.val" ""

echo "== multi-line values: a typed token reaches get and unlock with no newline =="
fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
pv "$PIN\n" get gate
assert "get into a pipe: a typed token has no trailing newline" test "$(wc -c <"$tmp/out")" -eq ${#T1} -a "$(out)" = "$T1"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "unlock: a typed token reaches the receiver with no trailing newline" test "$(wc -c <"$tmp/got.gate")" -eq ${#T1} -a "$(tok gate)" = "$T1"
assert "enroll: a typed token is version 3" is_v3 gate $PIN "$T1F" ""

echo "== pin-vault1 files keep opening =="
fresh; recv_ok gate; recv_ok engine
mk_v1 gate $PIN "$(recv gate)" $T1
assert "control: the helper writes a version 1 record" is_v1 gate $PIN
v1sum=$(fsum "$home/gate.bin")
pv "$PIN\n" get gate
assert "version 1: get opens it, token exact with no newline" test "$rc" -eq 0 -a "$(out)" = "$T1" -a "$(wc -c <"$tmp/out")" -eq ${#T1}
rm -f "$tmp"/got.*; pv "$PIN\n" unlock
assert "version 1: unlock opens it and the receiver gets the token" test "$rc" -eq 0 -a "$(wc -c <"$tmp/got.gate")" -eq ${#T1} -a "$(tok gate)" = "$T1"
assert "version 1: reading (get, unlock) does not rewrite the file" test "$(fsum "$home/gate.bin")" = "$v1sum"
assert "version 1: reading leaves it version 1" is_v1 gate $PIN
pv "wrongpin\n" get gate
assert "version 1: a wrong PIN still opens nothing" test "$rc" -ne 0 -a -z "$(out)"
later_v2 $PIN engine "$(recv engine)" "$ML"
assert "version 1: adding another entry leaves it untouched" test "$(fsum "$home/gate.bin")" = "$v1sum"

echo "== version 1 and version 2 side by side =="
rm -f "$tmp"/got.*; : >"$tmp/ran.log"
pv "$PIN\n" unlock
assert "mixed: one unlock serves both" test "$rc" -eq 0 -a "$(ranlog | wc -l)" -eq 2
assert "mixed: the version 1 token arrives exact" test "$(tok gate)" = "$T1" -a "$(wc -c <"$tmp/got.gate")" -eq ${#T1}
assert "mixed: the version 2 value arrives exact (cmp)" cmp -s "$tmp/got.engine" "$ML"

echo "== update and repin turn version 1 into version 3 =="
fresh; recv_ok gate; recv_ok gate2
mk_v1 gate $PIN "$(recv gate)" $T1
pv "$PIN\n" update gate --receiver "$(recv gate2)"
assert "update --receiver of a version 1 file: exits 0" test "$rc" -eq 0
assert "update --receiver of a version 1 file: it is now version 3" is_v3 gate $PIN "$T1F" ""
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "update --receiver of a version 1 file: the token is unchanged, at the new receiver" test "$(tok gate2)" = "$T1" -a "$(wc -c <"$tmp/got.gate2")" -eq ${#T1}

fresh; recv_ok gate; recv_ok gate2
first_v2 $PIN gate "$(recv gate)" "$ML"
pv "$PIN\n" update gate --receiver "$(recv gate2)"
assert "update --receiver of a multi-line value: exits 0" test "$rc" -eq 0
pv "$PIN\n" get gate
assert "update --receiver of a multi-line value: the value is kept byte for byte (cmp)" cmp -s "$tmp/out" "$ML"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "update --receiver of a multi-line value: the new receiver gets it (cmp)" cmp -s "$tmp/got.gate2" "$ML"
assert "update --receiver of a multi-line value: still version 3" is_v3 gate $PIN "$ML" ""

fresh; recv_ok gate; recv_ok engine
NEW=correct-horse
mk_v1 gate $PIN "$(recv gate)" $T1
later_v2 $PIN engine "$(recv engine)" "$ML"
pv "$PIN\n$NEW\n$NEW\n" repin
assert "repin over version 1 and 2 together: exits 0" test "$rc" -eq 0
assert "repin: the version 1 file is now version 3" is_v3 gate $NEW "$T1F" ""
assert "repin: the stored version 3 file is still version 3" is_v3 engine $NEW "$ML" ""
pv "$NEW\n" get engine
assert "repin: the multi-line value survives byte for byte (cmp)" cmp -s "$tmp/out" "$ML"
rm -f "$tmp"/got.*; pv "$NEW\n" unlock
assert "repin: unlock exits 0 and the version 1 token arrives exact" test "$rc" -eq 0 -a "$(tok gate)" = "$T1"
assert "repin: the multi-line receiver got the exact bytes (cmp)" cmp -s "$tmp/got.engine" "$ML"

echo "== a changed byte in a version 2 file =="
fresh; recv_ok gate
first_v2 $PIN gate "$(recv gate)" "$ML"
size=$(wc -c <"$home/gate.bin")
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "control: the untouched version 2 file unlocks" test "$rc" -eq 0 -a -f "$tmp/got.gate"
assert "control: and delivers the exact bytes" cmp -s "$tmp/got.gate" "$ML"
cp "$home/gate.bin" "$tmp/gate.orig"
for off in 0 1 8 16 31 $((size / 3)) $((size / 2)) $((size - 33)) $((size - 17)) $((size - 2)) $((size - 1)); do
  [ "$off" -ge 0 ] && [ "$off" -lt "$size" ] || continue
  rm -f "$tmp"/got.*; : >"$tmp/ran.log"
  cp "$tmp/gate.orig" "$home/gate.bin"; flip "$home/gate.bin" "$off"
  pv "$PIN\n" unlock gate
  assert "v2 flipped byte $off of $size: unlock fails, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0 -a ! -e "$tmp/got.gate"
  pv "$PIN\n" get gate
  assert "v2 flipped byte $off of $size: get prints nothing" test "$rc" -ne 0 -a ! -s "$tmp/out"
done
head -c $((size - 1)) "$tmp/gate.orig" >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "v2 truncated file: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"
{ cat "$tmp/gate.orig"; printf x; } >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "v2 appended byte: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"

# A changed v2 file next to good ones: the good ones are served, the bad one is not.
fresh; recv_ok gate; recv_ok engine
mk_v1 gate $PIN "$(recv gate)" $T1
later_v2 $PIN engine "$(recv engine)" "$ML"
flip "$home/engine.bin" 40
rm -f "$tmp"/got.*; pv "$PIN\n" unlock
assert "mixed with a changed v2 file: the intact v1 file is served, the changed one is not, exit not 0" test "$rc" -ne 0 -a "$(tok gate)" = "$T1" -a ! -e "$tmp/got.engine"

echo "== multi-line values: no value, encoded or not, in any argument or environment =="
# A spy base64 beside the spy openssl: the encoding may be either one.
REAL_B64=$(command -v base64)
cat >"$tmp/spy/base64" <<W
#!/bin/sh
if [ -n "\${SPY_LOG:-}" ]; then { echo "ARGS:\$*"; tr '\0' '\n' </proc/\$\$/environ; } >>"\$SPY_LOG"; fi
exec $REAL_B64 "\$@"
W
chmod +x "$tmp/spy/base64"
LV=$tmp/leak.val
printf -- '-----BEGIN TEST KEY-----\nleak-probe-ml-aaaa1111\nleak-probe-ml-bbbb2222\n-----END TEST KEY-----\n' >"$LV"
LB1=$(base64 -w0 <"$LV" | cut -c1-40)
LB2=$(base64 -w0 <"$LV" | cut -c41-80)
LB3=$(base64 -w0 <"$LV" | cut -c81-120)
fresh; recv_spy gate; recv_spy engine
: >"$tmp/spy.log"
export SPY_LOG=$tmp/spy.log
oldpath=$PATH; export PATH=$tmp/spy:$PATH
first_v2 $LP gate "$(recv gate)" "$LV"
add_rc=$rc
later_v2 $LP engine "$(recv engine)" "$LV"
pv "$LP\n" update gate --receiver "$(recv gate)"
pv "$LP\n" unlock
unlock_rc=$rc
pv "$LP\n" get gate
get_rc=$rc
pv "$LP\n$NP\n$NP\n" repin
pv "$NP\n" unlock
PATH=$oldpath; unset SPY_LOG
assert "control: add --stdin, unlock and get worked with the spies in the path" test "$add_rc" -eq 0 -a "$unlock_rc" -eq 0 -a "$get_rc" -eq 0
assert "control: the receiver got the exact value (cmp)" cmp -s "$tmp/got.gate" "$LV"
assert "control: the spies and the receiver's process dump were written" test -s "$tmp/spy.log"
assert "value: no line of it in any dumped argument or environment" test "$(grep -c -a -F -e leak-probe-ml-aaaa1111 -e leak-probe-ml-bbbb2222 -e 'BEGIN TEST KEY' "$tmp/spy.log")" = 0
assert "value in base64: no part of it in any dumped argument or environment" test "$(grep -c -a -F -e "$LB1" -e "$LB2" -e "$LB3" "$tmp/spy.log")" = 0
assert "value: not in the folder in the clear, nor in base64" test "$(grep -r -c -a -F -e leak-probe-ml -e "$LB1" "$home" 2>/dev/null | grep -vc ':0$')" = 0

echo "== notes: add asks for one after the receiver, get shows it =="
NOTE=$(printf 'caf\303\251 \303\274n\303\257 \342\200\224 \344\273\244\347\211\214  two  spaces')
fresh; recv_ok gate
addn $PIN gate "$(recv gate)" "rotate in March" "$ML"
assert "add: the note is asked after the receiver, exits 0" test "$rc" -eq 0 -a -f "$home/gate.bin"
assert "add: the record is version 3, with the note under the PIN and the value exact" is_v3 gate $PIN "$ML" "rotate in March"
assert "add: the receiver is the one typed" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"
assert "add: the note is not in the file in the clear" test "$(grep -c -a -F -e 'rotate in March' -e "$(b64s 'rotate in March')" "$home/gate.bin")" = 0
pv "$PIN\n" get gate
assert "get into a pipe, with a note: stdout is the exact value (cmp)" cmp -s "$tmp/out" "$ML"
assert "get into a pipe, with a note: the note is on stderr" test "$(errs | grep -c -F 'rotate in March')" -ge 1
assert "get into a pipe, with a note: the note is not on stdout" test "$(grep -c -a -F 'rotate in March' "$tmp/out")" = 0
printf '%s\n' "$PIN" >"$tmp/in"
PIN_VAULT_HOME=$home PIN_VAULT_WRAP=$tmp/wrap PIN_VAULT_INPUT_FD=7 timeout 120 "$PV" get gate 7<"$tmp/in" 2>"$tmp/err" </dev/null | cmp -s - "$ML"
assert "get into a real pipe, with a note: cmp on the pipe agrees" test "${PIPESTATUS[1]}" -eq 0 -a "$(errs | grep -c -F 'rotate in March')" -ge 1
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "unlock: the receiver gets the value (cmp)" cmp -s "$tmp/got.gate" "$ML"
assert "unlock: the note is not shown" test "$rc" -eq 0 -a "$( (out; errs) | grep -c -F 'rotate in March')" = 0
pv "" status
assert "status: lists the name, shows no note" test "$rc" -eq 0 -a "$(out | grep -c -w gate)" -ge 1 -a "$( (out; errs) | grep -c -F 'rotate')" = 0

fresh; recv_ok gate
enroll $PIN gate "$(recv gate)" $T1
pv "$PIN\n" get gate
assert "get into a pipe, no note: the exact value, no newline" test "$(out)" = "$T1" -a "$(wc -c <"$tmp/out")" -eq ${#T1}
assert "get into a pipe, no note: nothing on stderr" test "$rc" -eq 0 -a -z "$(errs)"

fresh; recv_ok gate
addn $PIN gate "$(recv gate)" "$NOTE" "$ML"
assert "add: a note with spaces and non-ASCII is stored as typed" is_v3 gate $PIN "$ML" "$NOTE"
pv "$PIN\n" get gate
assert "get: a note with spaces and non-ASCII survives, on stderr" test "$(errs | grep -c -F -- "$NOTE")" -ge 1
assert "get: and the value is still exact (cmp)" cmp -s "$tmp/out" "$ML"

fresh; recv_ok gate
pvs "$PIN\n$PIN\n$(recv gate)\n" "$ML" add gate --stdin --note "from the flag"
assert "add --note: skips the note question, exits 0" test "$rc" -eq 0
assert "add --note: the note is stored" is_v3 gate $PIN "$ML" "from the flag"
fresh; recv_ok gate
pv "$PIN\n$PIN\n$(recv gate)\n$T1\n" add gate --note "$NOTE"
assert "add --note, typed token: exits 0" test "$rc" -eq 0
assert "add --note, typed token: the note is stored, non-ASCII and spaces too" is_v3 gate $PIN "$T1F" "$NOTE"

echo "== add on an existing name refuses before the PIN =="
fresh; recv_ok gate
addn $PIN gate "$(recv gate)" "keep me" "$ML"
before=$(fsum "$home/gate.bin")
pvs "wrongpin\n$(recv gate)\n\n" "$T2F" add gate --stdin
assert "add --stdin on an existing name: refused, names update, no PIN asked" test "$rc" -ne 0 -a "$(errs | grep -c update)" -ge 1 -a "$(errs | grep -c -i -e 'wrong PIN' -e 'no PIN given')" -eq 0
pv "wrongpin\n" add gate --note "other"
assert "add --note on an existing name: refused, names update, no PIN asked" test "$rc" -ne 0 -a "$(errs | grep -c update)" -ge 1 -a "$(errs | grep -c -i -e 'wrong PIN' -e 'no PIN given')" -eq 0
assert "add on an existing name: the file is as it was" test "$(fsum "$home/gate.bin")" = "$before"
assert "add on an existing name: note and value are kept" is_v3 gate $PIN "$ML" "keep me"

echo "== add --receiver =="
fresh; recv_ok gate
pv "$PIN\n$PIN\n$T1\n" add gate --receiver "$(recv gate)" --note "n313"
assert "add --receiver --note: exits 0 on the PIN twice and the token alone" test "$rc" -eq 0
assert "add --receiver --note: the receiver is stored" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"
assert "add --receiver --note: the note and token are stored" is_v3 gate $PIN "$T1F" "n313"
assert "add --receiver --note: no receiver question was shown" test "$(errs | grep -c -i receiver)" -eq 0
fresh; recv_ok gate; recv_ok gate2
enroll $PIN gate "$(recv gate)" $T1
pv "$PIN\n$T1\n" add other --receiver "$(recv gate2)" --note "n313"
assert "add --receiver --note, later entry: exits 0 on the PIN and the token alone" test "$rc" -eq 0
assert "add --receiver --note, later entry: the receiver is stored" test "$(plain other $PIN | sed -n 2p)" = "$(recv gate2)"
fresh
pv "wrongpin\n" add gate --receiver nosuchprog-313 --note "n"
assert "add --receiver not on PATH: refused, with the reason" test "$rc" -ne 0 -a "$(errs | grep -c -F "not on PATH")" -ge 1
assert "add --receiver not on PATH: no PIN was asked" test "$(errs | grep -c -i -e "wrong PIN" -e "no PIN given" -e "new PIN")" -eq 0
assert "add --receiver not on PATH: nothing stored" test ! -e "$home/gate.bin"
fresh; recv_ok gate
pv "$PIN\n$PIN\n$T1\n" add gate --receiver "" --note ""
assert "add --receiver empty: exits 0, no receiver question" test "$rc" -eq 0
assert "add --receiver empty: stores no receiver" test -z "$(plain gate $PIN | sed -n 2p)" -a "$(plain gate $PIN | sed -n 1p)" = pin-vault3
assert "add --receiver empty: the token is stored" is_v3 gate $PIN "$T1F" ""
fresh; recv_ok gate
pv "$PIN\n$PIN\n$(recv gate)\n\n$T1\n" add gate
assert "add without --receiver: still asks, and stores the answer" test "$rc" -eq 0 -a "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"

echo "== pin-vault edit is gone =="
fresh; recv_ok gate; recv_ok gate2
enroll $PIN gate "$(recv gate)" $T1
before=$(fsum "$home/gate.bin")
pv "$PIN\n$(recv gate2)\n" edit gate
assert "edit: refused, exit not 0" test "$rc" -ne 0
assert "edit: the refusal names update" test "$(errs | grep -c update)" -ge 1
assert "edit: changes nothing" test "$(fsum "$home/gate.bin")" = "$before"
pv "" edit
assert "edit with no name: refused too, names update" test "$rc" -ne 0 -a "$(errs | grep -c update)" -ge 1
pv "" ""
assert "the usage lists update and no longer edit" test "$(errs | grep -c update)" -ge 1 -a "$(errs | grep -c -w edit)" = 0

echo "== update --receiver: the value and the note stay =="
fresh; recv_ok gate; recv_ok gate2
addn $PIN gate "$(recv gate)" "$NOTE" "$ML"
pv "$PIN\n" update gate --receiver "$(recv gate2)"
assert "update --receiver: exits 0 on the PIN alone" test "$rc" -eq 0
assert "update --receiver: the stored receiver is the new one" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate2)"
assert "update --receiver: the multi-line value and the note are as they were" is_v3 gate $PIN "$ML" "$NOTE"
pv "$PIN\n" get gate
assert "update --receiver: get gives the value byte for byte (cmp)" cmp -s "$tmp/out" "$ML"
assert "update --receiver: and the note is still shown" test "$(errs | grep -c -F -- "$NOTE")" -ge 1
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "update --receiver: the value goes to the new receiver (cmp)" cmp -s "$tmp/got.gate2" "$ML"
assert "update --receiver: and not to the old one" test ! -e "$tmp/got.gate"

echo "== update --note =="
fresh; recv_ok gate
addn $PIN gate "$(recv gate)" "first note" "$ML"
pv "$PIN\n" update gate --note "$NOTE"
assert "update --note: exits 0 on the PIN alone" test "$rc" -eq 0
assert "update --note: the new note is stored, non-ASCII and spaces survive" is_v3 gate $PIN "$ML" "$NOTE"
assert "update --note: the receiver is as it was" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"
pv "$PIN\n" update gate --note ""
assert "update --note '': exits 0" test "$rc" -eq 0
assert "update --note '': the note is gone, the value stays" is_v3 gate $PIN "$ML" ""
pv "$PIN\n" get gate
assert "update --note '': get gives the value (cmp)" cmp -s "$tmp/out" "$ML"
assert "update --note '': get shows no note" test "$rc" -eq 0 -a -z "$(errs)"

echo "== update on pin-vault1 and pin-vault2 files =="
fresh; recv_ok gate; recv_ok engine
mk_v1 gate $PIN "$(recv gate)" $T1
mk_v2 engine $PIN "$(recv engine)" "$ML"
v1sum=$(fsum "$home/gate.bin"); v2sum=$(fsum "$home/engine.bin")
pv "$PIN\n" get gate
assert "version 1: get is exact and shows no note" test "$(out)" = "$T1" -a -z "$(errs)"
pv "$PIN\n" get engine
assert "version 2: get is exact (cmp)" cmp -s "$tmp/out" "$ML"
assert "version 2: get shows no note" test "$rc" -eq 0 -a -z "$(errs)"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock
assert "versions 1 and 2: unlock serves both" test "$rc" -eq 0 -a "$(tok gate)" = "$T1" -a "$(ranlog | wc -l)" -ge 2
assert "version 2: unlock delivers the exact bytes (cmp)" cmp -s "$tmp/got.engine" "$ML"
assert "versions 1 and 2: reading rewrote neither" test "$(fsum "$home/gate.bin")" = "$v1sum" -a "$(fsum "$home/engine.bin")" = "$v2sum"
pv "$PIN\n" update gate --note "was version 1"
assert "update --note on a version 1 file: exits 0" test "$rc" -eq 0
assert "update --note on a version 1 file: it is now version 3 with the note" is_v3 gate $PIN "$T1F" "was version 1"
assert "update --note on a version 1 file: the receiver is as it was" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"
pv "$PIN\n" update engine --note "was version 2"
assert "update --note on a version 2 file: exits 0" test "$rc" -eq 0
assert "update --note on a version 2 file: it is now version 3, value byte for byte" is_v3 engine $PIN "$ML" "was version 2"
assert "update --note on a version 2 file: the receiver is as it was" test "$(plain engine $PIN | sed -n 2p)" = "$(recv engine)"
pv "$PIN\n" get engine
assert "update --note on a version 2 file: get shows the note on stderr" test "$(errs | grep -c -F 'was version 2')" -ge 1
assert "update --note on a version 2 file: get gives the value (cmp)" cmp -s "$tmp/out" "$ML"
fresh; recv_ok gate; recv_ok gate2
mk_v2 gate $PIN "$(recv gate)" "$ML"
pv "$PIN\n" update gate --receiver "$(recv gate2)"
assert "update --receiver on a version 2 file: exits 0" test "$rc" -eq 0
assert "update --receiver on a version 2 file: it is now version 3 with no note" is_v3 gate $PIN "$ML" ""
fresh; recv_ok gate; recv_ok gate2
mk_v1 gate $PIN "$(recv gate)" $T1
pv "$PIN\n$T2\n" update gate --token
assert "update --token on a version 1 file: exits 0" test "$rc" -eq 0
assert "update --token on a version 1 file: it is now version 3, new token, receiver kept" is_v3 gate $PIN "$T2F" ""
assert "update --token on a version 1 file: the stored receiver is as it was" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"

echo "== update --token: the receiver and the note stay =="
fresh; recv_ok gate
addn $PIN gate "$(recv gate)" "$NOTE" "$ML"
printf '%s' "$T3" >"$tmp/t3.val"
pv "$PIN\n$T3\n" update gate --token
assert "update --token: exits 0 on the PIN and the new value" test "$rc" -eq 0
assert "update --token: the new value is stored, the note is as it was" is_v3 gate $PIN "$tmp/t3.val" "$NOTE"
assert "update --token: the receiver is as it was" test "$(plain gate $PIN | sed -n 2p)" = "$(recv gate)"
pv "$PIN\n" get gate
assert "update --token: get gives the new token" test "$(out)" = "$T3"
pvs "$PIN\n" "$ML" update gate --token --stdin
assert "update --token --stdin: exits 0 on the PIN alone" test "$rc" -eq 0
assert "update --token --stdin: all of stdin is the value, note kept" is_v3 gate $PIN "$ML" "$NOTE"
pv "$PIN\n" get gate
assert "update --token --stdin: get gives the multi-line value byte for byte (cmp)" cmp -s "$tmp/out" "$ML"
before=$(fsum "$home/gate.bin")
pvs "$PIN\n" "$tmp/empty" update gate --token --stdin
assert "update --token --stdin, empty stdin: refused, says why" test "$rc" -ne 0 -a -n "$(errs)"
assert "update --token --stdin, empty stdin: changes nothing" test "$(fsum "$home/gate.bin")" = "$before"
pv "$PIN\n" update gate --token "$T3"
assert "update --token <value>: there is no such form, refused" test "$rc" -ne 0
assert "update --token <value>: nothing stored" test "$(fsum "$home/gate.bin")" = "$before"

echo "== update: a wrong PIN changes nothing on any path =="
fix_one() { fresh; recv_ok gate; recv_ok gate2; addn $PIN gate "$(recv gate)" "keep me" "$ML"; before=$(fsum "$home/gate.bin"); }
fix_one
pv "wrongpin\n" update gate --receiver "$(recv gate2)"
assert "wrong PIN, --receiver: refused after asking for the PIN" test "$rc" -ne 0 -a "$(errs | grep -c -i 'wrong PIN')" -ge 1
assert "wrong PIN, --receiver: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"
pv "wrongpin\n" update gate --note "other"
assert "wrong PIN, --note: refused after asking for the PIN" test "$rc" -ne 0 -a "$(errs | grep -c -i 'wrong PIN')" -ge 1
assert "wrong PIN, --note: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"
pv "wrongpin\n$T3\n" update gate --token
assert "wrong PIN, --token: refused after asking for the PIN" test "$rc" -ne 0 -a "$(errs | grep -c -i 'wrong PIN')" -ge 1
assert "wrong PIN, --token: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"
pvs "wrongpin\n" "$ML" update gate --token --stdin
assert "wrong PIN, --token --stdin: refused after asking for the PIN" test "$rc" -ne 0 -a "$(errs | grep -c -i 'wrong PIN')" -ge 1
assert "wrong PIN, --token --stdin: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"
pk '\033[B\n' "wrongpin\n$(recv gate2)\n" update gate
assert "wrong PIN, through the menu: refused after asking for the PIN" test "$rc" -ne 0 -a "$(errs | grep -c -i 'wrong PIN')" -ge 1
assert "wrong PIN, through the menu: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"

echo "== update: two part flags, or --stdin alone, refuse before the PIN =="
fix_one
pv "$PIN\n" update gate --note "control"
assert "control: one flag works with the same fixture" test "$rc" -eq 0
before=$(fsum "$home/gate.bin")
refuse() {
  local label=$1; shift
  pvs "wrongpin\n" "$ML" "$@"
  assert "$label: refused, with a reason" test "$rc" -ne 0 -a -n "$(errs)"
  assert "$label: refused before the PIN is asked" test "$(errs | grep -c -i -e 'wrong PIN' -e 'no PIN given')" -eq 0
  assert "$label: nothing changed" test "$(fsum "$home/gate.bin")" = "$before"
}
refuse "--receiver with --note" update gate --receiver "$(recv gate2)" --note "x"
refuse "--token with --note" update gate --token --note "x"
refuse "--receiver with --token" update gate --receiver "$(recv gate2)" --token
refuse "--stdin without --token" update gate --stdin
refuse "--stdin with --note" update gate --stdin --note "x"
refuse "--stdin with --receiver" update gate --stdin --receiver "$(recv gate2)"

echo "== update: the menu =="
# menu_has <word>: a line of the menu on stderr starts with the word, once the
# escape codes, the cursor mark and the indent are gone.
menu_has() { errs | sed -E 's/\x1b\[[0-9;?]*[A-Za-z]//g; s/\r//g; s/^[ >]+//' | grep -c -i -E "^$1"; }
fix_menu() { fresh; recv_ok gate; recv_ok gate2; recv_ok engine; addn $PIN engine "$(recv engine)" "" "$T2F"; addn $PIN gate "$(recv gate)" "n0" "$ML"; }
fix_menu
pk '\n' "$PIN\n$T3\n" update gate
assert "menu: offers token" test "$(menu_has token)" -ge 1
assert "menu: offers receiver" test "$(menu_has receiver)" -ge 1
assert "menu: offers note" test "$(menu_has note)" -ge 1
assert "menu: Enter alone picks the token, asks the PIN and the new value" test "$rc" -eq 0 -a "$(plain gate $PIN | sed -n 3p)" = "$(b64s "$T3")"
assert "menu: the token path leaves the receiver and the note" is_v3 gate $PIN "$tmp/t3.val" "n0"
fix_menu
pk '\033[B\n' "$PIN\n$(recv gate2)\n" update gate
assert "menu: Down picks the receiver" test "$rc" -eq 0 -a "$(plain gate $PIN | sed -n 2p)" = "$(recv gate2)"
assert "menu: the receiver path leaves the value and the note" is_v3 gate $PIN "$ML" "n0"
fix_menu
pk '\033[B\033[B\n' "$PIN\nmenu note\n" update gate
assert "menu: Down twice picks the note" is_v3 gate $PIN "$ML" "menu note"
fix_menu
pk '\033[A\n' "$PIN\nup note\n" update gate
assert "menu: Up from the first wraps to the note" is_v3 gate $PIN "$ML" "up note"
fix_menu
pk '\033[B\n\033[B\n' "$PIN\n$(recv gate2)\n" update
assert "menu, no name: picks the entry first, then the part" test "$rc" -eq 0 -a "$(plain gate $PIN | sed -n 2p)" = "$(recv gate2)"
assert "menu, no name: the other entry is untouched" is_v3 engine $PIN "$T2F" ""
for k in '\033' 'q' '\033[B\003'; do
  fix_menu; before=$(sum)
  pk "$k" "$PIN\n$T3\n" update gate
  assert "menu: keys '$k' leave every entry unchanged (the menu was shown)" test "$(sum)" = "$before" -a "$(menu_has note)" -ge 1
done
fix_menu; before=$(sum)
pk '\033' "$PIN\n" update
assert "menu, no name: Esc at the entry list leaves every entry unchanged" test "$(sum)" = "$before" -a "$(menu_has engine)" -ge 1
fix_menu; before=$(sum)
pk '\n\033' "$PIN\n" update
assert "menu, no name: Esc at the part list leaves every entry unchanged" test "$(sum)" = "$before" -a "$(menu_has note)" -ge 1

echo "== a changed pin-vault3 record =="
fresh; recv_ok gate
mk_v3 gate $PIN "$(recv gate)" "$ML" "a note that must not show"
assert "control: the helper writes a record is_v3 accepts" is_v3 gate $PIN "$ML" "a note that must not show"
mk_v2 engine $PIN "$(recv gate)" "$ML"
assert "control: mk_v2 writes a record is_v2 accepts" is_v2 engine $PIN "$ML"
rm -f "$home/engine.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "control: a well formed version 3 record unlocks" test "$rc" -eq 0 -a -f "$tmp/got.gate"
assert "control: and delivers the exact bytes (cmp)" cmp -s "$tmp/got.gate" "$ML"
pv "$PIN\n" get gate
assert "control: get shows the note on stderr" test "$(errs | grep -c -F 'a note that must not show')" -ge 1
size=$(wc -c <"$home/gate.bin"); cp "$home/gate.bin" "$tmp/gate.orig"
for off in 0 1 8 16 31 $((size / 3)) $((size / 2)) $((size - 33)) $((size - 17)) $((size - 2)) $((size - 1)); do
  [ "$off" -ge 0 ] && [ "$off" -lt "$size" ] || continue
  rm -f "$tmp"/got.*; : >"$tmp/ran.log"
  cp "$tmp/gate.orig" "$home/gate.bin"; flip "$home/gate.bin" "$off"
  pv "$PIN\n" unlock gate
  assert "v3 flipped byte $off of $size: unlock fails, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0 -a ! -e "$tmp/got.gate"
  pv "$PIN\n" get gate
  assert "v3 flipped byte $off of $size: get prints neither value nor note" test "$rc" -ne 0 -a ! -s "$tmp/out" -a "$(errs | grep -c -F 'a note that must not show')" -eq 0
done
head -c $((size - 1)) "$tmp/gate.orig" >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "v3 truncated file: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"
{ cat "$tmp/gate.orig"; printf x; } >"$home/gate.bin"
rm -f "$tmp"/got.*; pv "$PIN\n" unlock gate
assert "v3 appended byte: detected, no receiver run" test "$rc" -ne 0 -a ! -e "$tmp/got.gate"
# Whole records sealed under the right PIN, wrong inside.
fresh; recv_ok gate; : >"$tmp/ran.log"
mk_v3 gate $PIN "$(recv gate)" "$ML" "the note as stored" "the note as signed"
pv "$PIN\n" unlock gate
assert "v3 with a note the digest does not cover: refused, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0
pv "$PIN\n" get gate
assert "v3 with a note the digest does not cover: get prints neither value nor note" test "$rc" -ne 0 -a ! -s "$tmp/out" -a "$(errs | grep -c -F 'the note as stored')" -eq 0
before=$(fsum "$home/gate.bin")
pv "$PIN\n" update gate --note "repair"
assert "v3 with a note the digest does not cover: update refuses and writes nothing" test "$rc" -ne 0 -a "$(fsum "$home/gate.bin")" = "$before"
b=$(base64 -w0 <"$ML"); n=$(b64s "a note")
printf 'pin-vault3\n%s\n%s\n%s\n' "$(recv gate)" "$b" "$(dgst3 pin-vault3 "$(recv gate)" "$b")" | seal_raw gate $PIN
pv "$PIN\n" unlock gate
assert "v3 with no note line: refused, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0
printf 'pin-vault3\n%s\n%s\n%s\n%s\nextra\n' "$(recv gate)" "$b" "$n" "$(dgst4 pin-vault3 "$(recv gate)" "$b" "$n")" | seal_raw gate $PIN
pv "$PIN\n" unlock gate
assert "v3 with a line after the digest: refused, no receiver run" test "$rc" -ne 0 -a "$(ranlog | wc -l)" -eq 0
printf 'pin-vault3\n%s\n%s\n%s\n%s\n' "$(recv gate)" "$b" "$n" "$(dgst4 pin-vault3 "$(recv gate)" "$b" "$n")" | seal_raw gate $PIN
pv "$PIN\n" unlock gate
assert "control: the same record with its own digest unlocks" test "$rc" -eq 0 -a "$(ranlog | wc -l)" -eq 1

echo "== repin keeps the notes =="
fresh; recv_ok gate; recv_ok engine
NEW=correct-horse
mk_v3 gate $PIN "$(recv gate)" "$ML" "$NOTE"
mk_v2 engine $PIN "$(recv engine)" "$T1F"
pv "$PIN\n$NEW\n$NEW\n" repin
assert "repin over a version 3 and a version 2 file: exits 0" test "$rc" -eq 0
assert "repin: the note and the value of the version 3 file are kept" is_v3 gate $NEW "$ML" "$NOTE"
assert "repin: the version 2 file becomes version 3 with no note" is_v3 engine $NEW "$T1F" ""
pv "$NEW\n" get gate
assert "repin: get still shows the note" test "$(errs | grep -c -F -- "$NOTE")" -ge 1

echo "== update: no value, encoded or not, in any argument or environment =="
UTK=leak-probe-update-token-3e7c
UV=$tmp/leak2.val
printf -- '-----BEGIN UPDATE KEY-----\nleak-probe-up-cccc3333\nleak-probe-up-dddd4444\n-----END UPDATE KEY-----\n' >"$UV"
UB1=$(base64 -w0 <"$UV" | cut -c1-40); UB2=$(base64 -w0 <"$UV" | cut -c41-80); UB3=$(base64 -w0 <"$UV" | cut -c81-120)
UTB=$(printf '%s' "$UTK" | base64 -w0)
fresh; recv_spy gate; recv_spy gate2
: >"$tmp/spy.log"
export SPY_LOG=$tmp/spy.log
oldpath=$PATH; export PATH=$tmp/spy:$PATH
enroll $LP gate "$(recv gate)" $T1
pv "$LP\n$UTK\n" update gate --token
tk_rc=$rc
pvs "$LP\n" "$UV" update gate --token --stdin
st_rc=$rc
pv "$LP\n" update gate --note "a note"
pv "$LP\n" update gate --receiver "$(recv gate2)"
pv "$LP\n" unlock
unlock_rc=$rc
pv "$LP\n" get gate
PATH=$oldpath; unset SPY_LOG
assert "control: update --token and update --token --stdin worked with the spies in the path" test "$tk_rc" -eq 0 -a "$st_rc" -eq 0 -a "$unlock_rc" -eq 0
assert "control: the receiver got the last value (cmp)" cmp -s "$tmp/got.gate2" "$UV"
assert "control: the spies and the receiver's process dump were written" test -s "$tmp/spy.log"
assert "update: the typed token is in no dumped argument or environment" test "$(grep -c -a -F -e "$UTK" "$tmp/spy.log")" = 0
assert "update: the typed token in base64 is in none either" test "$(grep -c -a -F -e "$UTB" -e "$(printf '%s' "$UTK" | base64 -w0 | cut -c1-24)" "$tmp/spy.log")" = 0
assert "update --stdin: no line of the value is in any dumped argument or environment" test "$(grep -c -a -F -e leak-probe-up-cccc3333 -e leak-probe-up-dddd4444 -e 'BEGIN UPDATE KEY' "$tmp/spy.log")" = 0
assert "update --stdin: no part of its base64 is either" test "$(grep -c -a -F -e "$UB1" -e "$UB2" -e "$UB3" "$tmp/spy.log")" = 0
assert "update: the PIN is in none either" test "$(grep -c -a -F -e "$LP" "$tmp/spy.log")" = 0
assert "update: neither value is in the folder in the clear" test "$(grep -r -c -a -F -e "$UTK" -e leak-probe-up -e "$UB1" "$home" 2>/dev/null | grep -vc ':0$')" = 0

echo "== logon.sh: the PIN window of pin-vault, with no gate and no docker in it =="
# The window does one thing: runs `pin-vault unlock` (the PIN is asked there),
# closes on success, stays open on a failure showing it, and with an empty
# vault says so and closes without asking. Nothing in the script names the gate
# or docker, so a docker that is down cannot keep it from asking. pin-vault is
# a fake on PATH whose unlock succeeds or fails; a docker that fails is beside
# it, and must never be called. stdin is a fifo held open and idle, so any read
# for "enter to close" blocks and shows.
NO_PV=0
INSTALL_LOGON=$here/windows/install-logon-task.ps1
lg=$tmp/lg; mkdir -p "$lg/bin" "$lg/vault" "$lg/empty"
cat >"$lg/bin/pin-vault" <<'W'
#!/bin/sh
echo "$*" >> "$LG_CALLS"
if [ -e "$LG_FAIL" ]; then echo "LOGON-FAKE: receiver gate refused" >&2; exit 3; fi
echo "LOGON-FAKE: unlocked"
W
cat >"$lg/bin/docker" <<'W'
#!/bin/sh
echo "$*" >> "$LG_DOCKER"
exit 1
W
chmod +x "$lg/bin/pin-vault" "$lg/bin/docker"
: >"$lg/vault/gate.bin"
export LG_CALLS=$lg/calls LG_FAIL=$lg/fail LG_DOCKER=$lg/docker.calls
lg_start() { : >"$LG_CALLS"; : >"$LG_DOCKER"; rm -f "$lg/hold"; mkfifo "$lg/hold"; exec 9<>"$lg/hold"; }
lg_run() { # <vault dir>: runs to its end on its own
  lg_start
  PATH=$lg/bin:$PATH PIN_VAULT_HOME=$1 timeout 20 "$LOGON" <&9 >"$lg/out" 2>&1
  lgrc=$?
  exec 9>&-
}
lg_open() { # <vault dir>: wait briefly for the prompt to hold, then press a key
  lg_start
  PATH=$lg/bin:$PATH PIN_VAULT_HOME=$1 timeout 20 "$LOGON" <&9 >"$lg/out" 2>&1 &
  local pid=$! i=0
  while [ "$i" -lt 10 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.05
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then lgopen=1; else lgopen=0; fi
  echo >&9
  wait "$pid"; lgrc=$?
  exec 9>&-
}
rm -f "$LG_FAIL"; lgrc=99; lgopen=99
lg_run "$lg/vault"
assert "logon.sh exists and is executable" test -x "$LOGON"
assert "logon.sh: the word gate is nowhere in it, in any case" test -s "$LOGON" -a "$(grep -ci gate "$LOGON")" = 0
assert "logon.sh: the word docker is nowhere in it, in any case" test -s "$LOGON" -a "$(grep -ci docker "$LOGON")" = 0
assert "logon.sh: it runs pin-vault unlock" grep -q unlock "$LOGON"
assert "logon.sh, unlock succeeds: exits 0 without waiting for a key" test "$lgrc" -eq 0
assert "logon.sh, unlock succeeds: pin-vault unlock was run, once" test "$(grep -cx unlock "$LG_CALLS")" -eq 1
assert "logon.sh, docker down: docker is never called" test -x "$LOGON" -a ! -s "$LG_DOCKER"
touch "$LG_FAIL"
lg_open "$lg/vault"
assert "logon.sh, unlock fails: the window stays open, waiting for a key" test "$lgopen" -eq 1
assert "logon.sh, unlock fails: it shows what pin-vault said" grep -q 'receiver gate refused' "$lg/out"
assert "logon.sh, unlock fails: the exit status is not 0" test "$lgrc" -ne 0 -a "$lgrc" -ne 124
assert "logon.sh, unlock fails: pin-vault unlock was run, once" test "$(grep -cx unlock "$LG_CALLS")" -eq 1
assert "logon.sh, unlock fails, docker down: docker is never called" test -x "$LOGON" -a ! -s "$LG_DOCKER"
rm -f "$LG_FAIL"
lg_run "$lg/empty"
assert "logon.sh, empty vault: closes without waiting for a key" test -x "$LOGON" -a "$lgrc" -ne 124
assert "logon.sh, empty vault: says so" grep -Eqi 'empty|nothing|no (token|entr|secret)' "$lg/out"
assert "logon.sh, empty vault: no PIN is asked (pin-vault is not run)" test -x "$LOGON" -a ! -s "$LG_CALLS"
lg_run "$lg/nodir"
assert "logon.sh, no vault folder at all: closes with a message, pin-vault not run" test -x "$LOGON" -a "$lgrc" -ne 124 -a -s "$lg/out" -a ! -s "$LG_CALLS"

echo "== the Windows tasks: pin-vault owns the logon window, ci-runner only the keepalive =="
echo "== install-logon-task.ps1 =="
assert "install-logon-task.ps1 registers 'pin-vault unlock'" grep -q 'pin-vault unlock' "$INSTALL_LOGON"
assert "install-logon-task.ps1 registers it at logon" grep -q AtLogOn "$INSTALL_LOGON"
assert "install-logon-task.ps1 accepts -InstallDir" grep -q 'InstallDir' "$INSTALL_LOGON"
assert "install-logon-task.ps1 starts logon.sh" grep -q 'logon[.]sh' "$INSTALL_LOGON"

[ "$fail" = 0 ] && echo "all pin-vault checks passed" || echo "pin-vault checks FAILED"
exit "$fail"
