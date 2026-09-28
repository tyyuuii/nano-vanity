#!/data/data/com.termux/files/usr/bin/bash
#
# Installer for nano-vanity + the `Nanvin` launcher.
#
#   ./install.sh              install (build, copy, create launcher)
#   ./install.sh --uninstall  remove both, leave sources alone
#
# Idempotent: re-running rebuilds and replaces cleanly.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="nano-vanity"
LAUNCHER_NAME="Nanvin"

# Termux ships $PREFIX=/data/data/com.termux/files/usr. Honour it if set, and
# fall back to a sane guess so the script also works in odd shells.
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
BIN_DIR="$PREFIX/bin"
BIN_PATH="$BIN_DIR/$BIN_NAME"
LAUNCHER_PATH="$BIN_DIR/$LAUNCHER_NAME"
DEFAULT_PORT=8787

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_info() { printf '\033[36m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

die() { c_err "error: $*"; exit 1; }

# `pgrep -x` / `pkill -x` are unreliable on Termux: for this binary the
# process's /proc/PID/comm is exactly "nano-vanity", yet pgrep -x returns
# nothing and pkill -x silently fails to kill it. Scan /proc by comm instead.
# This reads the *live process list*, so it avoids the stale-pidfile problem.
proc_pids_by_comm() {
    local want="$1" d comm
    for d in /proc/[0-9]*; do
        [[ -r "$d/comm" ]] || continue
        comm="$(cat "$d/comm" 2>/dev/null)" || continue
        [[ "$comm" == "$want" ]] && printf '%s\n' "${d#/proc/}"
    done
}

# Wait for the given comm to disappear, up to ~3s. Returns 0 if gone.
wait_for_comm_gone() {
    local want="$1"
    for _ in $(seq 1 30); do
        [[ -z "$(proc_pids_by_comm "$want")" ]] && return 0
        sleep 0.1
    done
    [[ -z "$(proc_pids_by_comm "$want")" ]]
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" || "${1:-}" == "-u" ]]; then
    removed=0
    for f in "$LAUNCHER_PATH" "$BIN_PATH"; do
        if [[ -e "$f" ]]; then
            # Refuse to delete something we did not install.
            if [[ "$f" == "$BIN_PATH" && ! -x "$f" ]]; then
                c_warn "skipping $f (not executable)"
                continue
            fi
            rm -f "$f" && { c_ok "removed $f"; removed=1; }
        fi
    done
    for pid in $(proc_pids_by_comm "$BIN_NAME"); do
        kill "$pid" 2>/dev/null || true
    done
    wait_for_comm_gone "$BIN_NAME" || c_warn "$BIN_NAME is still running"
    [[ $removed -eq 1 ]] || c_info "nothing to remove"
    exit 0
fi

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && {
    sed -n '3,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
c_info "==> checking environment"

[[ -f "$REPO_DIR/Cargo.toml" ]] && [[ -d "$REPO_DIR/nano-vanity" ]] \
    || die "run this from the repository root (Cargo.toml + nano-vanity/ not found)"

command -v cargo >/dev/null 2>&1 \
    || die "cargo not found. In Termux: pkg install rust"

if [[ "$PREFIX" != *com.termux* ]]; then
    c_warn "PREFIX does not look like Termux ($PREFIX)."
    c_warn "Continuing, but the launcher assumes a Termux layout."
fi

[[ -d "$BIN_DIR" ]] || die "$BIN_DIR does not exist"
[[ -w "$BIN_DIR" ]] || die "$BIN_DIR is not writable"

if [[ -n "$(proc_pids_by_comm "$BIN_NAME")" ]]; then
    c_warn "a $BIN_NAME process is running; stopping it before replacing the binary"
    for pid in $(proc_pids_by_comm "$BIN_NAME"); do kill "$pid" 2>/dev/null || true; done
    # A process we cannot stop would keep serving the old code, so fail loudly
    # rather than install over it.
    if ! wait_for_comm_gone "$BIN_NAME"; then
        c_err "could not stop pids: $(proc_pids_by_comm "$BIN_NAME" | tr '\n' ' ')"
        die "stop the running $BIN_NAME and re-run"
    fi
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
c_info "==> building (release, jobs kept low for Android's LMK)"
cd "$REPO_DIR"
cargo build --release --bin "$BIN_NAME" \
    || die "build failed"

[[ -x "$REPO_DIR/target/release/$BIN_NAME" ]] \
    || die "build reported success but target/release/$BIN_NAME is missing"

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------
c_info "==> installing binary"
# install(1) writes then moves into place, so an interrupted run cannot leave a
# half-written executable behind.
install -m 0755 "$REPO_DIR/target/release/$BIN_NAME" "$BIN_PATH"

if command -v strip >/dev/null 2>&1; then
    # Best effort: failure here is not worth aborting an otherwise good install.
    strip "$BIN_PATH" 2>/dev/null && c_info "    stripped debug symbols" || true
fi

c_ok "    $BIN_PATH"

# ---------------------------------------------------------------------------
# Install launcher
# ---------------------------------------------------------------------------
c_info "==> installing launcher"

# Written with a quoted heredoc so nothing expands at install time; the single
# placeholder is substituted explicitly below.
TMP_LAUNCHER="$(mktemp "$BIN_DIR/.${LAUNCHER_NAME}.XXXXXX")"
trap 'rm -f "$TMP_LAUNCHER"' EXIT

cat >"$TMP_LAUNCHER" <<'LAUNCHER_EOF'
#!/usr/bin/env bash
#
# Nanvin — start the nano-vanity web UI.
#
#   Nanvin                  start on the default port and open the browser
#   Nanvin -p 9000          use another port
#   Nanvin --no-open        do not open a browser
#   Nanvin --stop           stop a running server
#   Nanvin -h               this help
#
# The web UI is bound to loopback only: anyone who can reach the port could
# start jobs and read the seeds and private keys it produces.

set -euo pipefail

BIN="@NANVIN_BIN@"
PORT="${NANVIN_PORT:-8787}"
OPEN=1
STOP=0

usage() {
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
}

# NOTE: `pgrep -x` / `pkill -x` do not match this binary on Termux (verified:
# the process's /proc/PID/comm is exactly "nano-vanity", yet pgrep -x returns
# nothing and pkill -x fails to kill it). Scan /proc directly instead.
#
# Both helpers only consider processes whose executable is *this* installed
# binary, so a copy running from target/release is deliberately left alone.
pids_of_installed_binary() {
    local d comm exe
    for d in /proc/[0-9]*; do
        [[ -r "$d/comm" ]] || continue
        comm="$(cat "$d/comm" 2>/dev/null)" || continue
        [[ "$comm" == "nano-vanity" ]] || continue
        exe="$(readlink -f "$d/exe" 2>/dev/null)" || continue
        [[ "$exe" == "$BIN" ]] && printf '%s\n' "${d#/proc/}"
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            [[ $# -ge 2 ]] || { echo "error: $1 needs a value" >&2; exit 2; }
            PORT="$2"; shift 2 ;;
        --no-open) OPEN=0; shift ;;
        --stop) STOP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown option: $1" >&2; echo >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "error: bad port: $PORT" >&2; exit 2; }
[[ -x "$BIN" ]] || { echo "error: $BIN not found or not executable. Re-run install.sh" >&2; exit 1; }

if [[ $STOP -eq 1 ]]; then
    found=0
    for pid in $(pids_of_installed_binary); do
        found=1
        echo "stopping nano-vanity (pid $pid)"
        kill "$pid" 2>/dev/null || true
    done
    if [[ $found -eq 0 ]]; then
        echo "nothing to stop (no running nano-vanity from $BIN)"
    else
        for _ in $(seq 1 30); do
            [[ -z "$(pids_of_installed_binary)" ]] && break
            sleep 0.1
        done
        if [[ -n "$(pids_of_installed_binary)" ]]; then
            echo "warn: it did not exit; forcing" >&2
            for pid in $(pids_of_installed_binary); do kill -9 "$pid" 2>/dev/null || true; done
        fi
        echo "stopped"
    fi
    exit 0
fi

URL="http://127.0.0.1:$PORT/"

# Does a *current* nano-vanity serve this port? A bare TCP probe is not enough:
# an old binary (a stale process, or one built before this install) can hold the
# port and answer happily, in which case "already running" would be a lie that
# serves you the wrong code.
server_version() {
    command -v curl >/dev/null 2>&1 || return 1
    curl -fsS --max-time 2 "http://127.0.0.1:$PORT/api/version" 2>/dev/null \
        | sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

# Path of the executable behind any running nano-vanity process, if readable.
running_exe() {
    local pid exe
    for pid in $(pids_of_any_nano_vanity); do
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" && [[ -n "$exe" ]] && { printf '%s\n' "$exe"; return 0; }
    done
    return 1
}

# Any nano-vanity at all, including one running out of target/release.
pids_of_any_nano_vanity() {
    local d comm
    for d in /proc/[0-9]*; do
        [[ -r "$d/comm" ]] || continue
        comm="$(cat "$d/comm" 2>/dev/null)" || continue
        [[ "$comm" == "nano-vanity" ]] && printf '%s\n' "${d#/proc/}"
    done
}

open_browser() {
    [[ $OPEN -eq 1 ]] || return 0
    local opener
    opener="$(command -v termux-open-url || command -v termux-open || true)"
    if [[ -n "$opener" ]]; then
        "$opener" "$URL" >/dev/null 2>&1 || true
        echo "Opened $URL in your browser."
    else
        echo "Open this in a browser: $URL"
    fi
}

# Something listening at all (possibly not ours).
#
# The whole probe, including the fd close, runs in a subshell. A bare
# `exec 3<&-` in the main shell would apply the redirections *permanently* to
# this script — `exec 3<&- 3>&- 2>/dev/null` silently points the launcher's own
# stderr at /dev/null for the rest of the run, so every later warning vanishes.
# `|| true` also hid it by making the exit status successful.
port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
}

if port_open; then
    running="$(server_version || true)"
    exe="$(running_exe || true)"

    if [[ -z "$running" ]]; then
        # Port held by something that is not this program (or not this version
        # of it). Never silently report success here — the user would be looking
        # at a page they did not ask for.
        echo "error: port $PORT is in use by something that is not nano-vanity." >&2
        echo "       Free it, or use another port:  Nanvin -p 9000" >&2
        exit 1
    fi

    if [[ -n "$exe" && "$exe" != "$BIN" ]]; then
        echo "warn: port $PORT is served by a different nano-vanity binary:" >&2
        echo "        $exe" >&2
        echo "      expected: $BIN" >&2
        echo >&2
        echo "      That is a stale process holding the port, running a copy that" >&2
        echo "      Nanvin does not manage (e.g. target/release). Stop it by pid," >&2
        echo "      or just use another port:  Nanvin -p 9000" >&2
        open_browser
        exit 1
    fi

    echo "nano-vanity $running is already running on port $PORT."
    open_browser
    echo
    echo "To stop it:  Nanvin --stop"
    echo "To restart:  Nanvin --stop && Nanvin"
    exit 0
fi

echo "Starting nano-vanity web UI on port $PORT ..."

# Run the server in the background so we can wait for readiness, then hand
# control back to it. Output is streamed to this terminal.
"$BIN" --web --bind "127.0.0.1:$PORT" &
SERVER_PID=$!

# Make sure Ctrl-C and the shell script end the server too, rather than
# orphaning a headless process on a fixed port.
cleanup() {
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT

# Wait for the listener instead of sleeping a fixed amount, so a fast start does
# not pause and a slow one is not declared broken too early.
ready=0
for _ in $(seq 1 100); do
    if [[ -n "$(server_version || true)" ]]; then ready=1; break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "error: the server exited before it was ready" >&2
        wait "$SERVER_PID" 2>/dev/null || true
        exit 1
    fi
    sleep 0.1
done

if [[ $ready -eq 0 ]]; then
    echo "error: server did not become ready on port $PORT after 10s" >&2
    exit 1
fi

echo "Ready: $URL  (nano-vanity $(server_version || echo '?'))"
open_browser
echo "Press Ctrl-C to stop, or run 'Nanvin --stop' from another shell."

# Wait on the server so Ctrl-C shuts everything down cleanly.
wait "$SERVER_PID"
LAUNCHER_EOF

# Substitute the absolute binary path. `|` as the delimiter because paths on
# Android contain slashes but never a pipe.
sed -i "s|@NANVIN_BIN@|$BIN_PATH|g" "$TMP_LAUNCHER"

# Refuse to install a launcher that does not parse. This catches the classic
# heredoc mistake of a multi-line comment whose continuation lines lack `#`,
# which would otherwise only surface as a syntax error on the user's first run.
if ! bash -n "$TMP_LAUNCHER" 2>/dev/null; then
    c_err "internal error: generated launcher has a syntax error:"
    bash -n "$TMP_LAUNCHER" >&2 || true
    die "refusing to install a broken launcher"
fi

# Sanity check
# be installed silently. Written as `if` rather than `grep && die`, because
# under `set -e` a failing `grep` in an `&&` list would abort the script on the
# good path with a confusing trace.
if grep -q '@NANVIN_BIN@' "$TMP_LAUNCHER"; then
    die "internal error: launcher placeholder not substituted"
fi
if ! grep -q "BIN=\"$BIN_PATH\"" "$TMP_LAUNCHER"; then
    die "internal error: launcher binary path wrong"
fi

install -m 0755 "$TMP_LAUNCHER" "$LAUNCHER_PATH"
rm -f "$TMP_LAUNCHER"
trap - EXIT
c_ok "    $LAUNCHER_PATH"

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
c_info "==> verifying"

"$BIN_PATH" --help >/dev/null 2>&1 \
    || die "installed binary does not run"

# The launcher lives in $BIN_DIR, which is on PATH, so this must resolve.
if command -v "$LAUNCHER_NAME" >/dev/null 2>&1; then
    c_ok "    '$(command -v "$LAUNCHER_NAME")' resolves on PATH"
else
    c_warn "    $BIN_DIR is not on PATH; call it as $LAUNCHER_PATH"
fi

if command -v sha256sum >/dev/null 2>&1; then
    printf '    sha256 %s\n' \
        "$(sha256sum "$BIN_PATH" | cut -d' ' -f1)"
fi

echo
c_ok "Installed."
echo
echo "  Nanvin              start the web UI and open the browser"
echo "  Nanvin -p 9000      use another port"
echo "  Nanvin --no-open    start without opening a browser"
echo "  nano-vanity 1111    CLI grind instead (see nano-vanity --help)"
echo "  ./install.sh -u     uninstall"
echo
echo "  Verify any generated address in a wallet before receiving funds."