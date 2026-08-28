#!/bin/sh
set -eu

display="${I3LOCK_XEPHYR_DISPLAY:-:99}"
screen="${I3LOCK_XEPHYR_SCREEN:-1280x720}"
i3lock_bin="${I3LOCK_UNDER_TEST:-./build/i3lock}"

if [ ! -x "$i3lock_bin" ]; then
    echo "error: i3lock binary is not executable: $i3lock_bin" >&2
    echo "hint: build it first with: meson compile -C build" >&2
    exit 1
fi

if ! command -v Xephyr >/dev/null 2>&1; then
    echo "error: Xephyr is not installed or not in PATH" >&2
    exit 1
fi

if ! command -v journalctl >/dev/null 2>&1; then
    echo "warning: journalctl is not available; skipping Himmelblau log hint" >&2
fi

cleanup() {
    if [ "${xephyr_pid:-}" ]; then
        kill "$xephyr_pid" >/dev/null 2>&1 || true
        wait "$xephyr_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

unset LD_PRELOAD
unset I3LOCK_PAM_HARNESS_SOCKET
unset I3LOCK_PAM_HARNESS_ACCT_RESULT
unset I3LOCK_PAM_HARNESS_SETCRED_RESULT

echo "Starting Xephyr on display $display with screen $screen"
Xephyr "$display" -screen "$screen" -ac &
xephyr_pid=$!

sleep 1

if ! kill -0 "$xephyr_pid" >/dev/null 2>&1; then
    echo "error: Xephyr exited before i3lock could start" >&2
    exit 1
fi

echo "Running real PAM/Himmelblau test with: $i3lock_bin"
echo "Focus the Xephyr window, then enter your real PAM/Himmelblau credentials."
echo "Optional log watcher in another terminal:"
echo "  journalctl -fu himmelblaud -u himmelblaud-tasks"

DISPLAY="$display" "$i3lock_bin" --nofork --debug --color 000000
