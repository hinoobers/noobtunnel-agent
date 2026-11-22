#!/bin/sh
set -eu
SERVER='' PIN='' TICKET='' DEADLINE=''
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || { echo 'Missing setup argument' >&2; exit 1; }
  case "$1" in
    --server) SERVER="$2" ;;
    --pin) PIN="$2" ;;
    --ticket) TICKET="$2" ;;
    --deadline) DEADLINE="$2" ;;
    *) echo 'Invalid setup argument' >&2; exit 1 ;;
  esac
  shift 2
done
[ "$(id -u)" = 0 ] || { echo 'Run Quick setup with sudo' >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7|armhf) ARCH=armv7 ;;
  i386|i686) ARCH=386 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
[ -n "$SERVER" ] && [ -n "$PIN" ] && [ -n "$TICKET" ] || exit 1
[ -n "$DEADLINE" ] || DEADLINE=$(( $(date +%s) + 30 ))
REMAINING=$(( DEADLINE - $(date +%s) ))
[ "$REMAINING" -gt 0 ] || { echo 'Quick setup reached its 30-second limit' >&2; exit 1; }
TASK_DIR=$(mktemp -d)
trap 'rm -rf "$TASK_DIR"' EXIT HUP INT TERM
curl -fsSLk --connect-timeout 5 --max-time "$REMAINING" --pinnedpubkey "sha256//$PIN" "https://$SERVER/download/noobtunnel_linux_$ARCH" -o "$TASK_DIR/noobtunnel"
chmod 700 "$TASK_DIR/noobtunnel"
"$TASK_DIR/noobtunnel" quick --server "$SERVER" --pin "$PIN" --ticket "$TICKET" --deadline "$DEADLINE"
