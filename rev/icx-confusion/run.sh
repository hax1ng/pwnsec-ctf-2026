#!/bin/sh
set -eu

: "${FLAG:?FLAG is required}"
if [ "${#FLAG}" -lt 8 ] || [ "${#FLAG}" -gt 160 ]; then
    echo "invalid FLAG length" >&2
    exit 1
fi
umask 077
printf '%s' "$FLAG" > /tmp/.icx-runtime
unset FLAG
exec /bin/busybox nc -ll -p 1337 -e /app/icx-emu
