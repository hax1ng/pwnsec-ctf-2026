#!/bin/sh
set -eu

umask 077
runtime_flag=/tmp/.icx-runtime
: "${FLAG:=pwnsec{this_is_fake_flag}}"

case ${#FLAG} in
  [0-7]) echo "flag is too short" >&2; exit 1 ;;
esac
if [ "${#FLAG}" -gt 160 ]; then
  echo "flag is too long" >&2
  exit 1
fi

printf '%s' "$FLAG" > "$runtime_flag"
unset FLAG
exec /app/icx-emu
