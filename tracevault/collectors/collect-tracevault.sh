#!/usr/bin/env bash
# TraceVault Linux evidence collector.
#
# Copies log files (auth, syslog/messages, auditd, web access logs, wtmp/btmp) byte-for-byte,
# exports the systemd journal for a time window, and writes manifest.json with the SHA-256 of
# every file, so the chain of custody starts at collection time. Rotated and gzip-compressed logs
# are copied as they are: TraceVault reads .gz directly.
#
# The script only reads logs and writes into its output folder. It changes no settings, installs
# nothing and sends nothing over the network. Run it as root so protected logs (auth.log, secure,
# btmp, the journal) are readable. Copy the output folder to the analyst machine and run:
#     tracevault ingest-collection <CASE-ID> <folder>
#
# Usage: sudo bash collect-tracevault.sh [options]
#   --since WHEN     journal window start, anything `date -d` accepts (default: "72 hours ago")
#   --until WHEN     journal window end (default: now)
#   --out DIR        output folder, must be new or empty (default: ./TraceVault-<host>-<UTC time>)
#   --examiner NAME  person collecting, recorded in the manifest (default: $SUDO_USER or $USER)
#   --root DIR       collect from a mounted disk image instead of this system (journal read with -D)
#   --host NAME      host name to record (default: hostname, or <root>/etc/hostname)
#   --no-journal     skip the systemd journal export
#   -h, --help       show this help

set -u
set -o pipefail
umask 077

COLLECTOR_VERSION='0.5.0'
SINCE='72 hours ago'
UNTIL='now'
OUT=''
EXAMINER="${SUDO_USER:-${USER:-unknown}}"
ROOT='/'
HOST_NAME=''
JOURNAL=1

usage() { sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$0"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="${2:?--since needs a value}"; shift 2 ;;
    --until) UNTIL="${2:?--until needs a value}"; shift 2 ;;
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --examiner) EXAMINER="${2:?--examiner needs a value}"; shift 2 ;;
    --root) ROOT="${2:?--root needs a value}"; shift 2 ;;
    --host) HOST_NAME="${2:?--host needs a value}"; shift 2 ;;
    --no-journal) JOURNAL=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------- helpers

# JSON string literal: escape backslash, quote and the common control characters, drop the rest.
json_str() {
  local s
  s=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037')
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}
  printf '"%s"' "$s"
}
utc_iso() { date -u -d "$1" '+%Y-%m-%dT%H:%M:%S.000000Z' 2>/dev/null; }
now_iso() { date -u '+%Y-%m-%dT%H:%M:%S.000000Z'; }
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | cut -d' ' -f1
  else shasum -a 256 -- "$1" | cut -d' ' -f1; fi
}
file_size() { wc -c < "$1" | tr -d ' '; }

ROOT="${ROOT%/}"; [ -z "$ROOT" ] && ROOT=''
[ -n "$ROOT" ] && [ ! -d "$ROOT" ] && die "--root $ROOT is not a directory"
SINCE_ISO=$(utc_iso "$SINCE") || die "cannot understand --since '$SINCE'"
UNTIL_ISO=$(utc_iso "$UNTIL") || die "cannot understand --until '$UNTIL'"
SINCE_EPOCH=$(date -u -d "$SINCE" +%s); UNTIL_EPOCH=$(date -u -d "$UNTIL" +%s)
STARTED=$(now_iso)

if [ -z "$HOST_NAME" ]; then
  if [ -z "$ROOT" ]; then HOST_NAME=$(hostname 2>/dev/null || uname -n)
  elif [ -r "$ROOT/etc/hostname" ]; then HOST_NAME=$(head -n1 "$ROOT/etc/hostname")
  else HOST_NAME='unknown-host'; fi
fi
# Used as a file-name prefix (TraceVault reads a web log's host from "<host>_"), so keep it plain.
HOST_SAFE=$(printf '%s' "$HOST_NAME" | tr -c 'A-Za-z0-9.-' '-' | sed 's/-*$//')
[ -z "$HOST_SAFE" ] && HOST_SAFE='host'

if [ -z "$OUT" ]; then OUT="./TraceVault-${HOST_SAFE}-$(date -u +%Y%m%dT%H%M%SZ)"; fi
if [ -e "$OUT" ] && [ -n "$(ls -A -- "$OUT" 2>/dev/null)" ]; then
  die "output folder '$OUT' is not empty. Use a new folder so the collection is unambiguous."
fi
mkdir -p -- "$OUT" || die "cannot create $OUT"
OUT=$(cd -- "$OUT" && pwd)

ELEVATED=false; [ "$(id -u)" -eq 0 ] && ELEVATED=true
if [ "$ELEVATED" = false ]; then
  echo "warning: not running as root - protected logs (auth.log, secure, btmp, journal) may be skipped." >&2
fi

echo "TraceVault Linux collector $COLLECTOR_VERSION on $HOST_NAME${ROOT:+ (image at $ROOT)}"
echo "Journal window: $SINCE_ISO -> $UNTIL_ISO (UTC)"
echo "Output: $OUT"

FILES_JSON=()
SKIPPED_JSON=()
add_file() {   # name channel format events
  local path="$OUT/$1" events="$4"
  [ -z "$events" ] && events=null
  FILES_JSON+=("{\"name\": $(json_str "$1"), \"channel\": $(json_str "$2"), \"format\": $(json_str "$3"), \"events\": $events, \"bytes\": $(file_size "$path"), \"sha256\": \"$(sha256 "$path")\"}")
}
add_skip() { SKIPPED_JSON+=("{\"channel\": $(json_str "$1"), \"reason\": $(json_str "$2")}"); }

# ---------------------------------------------------------------------------- log files

LOGDIR="$ROOT/var/log"
# Quoted: the patterns are expanded later, inside /var/log. Unquoted, bash would expand them
# against the current directory (and nullglob would silently drop them all).
PATTERNS=('auth.log*' 'secure*' 'syslog*' 'messages*' 'audit/audit.log*' 'nginx/access.log*'
          'apache2/access.log*' 'httpd/access_log*' 'wtmp*' 'btmp*')
shopt -s nullglob
found=0
for pattern in "${PATTERNS[@]}"; do
  for src in "$LOGDIR"/$pattern; do
    # Regular files only: never follow a symlink out of /var/log.
    [ -f "$src" ] && [ ! -L "$src" ] || continue
    found=1
    rel="${src#"$LOGDIR"/}"
    name="${HOST_SAFE}_${rel//\//_}"
    if ! cp -p -- "$src" "$OUT/$name" 2>/dev/null; then
      add_skip "/var/log/$rel" "could not read (permission denied? run as root)"
      echo "  - /var/log/$rel : not readable, skipped"
      continue
    fi
    case "$rel" in
      wtmp*|btmp*) fmt=binary; events='' ;;
      *.gz) fmt=gzip; events=$(gzip -dc -- "$OUT/$name" 2>/dev/null | wc -l | tr -d ' ') ;;
      *) fmt=text; events=$(wc -l < "$OUT/$name" | tr -d ' ') ;;
    esac
    add_file "$name" "/var/log/$rel" "$fmt" "$events"
    printf '  + /var/log/%s -> %s (%s%s)\n' "$rel" "$name" "$fmt" "${events:+, $events lines}"
  done
done
[ "$found" -eq 0 ] && add_skip "/var/log" "no auth, syslog, audit, web or login-record files found"

# ---------------------------------------------------------------------------- systemd journal

if [ "$JOURNAL" -eq 1 ]; then
  if ! command -v journalctl >/dev/null 2>&1; then
    add_skip "systemd journal" "journalctl not available"
    echo "  - systemd journal : journalctl not available, skipped"
  else
    jsrc=(); [ -n "$ROOT" ] && jsrc=(-D "$ROOT/var/log/journal")
    name="${HOST_SAFE}_journal.log"
    # short-iso-precise needs systemd >= 233; fall back to short-iso on older systems.
    # "${a[@]+...}" form: an empty array under `set -u` aborts on bash < 4.4 (RHEL/CentOS 7).
    if journalctl ${jsrc[@]+"${jsrc[@]}"} -q --no-pager --utc -o short-iso-precise \
         --since "@$SINCE_EPOCH" --until "@$UNTIL_EPOCH" > "$OUT/$name" 2>/dev/null \
       || journalctl ${jsrc[@]+"${jsrc[@]}"} -q --no-pager --utc -o short-iso \
         --since "@$SINCE_EPOCH" --until "@$UNTIL_EPOCH" > "$OUT/$name" 2>/dev/null; then
      events=$(grep -vc '^-- ' "$OUT/$name" || true)
      add_file "$name" "systemd journal" journal "$events"
      echo "  + systemd journal -> $name ($events lines)"
    else
      rm -f -- "$OUT/$name"
      add_skip "systemd journal" "journalctl failed (no journal, or not readable without root)"
      echo "  - systemd journal : journalctl failed, skipped"
    fi
  fi
fi

# ---------------------------------------------------------------------------- manifest

OS_NAME=$(sed -n 's/^PRETTY_NAME=//p' "$ROOT/etc/os-release" 2>/dev/null | tr -d '"' | head -n1)
[ -z "$OS_NAME" ] && OS_NAME=$(uname -sr)
OFFSET=$(date +%z); SIGN=1; [ "${OFFSET:0:1}" = "-" ] && SIGN=-1
OFFSET_MIN=$(( SIGN * (10#${OFFSET:1:2} * 60 + 10#${OFFSET:3:2}) ))
join() { local IFS=,; printf '%s' "$*"; }

{
  printf '{\n'
  printf '  "collector": "TraceVault Linux collector",\n'
  printf '  "version": %s,\n' "$(json_str "$COLLECTOR_VERSION")"
  printf '  "host": %s,\n' "$(json_str "$HOST_NAME")"
  printf '  "os": %s,\n' "$(json_str "$OS_NAME")"
  printf '  "shell": %s,\n' "$(json_str "bash $BASH_VERSION")"
  printf '  "source_root": %s,\n' "$(json_str "${ROOT:-/}")"
  printf '  "elevated": %s,\n' "$ELEVATED"
  printf '  "examiner": %s,\n' "$(json_str "$EXAMINER")"
  printf '  "collected_by_account": %s,\n' "$(json_str "$(id -un 2>/dev/null || echo unknown)")"
  printf '  "window": {"since": "%s", "until": "%s"},\n' "$SINCE_ISO" "$UNTIL_ISO"
  printf '  "started_at": "%s",\n' "$STARTED"
  printf '  "finished_at": "%s",\n' "$(now_iso)"
  printf '  "host_utc_offset_minutes": %s,\n' "$OFFSET_MIN"
  printf '  "files": [%s],\n' "$(join "${FILES_JSON[@]+"${FILES_JSON[@]}"}")"
  printf '  "skipped": [%s]\n' "$(join "${SKIPPED_JSON[@]+"${SKIPPED_JSON[@]}"}")"
  printf '}\n'
} > "$OUT/manifest.json"

echo
echo "Done. ${#FILES_JSON[@]} file(s), ${#SKIPPED_JSON[@]} skipped."
echo "manifest.json SHA-256: $(sha256 "$OUT/manifest.json")"
echo "  Record this hash in your notes; TraceVault logs it again at ingest."
echo "Next, on the analyst machine:  tracevault ingest-collection <CASE-ID> \"$OUT\""
