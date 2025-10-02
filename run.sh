#!/usr/bin/env bash
# run.sh — runner EASM (Linux) with tenant validation and automatic UDP using config.ini
# POSIX-friendly-ish: evita ((..)), [[..]] e ${var:0:1}
set -euo pipefail

# defaults
IPS_FILE="ips.txt"
TENANT=""
OVERRIDE_UDP_PORTS=""
OVERRIDE_UDP_SET="false"

# parse minimal args
while [ $# -gt 0 ]; do
  case "$1" in
    --ips-file) IPS_FILE="$2"; shift 2 ;;
    --tenant|-t) TENANT="$2"; shift 2 ;;
    --udp-ports) OVERRIDE_UDP_PORTS="$2"; OVERRIDE_UDP_SET="true"; shift 2 ;;
    --help|-h) echo "Usage: $0 --tenant TENANT [--ips-file ips.txt] [--udp-ports \"53,123\"]"; exit 0 ;;
    *) echo "Unknown arg: $1"; echo "Run with --help for usage"; exit 1 ;;
  esac
done

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="$WORKDIR/logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/run_easm-$(date +%F-%H%M%S).log"

LOCKDIR="$WORKDIR/.easm_runner.lockdir"
PIDFILE="$LOCKDIR/pid"

# acquire lock with stale-lock detection
if mkdir "$LOCKDIR" 2>/dev/null; then
  echo "$$" > "$PIDFILE"
  trap 'rm -rf "$LOCKDIR"' EXIT
else
  if [ -f "$PIDFILE" ]; then
    oldpid=$(cat "$PIDFILE" 2>/dev/null || echo "")
    if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
      echo "Another run (PID $oldpid) is in progress. Exiting." | tee -a "$LOGFILE"
      exit 0
    else
      echo "Stale lock found (pid:$oldpid). Removing stale lock and continuing." | tee -a "$LOGFILE"
      rm -rf "$LOCKDIR"
      mkdir "$LOCKDIR"
      echo "$$" > "$PIDFILE"
      trap 'rm -rf "$LOCKDIR"' EXIT
    fi
  else
    echo "Lock exists without pid file; removing stale lock." | tee -a "$LOGFILE"
    rm -rf "$LOCKDIR"
    mkdir "$LOCKDIR"
    echo "$$" > "$PIDFILE"
    trap 'rm -rf "$LOCKDIR"' EXIT
  fi
fi

log() {
  echo "$(date '+%F %T')    $*" | tee -a "$LOGFILE"
}

log "=== EASM run start $(date) ips_file=$IPS_FILE"

# tenant prompt if not provided
if [ -z "$TENANT" ]; then
  printf "Insert tenant to use (e.g. testtenant): "
  read -r TENANT
fi
TENANT="${TENANT:-}"

if [ -z "$TENANT" ]; then
  echo "[!] tenant non fornito. Esco." | tee -a "$LOGFILE"
  exit 1
fi

log "Tenant: $TENANT"

# read config values (db_path and udp_ports) via python for robustness
get_config_values() {
  python3 - <<'PY'
import configparser, os, json
cfg = configparser.ConfigParser()
cfg_path = os.path.join(os.getcwd(), "config.ini")
out = {"db_path": os.path.join(os.getcwd(),"db","easm.sqlite"), "udp_ports": ""}
if os.path.exists(cfg_path):
    try:
        cfg.read(cfg_path)
        out["db_path"] = cfg.get("general","db_path", fallback=out["db_path"])
        out["udp_ports"] = cfg.get("nmap","udp_ports", fallback="")
    except Exception:
        pass
print(json.dumps(out))
PY
}

cfg_json="$(get_config_values)"
DB_PATH="$(echo "$cfg_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['db_path'])")"
CFG_UDP_PORTS="$(echo "$cfg_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['udp_ports'])")"

# if CLI override provided, use it (including empty string to force skip)
if [ "$OVERRIDE_UDP_SET" = "true" ]; then
  UDP_PORTS="$OVERRIDE_UDP_PORTS"
else
  UDP_PORTS="$CFG_UDP_PORTS"
fi

log "DB path resolved to: $DB_PATH"
if [ -n "$UDP_PORTS" ]; then
  log "UDP ports (will be used): $UDP_PORTS"
else
  log "UDP ports not set in config.ini and no override provided — UDP scan will be skipped."
fi

# function to check tenant existence in DB using python (returns exit code 0 if exists, 1 if not, 2 if error)
check_tenant_exists() {
  TENANT_TO_CHECK="$1"
  DB="$2"
  python3 - <<'PYPY'
import sqlite3, sys, os
tenant = os.environ.get('EASM_TENANT')
db = os.environ.get('EASM_DB')
if not db or not os.path.exists(db):
    print(f"[check] DB not found: {db}", file=sys.stderr)
    sys.exit(2)
try:
    conn = sqlite3.connect(db)
    c = conn.cursor()
    # 1) tenants table?
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tenants'")
        if c.fetchone():
            c.execute("SELECT 1 FROM tenants WHERE name=? LIMIT 1", (tenant,))
            if c.fetchone():
                print("FOUND in tenants")
                sys.exit(0)
    except Exception:
        pass
    # 2) baseline_ports
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_ports'")
        if c.fetchone():
            c.execute("SELECT 1 FROM baseline_ports WHERE tenant=? LIMIT 1", (tenant,))
            if c.fetchone():
                print("FOUND in baseline_ports")
                sys.exit(0)
    except Exception:
        pass
    # 3) scan_files heuristic
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_files'")
        if c.fetchone():
            c.execute("SELECT scan_file FROM scan_files LIMIT 10")
            rows = c.fetchall()
            for r in rows:
                if r and tenant in (r[0] or ""):
                    print("FOUND in scan_files (heuristic)")
                    sys.exit(0)
    except Exception:
        pass
    conn.close()
    sys.exit(1)
except Exception as e:
    print(f"ERROR checking DB: {e}", file=sys.stderr)
    sys.exit(2)
PYPY
}

export EASM_TENANT="$TENANT"
export EASM_DB="$DB_PATH"

log "Verifying tenant exists in DB..."
check_tenant_exists "$TENANT" "$DB_PATH"
CHECK_RC=$?
if [ "$CHECK_RC" -eq 0 ]; then
  log "Tenant '$TENANT' found in DB."
elif [ "$CHECK_RC" -eq 1 ]; then
  echo "[!] Tenant '$TENANT' NOT FOUND in DB. Aborting." | tee -a "$LOGFILE"
  exit 2
else
  echo "[!] Error while checking tenant existence (DB missing or error). Aborting." | tee -a "$LOGFILE"
  exit 3
fi

# ensure ips file exists
if [ ! -f "$WORKDIR/$IPS_FILE" ]; then
  echo "[!] ips file not found: $WORKDIR/$IPS_FILE" | tee -a "$LOGFILE"
  exit 4
fi

# TCP scanning loop
log "=== Avvio scansioni TCP sui target in $IPS_FILE ==="
while IFS= read -r ip || [ -n "$ip" ]; do
  # skip CR and comments/blank lines using case
  ip="${ip%$'\r'}"
  case "$ip" in
    "" | \#*) continue ;;
  esac
  log ">>> TCP scan per $ip"
  if ! python3 "$WORKDIR/main.py" scan-tcp --ips-file "$IPS_FILE" --tenant "$TENANT" >>"$LOGFILE" 2>&1; then
    log "scan-tcp failed for $ip (see log)"
  else
    log "scan-tcp ok for $ip"
  fi
done < "$WORKDIR/$IPS_FILE"

# UDP scanning loop (automatic if UDP_PORTS non-empty)
if [ -n "$UDP_PORTS" ]; then
  log "=== Avvio scansioni UDP sui target in $IPS_FILE (ports: $UDP_PORTS) ==="
  while IFS= read -r ip || [ -n "$ip" ]; do
    ip="${ip%$'\r'}"
    case "$ip" in
      "" | \#*) continue ;;
    esac
    log ">>> UDP scan per $ip"
    if ! python3 "$WORKDIR/main.py" scan-udp --ips-file "$IPS_FILE" --tenant "$TENANT" --udp-ports "$UDP_PORTS" >>"$LOGFILE" 2>&1; then
      log "scan-udp failed for $ip (see log)"
    else
      log "scan-udp ok for $ip"
    fi
  done < "$WORKDIR/$IPS_FILE"
else
  log "UDP scan skipped (no udp_ports configured)"
fi

# ingest
log "=== Ingest (parse-scans) ==="
if ! python3 "$WORKDIR/main.py" parse-scans >>"$LOGFILE" 2>&1; then
  log "parse-scans failed (see log)"
else
  log "parse-scans completed"
fi

# check combined + mail
log "=== Check combinato (TCP+UDP) e invio mail se cambiamenti ==="
if ! python3 "$WORKDIR/main.py" check-baseline-combined --tenant "$TENANT" >>"$LOGFILE" 2>&1; then
  log "check-baseline-combined failed (see log)"
else
  log "check-baseline-combined completed"
fi

log "=== EASM run end $(date) ==="
# lock will be removed by trap
