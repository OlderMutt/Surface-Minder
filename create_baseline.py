#!/usr/bin/env python3
"""
create_baseline.py

Esegue (opzionale) scan TCP/UDP, ingest e imposta la baseline combinata (ultimo TCP + ultimo UDP)
per il tenant indicato.

Usage:
  python create_baseline.py --tenant TENANT [--ips-file ips.txt] [--udp-ports "53,123"] [--no-scan-tcp] [--no-scan-udp] [--main-py PATH]

Examples:
  python create_baseline.py --tenant testtenant
  python create_baseline.py --tenant testtenant --udp-ports "53,161" --ips-file myips.txt
  python create_baseline.py --tenant testtenant --no-scan-tcp   # usa gli XML già presenti
"""
from __future__ import annotations

import argparse
import configparser
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from typing import List, Optional, Tuple

HERE = os.path.abspath(os.path.dirname(__file__))


def read_config_db_path(config_path: str = None) -> str:
    """Legge config.ini per trovare db_path; se non presente ritorna db/easm.sqlite sotto repo."""
    if config_path is None:
        config_path = os.path.join(HERE, "config.ini")
    cfg = configparser.ConfigParser()
    if os.path.exists(config_path):
        cfg.read(config_path)
        try:
            db_path = cfg.get("general", "db_path", fallback=os.path.join(HERE, "db", "easm.sqlite"))
        except Exception:
            db_path = os.path.join(HERE, "db", "easm.sqlite")
    else:
        db_path = os.path.join(HERE, "db", "easm.sqlite")
    return os.path.abspath(db_path)


def run_main_action(action: str, ips_file: str, tenant: str, udp_ports: Optional[str], main_py: str) -> Tuple[int, str]:
    """
    Esegue 'python main.py <action> ...' e ritorna (returncode, output) catturando stdout+stderr.
    action in {'scan-tcp','scan-udp','parse-scans','set-baseline',...}
    """
    cmd = [sys.executable, main_py, action]
    if action in ("scan-tcp", "scan-udp"):
        cmd += ["--ips-file", ips_file, "--tenant", tenant]
        if action == "scan-udp" and udp_ports:
            cmd += ["--udp-ports", udp_ports]
    # parse-scans doesn't need args
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return proc.returncode, proc.stdout
    except Exception as e:
        return 1, f"Exception running {' '.join(cmd)}: {e}"


def get_latest_scan_files(db_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Ritorna (latest_tcp_scan_file_or_None, latest_udp_scan_file_or_None)."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    latest_tcp = None
    latest_udp = None
    try:
        c.execute("SELECT scan_file FROM scan_files WHERE scan_type='tcp' ORDER BY id DESC LIMIT 1")
        r = c.fetchone()
        if r:
            latest_tcp = r[0]
        c.execute("SELECT scan_file FROM scan_files WHERE scan_type='udp' ORDER BY id DESC LIMIT 1")
        r = c.fetchone()
        if r:
            latest_udp = r[0]
    finally:
        conn.close()
    return latest_tcp, latest_udp


def collect_ports_for_scans(db_path: str, scan_files: List[str]) -> List[Tuple[str, int, str, str, str]]:
    """
    Ritorna lista di tuple: (ip, port, proto, state, service) per i scan_file forniti.
    Se scan_files è vuoto ritorna lista vuota.
    """
    if not scan_files:
        return []
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    placeholders = ",".join("?" for _ in scan_files)
    q = f"SELECT ip, port, proto, state, service FROM ports WHERE scan_file IN ({placeholders})"
    c.execute(q, scan_files)
    rows = c.fetchall()
    conn.close()
    # assicurati i tipi: port int etc.
    out = []
    for r in rows:
        ip, port, proto, state, service = r
        try:
            port = int(port)
        except Exception:
            # leave as-is if not convertible
            pass
        out.append((ip, port, proto, state, service))
    return out


def set_baseline_combined(db_path: str, tenant: str, port_rows: List[Tuple[str, int, str, str, str]]) -> int:
    """
    Sostituisce la baseline_ports per il tenant con i port_rows forniti.
    port_rows: list of (ip, port, proto, state, service)
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # ensure tables exist (defensive)
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_file TEXT UNIQUE,
            scan_type TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_file TEXT,
            ip TEXT,
            port INTEGER,
            proto TEXT,
            state TEXT,
            service TEXT
        );
        CREATE TABLE IF NOT EXISTS baseline_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant TEXT,
            ip TEXT,
            port INTEGER,
            proto TEXT,
            state TEXT,
            service TEXT,
            set_at TEXT
        );
        """
    )
    try:
        # delete old baseline for tenant
        c.execute("DELETE FROM baseline_ports WHERE tenant = ?", (tenant,))
        set_at = datetime.utcnow().isoformat() + "Z"
        if port_rows:
            insert_q = "INSERT INTO baseline_ports (tenant, ip, port, proto, state, service, set_at) VALUES (?,?,?,?,?,?,?)"
            for (ip, port, proto, state, service) in port_rows:
                c.execute(insert_q, (tenant, ip, port, proto, state, service, set_at))
        conn.commit()
        inserted = len(port_rows)
        return inserted
    except Exception as e:
        conn.rollback()
        print("Error writing baseline to DB:", e)
        return -1
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Create combined baseline (latest tcp + latest udp) for a tenant")
    ap.add_argument("--tenant", required=True, help="Tenant name to set baseline")
    ap.add_argument("--ips-file", default="ips.txt", help="File with IPs (one per line)")
    ap.add_argument("--udp-ports", default="", help="Comma-separated UDP ports override")
    ap.add_argument("--no-scan-tcp", action="store_true", help="Do not run TCP scan; use existing XMLs")
    ap.add_argument("--no-scan-udp", action="store_true", help="Do not run UDP scan; use existing XMLs")
    ap.add_argument("--main-py", default=os.path.join(HERE, "main.py"), help="Path to main.py (used to run scan/parsers)")
    ap.add_argument("--skip-ingest", action="store_true", help="Skip parse-scans invocation (if you already ingested)")
    args = ap.parse_args()

    tenant = args.tenant
    ips_file = args.ips_file
    udp_ports = args.udp_ports.strip() or None
    main_py = args.main_py

    if not os.path.exists(main_py):
        print(f"[!] main.py not found at {main_py}. Please adjust --main-py")
        return 10

    # 1) scan TCP
    if not args.no_scan_tcp:
        print("[1/4] Running TCP scan via main.py ...")
        rc, out = run_main_action("scan-tcp", ips_file, tenant, udp_ports, main_py)
        print(out)
        if rc != 0:
            print(f"[!] Warning: scan-tcp returned nonzero exit {rc} (continuing)")

    # 2) scan UDP
    if not args.no_scan_udp:
        print("[2/4] Running UDP scan via main.py ...")
        rc, out = run_main_action("scan-udp", ips_file, tenant, udp_ports, main_py)
        print(out)
        if rc != 0:
            print(f"[!] Warning: scan-udp returned nonzero exit {rc} (continuing)")

    # 3) parse-scans (ingest)
    if not args.skip_ingest:
        print("[3/4] Running parse-scans via main.py ...")
        rc, out = run_main_action("parse-scans", ips_file, tenant, udp_ports, main_py)
        print(out)
        if rc != 0:
            print(f"[!] Warning: parse-scans returned nonzero exit {rc} (continuing)")

    # 4) build combined baseline
    print("[4/4] Building combined baseline from latest TCP + latest UDP ...")
    db_path = read_config_db_path()
    print("DB path:", db_path)
    if not os.path.exists(db_path):
        print("[!] DB not found at", db_path)
        return 20

    latest_tcp, latest_udp = get_latest_scan_files(db_path)
    print("Latest TCP scan file:", latest_tcp)
    print("Latest UDP scan file:", latest_udp)

    scan_files = []
    if latest_tcp:
        scan_files.append(latest_tcp)
    if latest_udp and latest_udp not in scan_files:
        scan_files.append(latest_udp)

    if not scan_files:
        print("[!] No tcp/udp scans found in DB to create baseline. Aborting.")
        return 21

    port_rows = collect_ports_for_scans(db_path, scan_files)
    print(f"Found {len(port_rows)} port rows across scans: {scan_files}")

    inserted = set_baseline_combined(db_path, tenant, port_rows)
    if inserted < 0:
        print("[!] Error inserting baseline into DB")
        return 30

    print(f"[+] Baseline combinata impostata per tenant '{tenant}': {inserted} records (source scans: {scan_files})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
