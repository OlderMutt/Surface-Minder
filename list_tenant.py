#!/usr/bin/env python3
"""
list_tenants.py

Mostra tutti i tenant "creati" trovati nel DB del progetto.

Comportamento:
 - legge config.ini per trovare db_path (fallback: db/easm.sqlite)
 - se c'è la tabella `tenants`, legge i nomi da lì
 - se c'è la tabella `baseline_ports`, legge tenant distinti e fornisce conteggio + ultima set_at
 - combina i risultati e stampa una tabella umana o JSON (--json)

Usage:
  python3 list_tenants.py
  python3 list_tenants.py --config config.ini
  python3 list_tenants.py --db db/easm.sqlite --json
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

HERE = Path(__file__).resolve().parent


def read_db_path(config_file: Optional[Path]) -> Path:
    default = HERE / "db" / "easm.sqlite"
    if config_file and config_file.exists():
        cfg = configparser.ConfigParser()
        cfg.read(str(config_file))
        try:
            p = cfg.get("general", "db_path", fallback=str(default))
        except Exception:
            p = str(default)
    else:
        p = str(default)
    return Path(p).expanduser().resolve()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=? COLLATE NOCASE", (table,))
    return cur.fetchone() is not None


def tenants_from_tenants_table(conn: sqlite3.Connection) -> List[str]:
    cur = conn.cursor()
    try:
        cur.execute("SELECT DISTINCT name FROM tenants")
        return [row[0] for row in cur.fetchall() if row[0] is not None]
    except Exception:
        return []


def tenants_from_baseline(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    """
    Ritorna dict tenant -> {count, last_set}
    """
    out: Dict[str, Dict[str, Any]] = {}
    cur = conn.cursor()
    try:
        cur.execute("SELECT tenant, COUNT(*) as cnt, MAX(set_at) as last_set FROM baseline_ports GROUP BY tenant")
        for tenant, cnt, last_set in cur.fetchall():
            if tenant is None:
                continue
            out[tenant] = {
                "baseline_count": int(cnt or 0),
                "baseline_last_set": last_set,
            }
    except Exception:
        pass
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="List tenants present in the SurfaceMinder DB")
    ap.add_argument("--config", "-c", help="Path to config.ini (optional)", default=str(HERE / "config.ini"))
    ap.add_argument("--db", help="Direct path to sqlite DB (overrides config)", default=None)
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config) if args.config else None
    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        db_path = read_db_path(cfg_path)

    if args.verbose:
        print(f"[debug] Using DB: {db_path}", file=sys.stderr)

    if not db_path.exists():
        print(f"[!] DB not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    result: Dict[str, Dict[str, Any]] = defaultdict(dict)

    # 1) tenants table
    if table_exists(conn, "tenants"):
        names = tenants_from_tenants_table(conn)
        for n in names:
            result[n].setdefault("in_tenants_table", True)
    else:
        if args.verbose:
            print("[debug] tenants table not present", file=sys.stderr)

    # 2) baseline_ports
    if table_exists(conn, "baseline_ports"):
        baseline_info = tenants_from_baseline(conn)
        for tenant, info in baseline_info.items():
            result[tenant].update(info)
            # mark tenant presence if not already
            result[tenant].setdefault("in_tenants_table", False)
    else:
        if args.verbose:
            print("[debug] baseline_ports table not present", file=sys.stderr)

    conn.close()

    # If still empty, try heuristic: look for tenant-like names in scan_files
    if not result:
        try:
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()
            if table_exists(conn, "scan_files"):
                cur.execute("SELECT DISTINCT scan_file FROM scan_files")
                rows = [r[0] for r in cur.fetchall() if r and isinstance(r[0], str)]
                # heuristic: any token 'tenantname-'? Hard to be exact; just show distinct filenames
                if rows:
                    for r in rows:
                        result[r] = {"in_tenants_table": False, "baseline_count": 0}
            conn.close()
        except Exception:
            pass

    tenants_sorted = sorted(result.items(), key=lambda x: (not x[1].get("in_tenants_table", False), -int(x[1].get("baseline_count", 0))), )

    if args.json:
        # prepare serializable output
        serial = []
        for tenant, info in tenants_sorted:
            entry = {"tenant": tenant}
            entry.update(info)
            serial.append(entry)
        print(json.dumps(serial, indent=2, ensure_ascii=False))
        return 0

    # pretty print table
    if not tenants_sorted:
        print("No tenants found in DB.")
        return 0

    # compute widths
    name_w = max(len("TENANT"), max(len(t) for t, _ in tenants_sorted))
    col1 = "IN_TENANTS_TABLE"
    col2 = "BASELINE_COUNT"
    col3 = "BASELINE_LAST_SET"
    hdr = f"{'TENANT'.ljust(name_w)}  {col1:16}  {col2:14}  {col3}"
    print(hdr)
    print("-" * len(hdr))
    for tenant, info in tenants_sorted:
        in_t = str(bool(info.get("in_tenants_table", False))).ljust(16)
        cnt = str(info.get("baseline_count", 0)).ljust(14)
        last = str(info.get("baseline_last_set", "") or "").ljust(20)
        print(f"{tenant.ljust(name_w)}  {in_t}  {cnt}  {last}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
