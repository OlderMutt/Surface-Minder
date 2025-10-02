#!/usr/bin/env python3
"""
clean_reset.py

Backup & reset workspace for SurfaceMinder.

Usage:
    python3 clean_reset.py [--backup-root BACKUP_ROOT] [--yes]

What it does:
 - creates BACKUP_ROOT/<TIMESTAMP>/ and stores:
    - copy of DB file (if exists)
    - SQL dump (iterdump)
    - CSV export of baseline_ports (if present)
    - all scans/*.xml
    - all logs/*
    - config.ini (copy)
    - cleanup-<timestamp>.log
 - then removes/moves old artifacts from workspace:
    - moves or removes scans/*.xml
    - moves or removes logs/*
    - moves DB to backup and creates a fresh DB file (optionally calls parser.tenant_parser.init_db(conn))
"""
from __future__ import annotations

import argparse
import configparser
import csv
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent


def read_config_paths(config_path: Path = None):
    cfg_db = HERE / "db" / "easm.sqlite"
    cfg_scans = HERE / "scans"
    cfg_logs = HERE / "logs"
    if config_path is None:
        config_path = HERE / "config.ini"
    if config_path.exists():
        cp = configparser.ConfigParser()
        try:
            cp.read(str(config_path))
            db_path = cp.get("general", "db_path", fallback=str(cfg_db))
            scans_dir = cp.get("general", "scans_dir", fallback=str(cfg_scans))
            logs_dir = cp.get("general", "logs_dir", fallback=str(cfg_logs))
            return Path(db_path).resolve(), Path(scans_dir).resolve(), Path(logs_dir).resolve()
        except Exception:
            return cfg_db.resolve(), cfg_scans.resolve(), cfg_logs.resolve()
    else:
        return cfg_db.resolve(), cfg_scans.resolve(), cfg_logs.resolve()


def ensure_dir(p: Path):
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True)


def atomic_move(src: Path, dst: Path):
    """
    Try to move; if moving across devices fails, fall back to copy & unlink.
    """
    ensure_dir(dst.parent)
    try:
        shutil.move(str(src), str(dst))
    except Exception:
        # fallback: copy then remove
        shutil.copy2(str(src), str(dst))
        try:
            src.unlink()
        except Exception:
            pass


def copy_all_matching(src_dir: Path, dst_dir: Path, pattern: str = "*"):
    ensure_dir(dst_dir)
    files = list(src_dir.glob(pattern))
    for f in files:
        if f.is_file():
            shutil.copy2(str(f), str(dst_dir / f.name))


def sql_dump(db_path: Path, out_path: Path):
    try:
        conn = sqlite3.connect(str(db_path))
        with out_path.open("w", encoding="utf-8") as fh:
            for line in conn.iterdump():
                fh.write(f"{line}\n")
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def export_table_csv(db_path: Path, table: str, out_path: Path):
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        conn.close()
        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            if cols:
                writer.writerow(cols)
            for r in rows:
                writer.writerow(r)
        return True, None
    except sqlite3.OperationalError as e:
        return False, f"OperationalError: {e}"
    except Exception as e:
        return False, str(e)


def create_empty_db(db_path: Path) -> bool:
    """
    Create an empty sqlite DB file. Return True on ok.
    """
    ensure_dir(db_path.parent)
    try:
        conn = sqlite3.connect(str(db_path))
        conn.close()
        return True
    except Exception:
        return False


def try_init_db_with_parser(db_path: Path) -> tuple[bool, Optional[str]]:
    """
    Try to import parser.tenant_parser.init_db(conn) and call it to create schema.
    Returns (True, None) if OK, (False, error_msg) otherwise.
    """
    try:
        sys.path.insert(0, str(HERE))
        import parser.tenant_parser as tp  # type: ignore
        conn = sqlite3.connect(str(db_path))
        if hasattr(tp, "init_db"):
            tp.init_db(conn)
            conn.commit()
            conn.close()
            return True, None
        else:
            conn.close()
            return False, "parser.tenant_parser has no init_db function"
    except Exception as e:
        return False, str(e)


def write_log(log_path: Path, lines: list[str]):
    ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")


def main():
    ap = argparse.ArgumentParser(description="Backup & reset SurfaceMinder workspace")
    ap.add_argument("--backup-root", default="backup", help="Backup root folder (default: backup)")
    ap.add_argument("--yes", action="store_true", help="Proceed without interactive confirmation")
    args = ap.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_root = (HERE / args.backup_root).resolve()
    dest = backup_root / timestamp
    ensure_dir(dest)

    db_path, scans_dir, logs_dir = read_config_paths()
    cfg_file = HERE / "config.ini"

    log_lines: list[str] = []
    def log(msg: str):
        ts = datetime.now().isoformat()
        line = f"{ts}  {msg}"
        print(line)
        log_lines.append(line)

    log(f"Starting CLEAN RESET at {timestamp}")
    log(f"Workspace: {HERE}")
    log(f"DB path: {db_path}")
    log(f"Scans dir: {scans_dir}")
    log(f"Logs dir: {logs_dir}")
    log(f"Backup destination: {dest}")

    # confirmation
    if not args.yes:
        ans = input(f"Proceed and backup+reset workspace to {dest}? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            log("Operation cancelled by user.")
            write_log(dest / f"cleanup-{timestamp}.log", log_lines)
            return 0

    # 1) Backup DB file (if exist)
    if db_path.exists():
        log("Backing up DB file...")
        dest_db_dir = dest / "db"
        ensure_dir(dest_db_dir)
        try:
            shutil.copy2(str(db_path), str(dest_db_dir / db_path.name))
            log(f"Copied DB file to {dest_db_dir / db_path.name}")
        except Exception as e:
            log(f"ERROR copying DB file: {e}")

        # 1b) SQL dump
        dump_path = dest_db_dir / f"db-dump-{timestamp}.sql"
        ok, err = sql_dump(db_path, dump_path)
        if ok:
            log(f"SQL dump created: {dump_path}")
        else:
            log(f"SQL dump failed: {err}")

        # 1c) export baseline_ports to CSV (if table exists)
        csv_out = dest / "exports"
        ensure_dir(csv_out)
        csv_file = csv_out / f"baseline_ports-{timestamp}.csv"
        ok, err = export_table_csv(db_path, "baseline_ports", csv_file)
        if ok:
            log(f"Exported baseline_ports to CSV: {csv_file}")
        else:
            log(f"baseline_ports export skipped / failed: {err}")
    else:
        log("No DB file found; skipping DB backup steps.")

    # 2) Backup scans/*.xml
    if scans_dir.exists() and scans_dir.is_dir():
        dest_scans = dest / "scans"
        ensure_dir(dest_scans)
        xmls = list(scans_dir.glob("*.xml"))
        if xmls:
            for f in xmls:
                try:
                    shutil.move(str(f), str(dest_scans / f.name))
                except Exception:
                    try:
                        shutil.copy2(str(f), str(dest_scans / f.name))
                        f.unlink(missing_ok=True)
                    except Exception as e:
                        log(f"Error moving/copying scan {f}: {e}")
            log(f"Moved {len(xmls)} xml files to {dest_scans}")
        else:
            log("No xml files in scans/ to backup.")
    else:
        log("Scans directory does not exist; skipping scans backup.")

    # 3) Backup logs/*
    if logs_dir.exists() and logs_dir.is_dir():
        dest_logs = dest / "logs"
        ensure_dir(dest_logs)
        logs_files = list(logs_dir.iterdir())
        if logs_files:
            for f in logs_files:
                if f.is_file():
                    try:
                        shutil.move(str(f), str(dest_logs / f.name))
                    except Exception:
                        try:
                            shutil.copy2(str(f), str(dest_logs / f.name))
                            f.unlink(missing_ok=True)
                        except Exception as e:
                            log(f"Error moving/copying log {f}: {e}")
            log(f"Moved {len(list(dest_logs.iterdir()))} log files to {dest_logs}")
        else:
            log("No files in logs/ to backup.")
    else:
        log("Logs directory does not exist; skipping logs backup.")

    # 4) copy config.ini (if present)
    if cfg_file.exists():
        dest_cfg = dest / "config"
        ensure_dir(dest_cfg)
        try:
            shutil.copy2(str(cfg_file), str(dest_cfg / cfg_file.name))
            log(f"Copied config.ini to {dest_cfg}")
        except Exception as e:
            log(f"Error copying config.ini: {e}")
    else:
        log("No config.ini found; skipping copy")

    # 5) move DB and create fresh DB
    if db_path.exists():
        try:
            moved_db_name = f"old-db-{timestamp}.sqlite"
            dest_db_dir = dest / "db"
            ensure_dir(dest_db_dir)
            atomic_move(db_path, dest_db_dir / moved_db_name)
            log(f"Moved DB to backup as {dest_db_dir / moved_db_name}")
        except Exception as e:
            log(f"Error moving DB to backup: {e}")

        # create new db file
        created = create_empty_db(db_path)
        if created:
            log(f"Created new empty DB at {db_path}")
            # try to initialize schema via parser
            ok, err = try_init_db_with_parser(db_path)
            if ok:
                log("Initialized new DB schema via parser.tenant_parser.init_db")
            else:
                log(f"Could not initialize schema via parser: {err} — DB is empty but present")
        else:
            log("Failed to create fresh DB file (see errors).")
    else:
        # ensure parent dir exists and create new db
        ensure_dir(db_path.parent)
        created = create_empty_db(db_path)
        if created:
            log(f"Created new empty DB at {db_path}")
            ok, err = try_init_db_with_parser(db_path)
            if ok:
                log("Initialized DB schema via parser.tenant_parser.init_db")
            else:
                log(f"No parser/init available or failed: {err}")
        else:
            log("Failed to create DB where none existed before.")

    # 6) final cleanup: ensure scans/ and logs/ are empty
    if scans_dir.exists() and scans_dir.is_dir():
        for f in scans_dir.glob("*.xml"):
            try:
                f.unlink()
            except Exception:
                pass
        log("Cleaned scans/ (removed xmls)")

    if logs_dir.exists() and logs_dir.is_dir():
        for f in logs_dir.iterdir():
            try:
                if f.is_file():
                    f.unlink()
                elif f.is_dir():
                    shutil.rmtree(str(f))
            except Exception:
                pass
        log("Cleaned logs/ (removed files)")

    # write cleanup log inside backup
    cleanup_log = dest / f"cleanup-{timestamp}.log"
    write_log(cleanup_log, log_lines)
    log(f"Cleanup log written to {cleanup_log}")

    print()
    log("CLEAN RESET completed.")
    log(f"Backup stored in: {dest}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
