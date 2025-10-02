#!/usr/bin/env python3
"""
main.py - CLI orchestrator per SurfaceMinder (EASM basic)

Azioni:
  scan-tcp
  scan-udp
  parse-scans
  set-baseline
  check-baseline
  check-baseline-combined

Questo file usa gli script nel repo (scanner/, parser/) e invia mail tramite mailer.send_mail.
"""
from __future__ import annotations

import os
import sys
import subprocess
import traceback
import configparser
from datetime import datetime
from typing import List, Dict, Tuple, Optional

BASE = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


def read_config_db_path(config_path: str = None) -> str:
    if config_path is None:
        config_path = os.path.join(BASE, "config.ini")
    cfg = configparser.ConfigParser()
    if os.path.exists(config_path):
        try:
            cfg.read(config_path)
            return cfg.get("general", "db_path", fallback=os.path.join(BASE, "db", "easm.sqlite"))
        except Exception:
            return os.path.join(BASE, "db", "easm.sqlite")
    else:
        return os.path.join(BASE, "db", "easm.sqlite")


def read_ips(path: str) -> List[str]:
    if not os.path.exists(path):
        print(f"[!] ips file mancante: {path}")
        return []
    ips: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.append(line)
    return ips


def run_subprocess(cmd: List[str], capture: bool = False, cwd: Optional[str] = None) -> Tuple[int, str]:
    """
    Esegui subprocess e ritorna (returncode, output_str).
    Se capture==True ritorna stdout+stderr.
    """
    try:
        if capture:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=cwd)
            return proc.returncode, proc.stdout
        else:
            proc = subprocess.run(cmd, cwd=cwd)
            return proc.returncode, ""
    except Exception as e:
        return 1, f"Exception executing {' '.join(cmd)}: {e}\n{traceback.format_exc()}"


def scan_tcp(ips_file: str, tenant: str) -> int:
    ips = read_ips(ips_file)
    if not ips:
        print("[!] Nessun IP da scandire (TCP).")
        return 1
    rc_total = 0
    for ip in ips:
        print(f"[scan] TCP -> {ip}")
        cmd = [sys.executable, os.path.join(BASE, "scanner", "tcp_scanner.py"), "--ip", ip, "--tenant", tenant]
        rc, out = run_subprocess(cmd, capture=True)
        if rc != 0:
            rc_total = rc_total or rc
            print(f"[!] scan-tcp failed for {ip}. Output:\n{out}")
        else:
            print(f"[+] scan-tcp completed for {ip}")
    return rc_total


def scan_udp(ips_file: str, tenant: str, udp_ports: Optional[str] = None) -> int:
    ips = read_ips(ips_file)
    if not ips:
        print("[!] Nessun IP da scandire (UDP).")
        return 1
    rc_total = 0
    for ip in ips:
        print(f"[scan] UDP -> {ip}")
        cmd = [sys.executable, os.path.join(BASE, "scanner", "udp_scanner.py"), "--ip", ip, "--tenant", tenant]
        if udp_ports is not None:
            cmd += ["--udp-ports", udp_ports]
        rc, out = run_subprocess(cmd, capture=True)
        if rc != 0:
            rc_total = rc_total or rc
            print(f"[!] scan-udp failed for {ip}. Output:\n{out}")
        else:
            print(f"[+] scan-udp completed for {ip}")
    return rc_total


def parse_scans() -> int:
    print("[ingest] parsing scans (parser/tenant_parser.py --ingest)")
    cmd = [sys.executable, os.path.join(BASE, "parser", "tenant_parser.py"), "--ingest"]
    rc, out = run_subprocess(cmd, capture=True)
    if rc != 0:
        print(f"[!] parse-scans failed. Output:\n{out}")
    else:
        print("[+] parse-scans completed.")
    return rc


def set_baseline(tenant: str, scan_file: Optional[str] = None) -> int:
    if not tenant:
        print("[!] set-baseline richiede --tenant")
        return 1
    if scan_file:
        try:
            sys.path.insert(0, BASE)
            from parser.tenant_parser import set_baseline as _setb
            _setb(tenant, scan_file=scan_file)
            return 0
        except Exception as e:
            print("[!] Errore set-baseline (import):", e)
            print(traceback.format_exc())
            return 2
    else:
        cmd = [sys.executable, os.path.join(BASE, "parser", "tenant_parser.py"), "--set-baseline", tenant]
        rc, out = run_subprocess(cmd, capture=True)
        if rc != 0:
            print(f"[!] set-baseline failed. Output:\n{out}")
        else:
            print("[+] Baseline impostata.")
        return rc


def _format_report(report: Dict[str, Dict]) -> Tuple[str, int]:
    """
    Formatta il report (structure from tenant_parser._compute_delta)
    in una stringa multi-linea completa di proto (tcp/udp), stato e service.
    Ritorna: (body, total_changes)
    """
    lines: List[str] = []
    total = 0
    # sort ips for deterministic output
    for ip, info in sorted(report.items(), key=lambda x: x[0]):
        lines.append(f"\nIP: {ip}")
        if info.get("added"):
            lines.append("  Porte AGGIUNTE:")
            for (p, proto), v in info["added"]:
                svc = v.get("service") if isinstance(v, dict) else ""
                state = v.get("state") if isinstance(v, dict) else ""
                lines.append(f"    - {p}/{proto}   state={state}   svc={svc}")
                total += 1
        if info.get("removed"):
            lines.append("  Porte RIMOSSE:")
            for (p, proto), v in info["removed"]:
                svc = v.get("service") if isinstance(v, dict) else ""
                state = v.get("state") if isinstance(v, dict) else ""
                lines.append(f"    - {p}/{proto}   state={state}   svc={svc}")
                total += 1
        if info.get("changed"):
            lines.append("  Porte CAMBIATE:")
            for (p, proto), prevv, curv in info["changed"]:
                prev_state = prevv.get("state") if isinstance(prevv, dict) else ""
                prev_svc = prevv.get("service") if isinstance(prevv, dict) else ""
                cur_state = curv.get("state") if isinstance(curv, dict) else ""
                cur_svc = curv.get("service") if isinstance(curv, dict) else ""
                lines.append(f"    - {p}/{proto}   {prev_state}/{prev_svc}  ->  {cur_state}/{cur_svc}")
                total += 1
    header = "EASM: report generato"
    body = header + "\n" + "\n".join(lines)
    return body, total


def check_baseline(tenant: str) -> int:
    if not tenant:
        print("[!] check-baseline richiede --tenant")
        return 1
    # ensure ingest first
    parse_rc = parse_scans()
    if parse_rc != 0:
        print("[!] Attenzione: ingest fallito — procedo comunque al confronto (potrebbe non trovare scans).")
    # import comparator
    try:
        sys.path.insert(0, BASE)
        from parser.tenant_parser import compare_baseline_to_latest
    except Exception as e:
        print("[!] Errore import parser.tenant_parser:", e)
        print(traceback.format_exc())
        return 2
    out = compare_baseline_to_latest(tenant)
    latest = out.get("latest_scan_file")
    report = out.get("report", {})
    if not report:
        print("[*] Nessun cambiamento rispetto alla baseline")
        return 0
    body, total = _format_report(report)
    body = f"EASM: cambiamenti vs baseline (tenant={tenant}) — latest_scan: {latest}\n\n" + body
    subj = f"EASM: {total} cambiamenti tenant={tenant}"
    # debug: print body before sending
    print("=== MAIL SUBJECT ===")
    print(subj)
    print("=== MAIL BODY ===")
    print(body)
    print("=== END MAIL DUMP ===")
    try:
        from mailer import send_mail
        send_mail(subj, body)
        print("[+] Mail inviata.")
    except Exception as e:
        print("[!] Errore invio mail:", e)
        print(traceback.format_exc())
        return 3
    return 0


def check_baseline_combined(tenant: str) -> int:
    if not tenant:
        print("[!] check-baseline-combined richiede --tenant")
        return 1
    # ingest first
    parse_rc = parse_scans()
    if parse_rc != 0:
        print("[!] Attenzione: ingest fallito — procedo comunque al confronto (potrebbe non trovare scans).")
    # import comparator combined
    try:
        sys.path.insert(0, BASE)
        from parser.tenant_parser import compare_baseline_to_latest_combined
    except Exception as e:
        print("[!] Errore import parser.tenant_parser:", e)
        print(traceback.format_exc())
        return 2
    out = compare_baseline_to_latest_combined(tenant)
    latest_tcp = out.get("latest_tcp")
    latest_udp = out.get("latest_udp")
    report = out.get("report", {})
    if not report:
        print("[*] Nessun cambiamento rispetto alla baseline (combinato tcp+udp)")
        return 0
    body_core, total = _format_report(report)
    header = f"EASM: cambiamenti vs baseline (tenant={tenant}) [latest_tcp={latest_tcp or '-'} latest_udp={latest_udp or '-'}]"
    body = header + "\n\n" + body_core
    subj = f"EASM: {total} cambiamenti (tcp+udp) tenant={tenant}"

    # debug: print body before sending
    print("=== MAIL SUBJECT ===")
    print(subj)
    print("=== MAIL BODY ===")
    print(body)
    print("=== END MAIL DUMP ===")

    try:
        from mailer import send_mail
        send_mail(subj, body)
        print("[+] Mail inviata (combinata).")
    except Exception as e:
        print("[!] Errore invio mail:", e)
        print(traceback.format_exc())
        return 3
    return 0


def print_help_and_exit():
    help_text = """
Usage: python main.py <action> [--ips-file <file>] [--tenant <tenant>] [--udp-ports <ports>]

Actions:
  scan-tcp
  scan-udp
  parse-scans
  set-baseline
  check-baseline
  check-baseline-combined
"""
    print(help_text.strip())
    sys.exit(1)


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print_help_and_exit()
    action = argv[0]
    # defaults
    ips_file = "ips.txt"
    tenant = None
    udp_ports = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("--ips-file", "--ipsfile"):
            i += 1
            ips_file = argv[i]
        elif a in ("--tenant", "-t"):
            i += 1
            tenant = argv[i]
        elif a in ("--udp-ports", "--udp"):
            i += 1
            udp_ports = argv[i]
        else:
            print(f"[!] Unknown argument: {a}")
            print_help_and_exit()
        i += 1

    if action == "scan-tcp":
        if not tenant:
            print("[!] per scan-tcp specifica --tenant")
            return 1
        return scan_tcp(ips_file, tenant)

    if action == "scan-udp":
        if not tenant:
            print("[!] per scan-udp specifica --tenant")
            return 1
        return scan_udp(ips_file, tenant, udp_ports)

    if action == "parse-scans":
        return parse_scans()

    if action == "set-baseline":
        if not tenant:
            print("[!] specifica --tenant")
            return 1
        return set_baseline(tenant)

    if action == "check-baseline":
        if not tenant:
            print("[!] specifica --tenant")
            return 1
        return check_baseline(tenant)

    if action == "check-baseline-combined":
        if not tenant:
            print("[!] specifica --tenant")
            return 1
        return check_baseline_combined(tenant)

    print_help_and_exit()
    return 0


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
