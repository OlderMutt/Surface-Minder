#!/usr/bin/env python3
"""
Tenant-aware parser (aggiornato)
- ingest_all_scans, set_baseline e compare_baseline_to_latest rimangono
- aggiunta compare_baseline_to_latest_combined(tenant) che aggrega latest TCP+UDP scans
"""
import os
import sqlite3
import xml.etree.ElementTree as ET
from configparser import ConfigParser
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(__file__))
cfg = ConfigParser()
cfg.read(os.path.join(BASE, 'config.ini'))
SCANS_DIR = cfg.get('general', 'scans_dir', fallback=os.path.join(BASE, 'scans'))
DB_PATH = cfg.get('general', 'db_path', fallback=os.path.join(BASE, 'db', 'easm.sqlite'))

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db(conn):
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS scan_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_file TEXT UNIQUE,
        scan_type TEXT,
        created_at TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_file TEXT,
        ip TEXT,
        port INTEGER,
        proto TEXT,
        state TEXT,
        service TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS baseline_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT,
        ip TEXT,
        port INTEGER,
        proto TEXT,
        state TEXT,
        service TEXT,
        set_at TEXT
    )
    ''')
    conn.commit()

def parse_nmap_xml_path(path):
    """Legge un file XML nmap e ritorna lista di record {ip,port,proto,state,service}"""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        print('[!] Parse error', path, e)
        return []
    out = []
    for host in root.findall('host'):
        addr = None
        for a in host.findall('address'):
            if a.get('addr'):
                addr = a.get('addr')
                break
        if not addr:
            continue
        ports = host.find('ports')
        if ports is None:
            continue
        for p in ports.findall('port'):
            try:
                portid = int(p.get('portid'))
            except Exception:
                continue
            proto = p.get('protocol')
            state_el = p.find('state')
            state = state_el.get('state') if state_el is not None else ''
            service_el = p.find('service')
            service = service_el.get('name') if service_el is not None and 'name' in service_el.attrib else ''
            out.append({'ip': addr, 'port': portid, 'proto': proto, 'state': state, 'service': service})
    return out

def ingest_all_scans(scans_dir=SCANS_DIR, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    init_db(conn)
    c = conn.cursor()
    files = sorted([os.path.join(scans_dir, f) for f in os.listdir(scans_dir) if f.endswith('.xml')])
    for fpath in files:
        fname = os.path.basename(fpath)
        # decide type da filename (tcp/udp) se presente
        typ = 'unknown'
        if '-tcp-' in fname:
            typ = 'tcp'
        elif '-udp-' in fname:
            typ = 'udp'
        # inserisci scan_file se non esiste
        c.execute('SELECT 1 FROM scan_files WHERE scan_file=?', (fname,))
        if c.fetchone():
            # già processato
            continue
        created_at = datetime.utcnow().isoformat() + 'Z'
        c.execute('INSERT INTO scan_files (scan_file, scan_type, created_at) VALUES (?,?,?)', (fname, typ, created_at))
        records = parse_nmap_xml_path(fpath)
        for r in records:
            c.execute('INSERT INTO ports (scan_file, ip, port, proto, state, service) VALUES (?,?,?,?,?,?)',
                      (fname, r['ip'], r['port'], r['proto'], r['state'], r['service']))
        conn.commit()
        print('[+] Ingested', fname, 'records:', len(records))
    conn.close()

def set_baseline(tenant, scan_file=None, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    init_db(conn)
    c = conn.cursor()
    if not scan_file:
        c.execute('SELECT scan_file FROM scan_files ORDER BY id DESC LIMIT 1')
        r = c.fetchone()
        if not r:
            print('[!] Nessun scan presente per impostare baseline')
            return
        scan_file = r[0]
    # pulisci baseline tenant precedente
    c.execute('DELETE FROM baseline_ports WHERE tenant=?', (tenant,))
    # prendi tutte le righe per scan_file e inseriscile come baseline
    c.execute('SELECT ip, port, proto, state, service FROM ports WHERE scan_file=?', (scan_file,))
    rows = c.fetchall()
    set_at = datetime.utcnow().isoformat() + 'Z'
    for ip, port, proto, state, service in rows:
        c.execute('INSERT INTO baseline_ports (tenant, ip, port, proto, state, service, set_at) VALUES (?,?,?,?,?,?,?)',
                  (tenant, ip, port, proto, state, service, set_at))
    conn.commit()
    print(f'[+] Baseline impostata per tenant {tenant} da scan {scan_file} ({len(rows)} record)')
    conn.close()

def compare_baseline_to_latest(tenant, db_path=DB_PATH):
    """Compara baseline del tenant con l'ultima scansione (vecchia funzione)"""
    conn = sqlite3.connect(db_path)
    init_db(conn)
    c = conn.cursor()
    c.execute('SELECT ip, port, proto, state, service FROM baseline_ports WHERE tenant=?', (tenant,))
    b_rows = c.fetchall()
    baseline = {}
    for ip, port, proto, state, service in b_rows:
        baseline.setdefault(ip, {})[(port, proto)] = {'state': state, 'service': service}
    c.execute('SELECT scan_file FROM scan_files ORDER BY id DESC LIMIT 1')
    r = c.fetchone()
    if not r:
        print('[!] Nessuna scansione trovata per confronto')
        return {}
    latest = r[0]
    c.execute('SELECT ip, port, proto, state, service FROM ports WHERE scan_file=?', (latest,))
    cur_rows = c.fetchall()
    current = {}
    for ip, port, proto, state, service in cur_rows:
        current.setdefault(ip, {})[(port, proto)] = {'state': state, 'service': service}
    report = _compute_delta(baseline, current)
    conn.close()
    return {'latest_scan_file': latest, 'report': report}

def _compute_delta(baseline, current):
    report = {}
    ips = set(list(baseline.keys()) + list(current.keys()))
    for ip in ips:
        b_map = baseline.get(ip, {})
        c_map = current.get(ip, {})
        added = []
        removed = []
        changed = []
        for k, v in c_map.items():
            if k not in b_map:
                added.append((k, v))
            else:
                if v != b_map[k]:
                    changed.append((k, b_map[k], v))
        for k, v in b_map.items():
            if k not in c_map:
                removed.append((k, v))
        if added or removed or changed:
            report[ip] = {'added': added, 'removed': removed, 'changed': changed}
    return report

def compare_baseline_to_latest_combined(tenant, db_path=DB_PATH):
    """
    Confronta la baseline del tenant con l'ultima scansione TCP + l'ultima scansione UDP
    e restituisce un unico report combinato.
    Ritorna dict: {'latest_tcp': <scan_file or None>, 'latest_udp': <scan_file or None>, 'report': {...}}
    """
    conn = sqlite3.connect(db_path)
    init_db(conn)
    c = conn.cursor()

    # baseline map
    c.execute('SELECT ip, port, proto, state, service FROM baseline_ports WHERE tenant=?', (tenant,))
    b_rows = c.fetchall()
    baseline = {}
    for ip, port, proto, state, service in b_rows:
        baseline.setdefault(ip, {})[(port, proto)] = {'state': state, 'service': service}

    # trova ultimo TCP e ultimo UDP (se presenti)
    c.execute("SELECT scan_file FROM scan_files WHERE scan_type='tcp' ORDER BY id DESC LIMIT 1")
    r_tcp = c.fetchone()
    latest_tcp = r_tcp[0] if r_tcp else None

    c.execute("SELECT scan_file FROM scan_files WHERE scan_type='udp' ORDER BY id DESC LIMIT 1")
    r_udp = c.fetchone()
    latest_udp = r_udp[0] if r_udp else None

    # costruisci la mappa 'current' combinata da TCP e UDP
    current = {}
    if latest_tcp:
        c.execute('SELECT ip, port, proto, state, service FROM ports WHERE scan_file=?', (latest_tcp,))
        for ip, port, proto, state, service in c.fetchall():
            current.setdefault(ip, {})[(port, proto)] = {'state': state, 'service': service}
    if latest_udp:
        c.execute('SELECT ip, port, proto, state, service FROM ports WHERE scan_file=?', (latest_udp,))
        for ip, port, proto, state, service in c.fetchall():
            # se c'è duplicato con tcp, udp entries are distinct by proto value
            current.setdefault(ip, {})[(port, proto)] = {'state': state, 'service': service}

    report = _compute_delta(baseline, current)
    conn.close()
    return {'latest_tcp': latest_tcp, 'latest_udp': latest_udp, 'report': report}

def list_tenants(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT DISTINCT tenant FROM baseline_ports')
    res = [r[0] for r in c.fetchall()]
    conn.close()
    return res

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--ingest', action='store_true')
    parser.add_argument('--set-baseline', help='tenant name to set baseline from latest scan')
    parser.add_argument('--compare', help='tenant name to compare baseline to latest and print report')
    parser.add_argument('--compare-combined', help='tenant name to compare baseline to latest tcp+udp and print report')
    args = parser.parse_args()
    if args.ingest:
        ingest_all_scans()
    if args.set_baseline:
        set_baseline(args.set_baseline)
    if args.compare:
        out = compare_baseline_to_latest(args.compare)
        print('Latest scan:', out.get('latest_scan_file'))
        import json
        print(json.dumps(out.get('report', {}), indent=2))
    if args.compare_combined:
        out = compare_baseline_to_latest_combined(args.compare_combined)
        print('Latest tcp:', out.get('latest_tcp'), 'Latest udp:', out.get('latest_udp'))
        import json
        print(json.dumps(out.get('report', {}), indent=2))
