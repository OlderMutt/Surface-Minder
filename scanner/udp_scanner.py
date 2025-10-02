#!/usr/bin/env python3
"""Esegui singolo scan UDP con nmap (porte configurabili) e salva XML"""
import subprocess
import os
import time
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
NMAP = cfg.get('nmap', 'nmap_cmd', fallback='nmap')
UDP_PORTS = cfg.get('nmap', 'udp_ports', fallback='53,67-69,123').strip()
UDP_OPTS_TEMPLATE = ['-sU', '-Pn', '-sV', '-oX', '-', '-p']
SCANS_DIR = cfg.get('general', 'scans_dir', fallback='scans')
UDP_TIMEOUT = cfg.getint('scan', 'udp_timeout', fallback=1800)

os.makedirs(SCANS_DIR, exist_ok=True)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--ip', required=True)
parser.add_argument('--udp-ports', default=UDP_PORTS)
parser.add_argument('--tenant', default='default')
args = parser.parse_args()

ip = args.ip
tenant = args.tenant
udp_ports = args.udp_ports
TS = time.strftime('%Y%m%d-%H%M%S')
out_file = os.path.join(SCANS_DIR, f"scan-{TS}-udp-{ip}.xml")
cmd = [NMAP] + UDP_OPTS_TEMPLATE + [udp_ports, ip]
print('[*] UDP scan:', ' '.join(cmd))
try:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=UDP_TIMEOUT)
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(res.stdout)
    print('[+] UDP scan salvato in', out_file)
except Exception as e:
    print('[!] Errore UDP scan', e)
