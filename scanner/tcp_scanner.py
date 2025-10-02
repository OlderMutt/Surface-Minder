#!/usr/bin/env python3
"""Esegui singolo scan TCP con nmap, salva XML in scans/ con nome scan-TIMESTAMP-TCP-<ip>.xml"""
import subprocess
import os
import time
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
NMAP = cfg.get('nmap', 'nmap_cmd', fallback='nmap')
TCP_OPTS = cfg.get('nmap', 'tcp_opts', fallback='-sT -p- -Pn -sV -oX -').split()
SCANS_DIR = cfg.get('general', 'scans_dir', fallback='scans')
TCP_TIMEOUT = cfg.getint('scan', 'tcp_timeout', fallback=600)

os.makedirs(SCANS_DIR, exist_ok=True)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--ip', required=True)
parser.add_argument('--tenant', default='default')
args = parser.parse_args()

ip = args.ip
tenant = args.tenant
TS = time.strftime('%Y%m%d-%H%M%S')
out_file = os.path.join(SCANS_DIR, f"scan-{TS}-tcp-{ip}.xml")
cmd = [NMAP] + TCP_OPTS + [ip]
print('[*] TCP scan:', ' '.join(cmd))
try:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=TCP_TIMEOUT)
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(res.stdout)
    print('[+] TCP scan salvato in', out_file)
except Exception as e:
    print('[!] Errore TCP scan', e)
