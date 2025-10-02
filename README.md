# SurfaceMinder

> This document explains everything: installation, configuration, components, how to create baselines, how scanning, parsing and notifications work, backup & cleanup, tests, debugging, and recommended best practices.

---

## Table of contents

1. Overview
2. Installation & prerequisites
3. File layout (project structure)
4. Configuration files
   - `config.ini` (fields explained)
   - `ips.txt`
5. Database (schema & tables)
6. How the system works (workflow)
7. Scripts and modules — what each does
   - `main.py`
   - `scanner/tcp_scanner.py`
   - `scanner/udp_scanner.py`
   - `parser/tenant_parser.py`
   - `mailer.py`
   - `run.sh`
   - `create_baseline.py`
   - `clean_reset.py`
   - `list_tenants.py`
8. Creating and updating a baseline (detailed steps)
9. Email notifications (how they're built & sent)
10. Logging and troubleshooting
11. Testing (including UDP test) and verification steps
12. Automation & scheduling
13. Backup & cleanup (what `clean_reset.py` does)
14. Security considerations
15. Development notes & contribution guide
16. FAQ
17. Appendix: example files

---

# 1. Overview

SurfaceMinder is a small External Attack Surface Management (EASM) toolkit whose goal is to periodically scan a list of public IPs for exposed services (both TCP and UDP), keep a baseline per tenant, detect changes vs baseline and notify via email when changes occur.

Design goals:
- Separate TCP and UDP scanning code paths for flexibility.
- Parser that ingests Nmap XML and stores results in a small SQLite DB.
- Tenant-aware baseline system: per-tenant baseline stored in DB; comparisons detect added/removed/changed ports.
- Email alerts summarizing differences (single combined mail for TCP+UDP).
- Tools to create baseline, clean/reset workspace, list tenants and run the full pipeline interactively.

# 2. Installation & prerequisites

Minimum prerequisites:
- Python 3.8+ (3.10/3.11 recommended)
- `nmap` (for scans)
- `sqlite3` (CLI optional but helpful)
- `pip` to install Python requirements (if any)

Recommended Python packages (install via `pip` if present in `requirements.txt`):
- requests (if `mailer` uses API)
- dataclass-wizard (if used by other modules)

Install `nmap` on Debian/Ubuntu/Kali:

```bash
sudo apt update
sudo apt install -y nmap
```

# 3. File layout (project structure)

```
- scans/                      # where XMLs from nmap are written
- scanner/
  - tcp_scanner.py
  - udp_scanner.py
- parser/
  - tenant_parser.py
- mailer.py
- main.py                     # CLI orchestrator
- run.sh                      # interactive runner
- create_baseline.py          # python helper for baseline
- clean_reset.py              # python backup & reset tool
- list_tenants.py             # list tenants helper
- config.ini                  # configuration (SMTP, nmap, paths)
- db/easm.sqlite              # created automatically by parser
- logs/                       # runtime logs
- backup/                     # used by clean_reset.py
- ips.txt                     # targets file (one IP per line)
```

# 4. Configuration files

## `config.ini` (recommended fields)

A sample minimal `config.ini`:

```ini
[general]
db_path = db/easm.sqlite
scans_dir = scans
logs_dir = logs

[nmap]
nmap_cmd = nmap
# Default TCP options used by tcp_scanner (example):
tcp_opts = -sT -p- -Pn -sV -oX
# Comma-separated UDP ports used by run.sh and scan-udp if not overridden
udp_ports = 53,123,161

[smtp]
host = smtp.gmail.com
port = 587
starttls = True
user = youremail@gmail.com
password = your_app_password_or_smtp_token
from = youremail@gmail.com

[app]
ips_file = ips.txt
```

**Important notes**:
- For Gmail, use an *App Password* (if account has 2FA) or configure OAuth if preferred. Plain account passwords may be blocked.
- `udp_ports` is used by `run.sh` to decide whether to run UDP scans automatically. If empty, UDP is skipped.

## `ips.txt`

Simple text file, one IP per line. Blank lines and lines starting with `#` are ignored.

Example:
```
# internal test
127.0.0.1
8.8.8.8
```

# 5. Database (schema & tables)

The SQLite DB (by default `db/easm.sqlite`) contains a few key tables used by the parser and the benchmark baseline logic. Typical tables:

- `scan_files` — metadata about scans
  - `id` INT PK
  - `scan_file` TEXT (filename)
  - `scan_type` TEXT ('tcp' or 'udp')
  - `created_at` TEXT (ISO timestamp)

- `ports` — port-level records extracted from XMLs
  - `id` INT PK
  - `scan_file` TEXT
  - `ip` TEXT
  - `port` INTEGER
  - `proto` TEXT ('tcp' or 'udp')
  - `state` TEXT ('open','closed','filtered',...)
  - `service` TEXT (service name / version)

- `baseline_ports` — per-tenant baseline
  - `id` INT PK
  - `tenant` TEXT
  - `ip` TEXT
  - `port` INTEGER
  - `proto` TEXT
  - `state` TEXT
  - `service` TEXT
  - `set_at` TEXT (ISO timestamp)

(Your `parser/tenant_parser.py` also uses these tables; the `clean_reset.py` will export and backup them before delete all.)

# 6. How the system works (workflow)

High-level flow used by `run.sh` or orchestration:

1. **Scan**: `scan-tcp` runs Nmap to generate XMLs for targets and writes them to `scans/`. Optionally `scan-udp` runs for UDP ports. `scanner/*` scripts call `nmap` and save XML output.
2. **Ingest (parse-scans)**: `parser/tenant_parser.py --ingest` reads XMLs from `scans/` and inserts `scan_files` + `ports` rows in DB.
3. **Baseline**: A baseline for a tenant is set via the `set-baseline` action (either using the latest scans or a specific scan file). Baseline rows live in `baseline_ports`.
4. **Check**: `check-baseline` compares `baseline_ports` with latest scan (TCP) and computes `added` / `removed` / `changed`. `check-baseline-combined` does the same for combined latest TCP+UDP.
5. **Notification**: If differences exist, `mailer.send_mail` is called with a short subject and a body describing the changes (it now prints the body to stdout for easier debugging).

# 7. Scripts and modules — what each does

Below each file/module with responsibilities, inputs, outputs and critical implementation notes.

---

## `main.py` (CLI orchestrator)

**Role**: central CLI entrypoint for the pipeline: `scan-tcp`, `scan-udp`, `parse-scans`, `set-baseline`, `check-baseline`, `check-baseline-combined`.

**Key functions**:
- `scan_tcp(ips_file, tenant)` — loops IPs, calls `scanner/tcp_scanner.py` for each IP.
- `scan_udp(ips_file, tenant, udp_ports)` — idem for UDP.
- `parse_scans()` — calls `parser/tenant_parser.py --ingest` to populate DB.
- `set_baseline(tenant[, scan_file])` — sets baseline using parser helper.
- `check_baseline(tenant)` — compares baseline vs latest tcp only.
- `check_baseline_combined(tenant)` — compares baseline vs latest tcp+udp combined and builds body.

---

## `scanner/tcp_scanner.py`

**Role**: perform TCP scan of a single IP and write Nmap XML to `scans/`.

**Behavior**:
- Accepts `--ip` and `--tenant` (and optional `--tcp-opts` override).
- Runs `nmap` with configured options (e.g. `-sT -p- -Pn -sV -oX <file>`), writes output to `scans/scan-<timestamp>-tcp-<ip>.xml` and prints or returns the filename.

**Important**:
- For speed, consider `-T4` and limiting ports (default in example is `-p-`).
- Ensure `nmap` is in PATH or adjust `nmap_cmd` in `config.ini`.

---

## `scanner/udp_scanner.py`

**Role**: perform UDP scan for the specified ports and write XML.

**Behavior**:
- Accepts `--ip`, `--tenant`, and `--udp-ports` (comma-separated string).
- Runs `nmap -sU -p <ports> -Pn -sV -oX <file>` and writes `scans/scan-<timestamp>-udp-<ip>.xml`.

**Notes**:
- UDP scans are slower and less deterministic; services often don't reply.
- `nmap` may show `open|filtered` if no ICMP error is returned.
- Running `nmap -sU` usually requires root or `cap_net_raw` capability.

---

## `parser/tenant_parser.py`

**Role**: parse Nmap XML files, populate DB tables and provide tenant-level utilities.

**Behavior**:
- `--ingest`: scans the `scans/` directory and parses new XMLs, storing data in `scan_files` and `ports`.
- `--set-baseline <tenant>`: sets baseline from latest scans or from a given scan file.
- comparison functions:
  - `compare_baseline_to_latest(tenant)` returns a dict with `latest_scan_file` and `report` (per IP: added/removed/changed lists)
  - `compare_baseline_to_latest_combined(tenant)` does combined TCP+UDP.

**Important**:
- Parser must handle both TCP and UDP XMLs (nmap XML includes `<port protocol="udp">` entries — parser must record protocol per port).
- The `report` structure used by `main.py` expects keys per IP with lists for `added`, `removed`, `changed` in a specific tuple format (see `_format_report` in `main.py`).

---

## `mailer.py`

**Role**: send email notifications.

**Behavior**:
- Exposes `send_mail(subject, body)`.
- Reads SMTP config from `config.ini` (`smtp.host`, `smtp.port`, `smtp.starttls`, `smtp.user`, `smtp.password`, `smtp.from`).
- Uses STARTTLS if configured; if server doesn't support it and the config enables starttls, `smtplib` raises — ensure `starttls = False` for servers without STARTTLS (like local MailHog setups), or simply point to a real SMTP server.

**Security**:
- Avoid storing plaintext passwords in repo; consider environment variables or a secrets manager. For small tests, app password is acceptable.

---

## `run.sh` (runner)

**Role**: interactive runner that:
- asks for tenant (or takes via CLI),
- validates tenant exists in DB,
- loops all IPs in `ips.txt`, runs `scan-tcp` for each IP,
- automatically runs `scan-udp` if `nmap.udp_ports` present or `--udp-ports` override provided,
- runs `parse-scans`,
- runs `check-baseline-combined` and sends mail if changes.

**Lock**: creates a directory `.easm_runner.lockdir` with PID to avoid concurrent runs. It detects and clears stale locks.

**Logs**: writes into `logs/run_easm-<timestamp>.log`.

---

## `create_baseline.py` (python)

**Role**: script to automate baseline creation: runs tcp+udp scans (optional), runs ingest, then constructs a *combined baseline* by taking latest tcp and latest udp scans and inserting their ports into `baseline_ports` for the tenant.

**Options**:
- `--tenant` required.
- `--no-scan-tcp` or `--no-scan-udp` to skip running scans.
- `--skip-ingest` if you already ingested XMLs.

**Behavior**:
- Collects port rows from `ports` related to the latest tcp/udp scan files, inserts them into `baseline_ports` (deletes existing tenant baseline first), records `set_at` timestamp.

---

## `clean_reset.py` (python)

**Role**: backup and reset workspace. It is the safe "nuke & pave" script.

**What it does**:
- Creates `backup/<TIMESTAMP>/` and copies:
  - DB binary file (e.g. `db/easm.sqlite`)
  - SQL dump (iterdump)
  - CSV export of `baseline_ports`
  - all `scans/*.xml`
  - all `logs/*`
  - `config.ini`
  - a `cleanup-<timestamp>.log` describing operations
- Moves/cleans originals: moves XMLs & logs into backup, moves DB into backup (`old-db-<timestamp>.sqlite`) and creates a new empty DB. It attempts to call `parser.tenant_parser.init_db(conn)` to initialize schema if available.

**Safety**:
- Interactive confirmation required unless `--yes` passed.
- Uses safe move/copy & fallback copy when cross-device moves fail.

---

## `list_tenants.py`

**Role**: utility to list tenants found in DB. Searches `tenants` table (if exists) and `baseline_ports` for tenant names; provides counts and last baseline set timestamp. Supports `--json` for machine-readable output.

---

# 8. Creating and updating a baseline (detailed steps)

### Quick interactive (recommended first run)

1. Make sure you have `ips.txt` with targets.
2. Run a full interactive runner to generate scans and ingest:

```bash
./run.sh --tenant testtenant
```

3. The runner will ask to set baseline (or you can use `create_baseline.py`):

```bash
python3 create_baseline.py --tenant testtenant
```

This will run scans (unless `--no-scan-*` used), ingest, and create a combined baseline from the latest tcp+udp scans.

### Manual method

1. Run scans:
```bash
python3 main.py scan-tcp --ips-file ips.txt --tenant testtenant
python3 main.py scan-udp --ips-file ips.txt --tenant testtenant --udp-ports "53,123"
```
2. Ingest scans:
```bash
python3 main.py parse-scans
```
3. Create baseline (make a tcp and udp scan and it creates a baselines based on this results):
```bash
python3 main.py create-baseline --tenant testtenant
```

# 9. Email notifications (how they're built & sent)

- `main.py` builds a subject like `EASM: <N> cambiamenti (tcp+udp) tenant=<tenant>` and a multi-line body with sections per IP and per change type.
- For debug, `main.py` prints the subject/body to stdout before calling `mailer.send_mail`.
- `mailer.py` reads `smtp` section from `config.ini`. For Gmail use `smtp.gmail.com:587` and STARTTLS; store app password in `smtp.password` or prefer environment secrets.

# 10. Logging and troubleshooting

- Runner: `logs/run_easm-<timestamp>.log` (contains full stdout/stderr of actions called by runner).
- Parser: prints errors/exceptions when parsing invalid XMLs; check parse-scans output.
- If an action fails silently in the runner, run the underlying action directly for full trace, e.g.:
  - `python3 main.py scan-udp --ips-file ips.txt --tenant testtenant --udp-ports "53,123"`
  - `python3 main.py parse-scans`
  - `python3 main.py check-baseline-combined --tenant testtenant`

Common issues & fixes:
- **UDP scans produce open|filtered**: expected for many UDP services — ensure the service responds or the listener replies (use UDP echo during tests).
- **nmap not in PATH**: set `nmap_cmd` in `config.ini` or add to PATH.
- **Lock stale**: remove `.easm_runner.lockdir` only if no run is active (check `ps aux`).

### SQL checks
```bash
sqlite3 db/easm.sqlite "SELECT proto, COUNT(*) FROM ports GROUP BY proto;"
sqlite3 db/easm.sqlite "SELECT proto, COUNT(*) FROM baseline_ports WHERE tenant='TEST' GROUP BY proto;"
```

# 12. Automation & scheduling

To run the pipeline periodically, you can use `cron` on Linux. Example crontab to run hourly (non-interactive):

1. Create a non-interactive wrapper that accepts tenant and ip file and runs the sequence without prompts (or pass flags to `run.sh` if you added `--yes` etc.).

2. Example cron entry (run as the user owning the repo):
```
0 * * * * cd /home/user/SurfaceMinder && /usr/bin/bash ./run.sh --tenant mytenant --ips-file ips.txt >> logs/cron-run.log 2>&1
```

Prefer using `systemd` timers for more robust scheduling if you need reliability.

# 13. Backup & cleanup (what `clean_reset.py` does)

`clean_reset.py` will:
- backup DB (binary), dump SQL via `iterdump`, export `baseline_ports` to CSV,
- move `scans/*.xml` and `logs/*` into `backup/<TIMESTAMP>/`,
- move DB into backup and create a fresh DB; attempt to initialize schema via `parser.tenant_parser.init_db(conn)` if provided.

Use:
```bash
python3 clean_reset.py --backup-root backup --yes
```

# 14. Security considerations

- **Store SMTP credentials safely**: avoid committing `config.ini` with passwords. Consider env vars or OS-level secrets.
- **Limit access to db/**: restrict file permissions to the user running scans.
- **Nmap capability**: `setcap cap_net_raw+ep $(which nmap)` allows nmap to run UDP scans as non-root but gives it network raw capabilities — treat carefully.
- **Avoid running untrusted XML**: parser reads XML files; ensure scans come from controlled nmap runs only.

# 15. Development notes & contribution guide

- Keep code modular: scanner vs parser vs mailer.
- Unit tests: consider unit tests for parser functions and report diffing logic. Add tests under `tests/`.
- Linting and static type hints help maintainability.

# 16. FAQ

**Q: Why do UDP scans sometimes show `open|filtered`?**
A: Because UDP is connectionless. Nmap can mark a port `open|filtered` when it cannot determine status — a service that replies will let nmap mark `open`.

**Q: Mail fails with STARTTLS errors**
A: If using a local SMTP dev server (MailHog) set `smtp.starttls = False` in `config.ini`. For Gmail use starttls=true and an app password.

**Q: My run exits because of a stale lock**
A: Remove `.easm_runner.lockdir` only if no other runner is active. Better: keep the PID-enabled lock logic in `run.sh`.

## Final notes

This document is intentionally verbose to be the single reference point for everything in SurfaceMinder.


