#!/usr/bin/env python3
"""
test_smtp.py -- semplice tool per testare l'invio SMTP configurato per il progetto

Caratteristiche:
- legge la configurazione da config.ini (se presente) o da variabili d'ambiente:
  EASM_SMTP_HOST, EASM_SMTP_PORT, EASM_SMTP_USER, EASM_SMTP_PASS,
  EASM_SMTP_FROM, EASM_SMTP_TO, EASM_SMTP_STARTTLS, EASM_SMTP_USE_SSL
- supporta STARTTLS e SMTP_SSL
- login solo se user è fornito
- accetta argomenti CLI per subject, body, to, attachment e verbose
- esce con 0 su successo, 1 su errore
"""
import os
import sys
import argparse
import smtplib
import mimetypes
import traceback
from email.message import EmailMessage
from configparser import ConfigParser

HERE = os.path.abspath(os.path.dirname(__file__))
CFG_PATH = os.path.join(HERE, "config.ini")

def parse_bool_str(s, fallback=False):
    if s is None:
        return fallback
    s = str(s).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return fallback

def load_config():
    """
    Carica la configurazione dando priorità alle variabili d'ambiente,
    poi a config.ini (se presente). Ritorna un dict con le chiavi:
    host, port, user, pass, from, to, starttls, use_ssl
    """
    conf = {
        "host": "localhost",
        "port": 25,
        "user": "",
        "pass": "",
        "from": "easm-alerts@example.com",
        "to": "",
        "starttls": False,
        "use_ssl": False,
    }

    env = os.environ
    if env.get("EASM_SMTP_HOST"):
        conf["host"] = env.get("EASM_SMTP_HOST")
    if env.get("EASM_SMTP_PORT"):
        try:
            conf["port"] = int(env.get("EASM_SMTP_PORT"))
        except ValueError:
            pass
    if env.get("EASM_SMTP_USER"):
        conf["user"] = env.get("EASM_SMTP_USER")
    if env.get("EASM_SMTP_PASS"):
        conf["pass"] = env.get("EASM_SMTP_PASS")
    if env.get("EASM_SMTP_FROM"):
        conf["from"] = env.get("EASM_SMTP_FROM")
    if env.get("EASM_SMTP_TO"):
        conf["to"] = env.get("EASM_SMTP_TO")
    if env.get("EASM_SMTP_STARTTLS"):
        conf["starttls"] = parse_bool_str(env.get("EASM_SMTP_STARTTLS"), False)
    if env.get("EASM_SMTP_USE_SSL"):
        conf["use_ssl"] = parse_bool_str(env.get("EASM_SMTP_USE_SSL"), False)

    # Se esiste config.ini, usa i valori altrimenti non sovrascritti da env
    if os.path.exists(CFG_PATH):
        parser = ConfigParser()
        parser.read(CFG_PATH)
        if parser.has_section("smtp"):
            sec = parser["smtp"]
            def get_strip(k, fallback=None):
                v = sec.get(k, fallback=fallback)
                if v is None:
                    return fallback
                # rimuovi commenti inline e strip
                v = v.split("#",1)[0].split(";",1)[0].strip()
                return v
            if not env.get("EASM_SMTP_HOST") and get_strip("host"):
                conf["host"] = get_strip("host")
            if not env.get("EASM_SMTP_PORT") and get_strip("port"):
                try:
                    conf["port"] = int(get_strip("port"))
                except Exception:
                    pass
            if not env.get("EASM_SMTP_USER") and get_strip("user"):
                conf["user"] = get_strip("user")
            if not env.get("EASM_SMTP_PASS") and get_strip("pass"):
                conf["pass"] = get_strip("pass")
            if not env.get("EASM_SMTP_FROM") and get_strip("from"):
                conf["from"] = get_strip("from")
            if not env.get("EASM_SMTP_TO") and get_strip("to"):
                conf["to"] = get_strip("to")
            if not env.get("EASM_SMTP_STARTTLS"):
                conf["starttls"] = parse_bool_str(get_strip("starttls"), conf["starttls"])
            if not env.get("EASM_SMTP_USE_SSL"):
                conf["use_ssl"] = parse_bool_str(get_strip("use_ssl"), conf["use_ssl"])
    return conf

def build_message(subject, body, mail_from, to_list, attach_path=None):
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_list)
    msg["Subject"] = subject
    msg.set_content(body)

    if attach_path:
        if not os.path.exists(attach_path):
            raise FileNotFoundError(f"Attachment not found: {attach_path}")
        ctype, _ = mimetypes.guess_type(attach_path)
        if ctype is None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        with open(attach_path, "rb") as f:
            data = f.read()
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(attach_path))
    return msg

def send(conf, msg, verbose=False):
    host = conf["host"]
    port = conf["port"]
    use_ssl = conf["use_ssl"]
    starttls = conf["starttls"]
    user = conf["user"]
    passwd = conf["pass"]

    if verbose:
        print("SMTP configuration:", conf)

    try:
        if use_ssl:
            if verbose:
                print(f"Connecting to {host}:{port} using SSL")
            with smtplib.SMTP_SSL(host, port, timeout=30) as s:
                s.ehlo()
                if user:
                    if verbose:
                        print("Logging in (SSL)...")
                    s.login(user, passwd)
                s.send_message(msg)
        else:
            if verbose:
                print(f"Connecting to {host}:{port} (plain SMTP)")
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.ehlo()
                if starttls:
                    try:
                        if s.has_extn("STARTTLS"):
                            if verbose:
                                print("Server supports STARTTLS — starting TLS...")
                            s.starttls()
                            s.ehlo()
                        else:
                            if verbose:
                                print("STARTTLS requested but server did not advertise it — skipping TLS")
                    except Exception as e:
                        if verbose:
                            print("STARTTLS attempt failed:", e)
                if user:
                    if verbose:
                        print("Logging in...")
                    s.login(user, passwd)
                s.send_message(msg)
        return True, None
    except Exception:
        return False, traceback.format_exc()

def main(argv):
    conf = load_config()

    ap = argparse.ArgumentParser(description="SMTP quick test for EASM project")
    ap.add_argument("--subject", "-s", default="EASM SMTP test", help="Email subject")
    ap.add_argument("--body", "-b", default="This is a test message from EASM test_smtp.py", help="Email body text")
    ap.add_argument("--to", "-t", help="Comma-separated recipients (overrides config)", default=None)
    ap.add_argument("--from-addr", "-f", help="From address (overrides config)", default=None)
    ap.add_argument("--attach", "-a", help="Attachment file path (optional)", default=None)
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = ap.parse_args(argv)

    mail_from = args.from_addr or conf.get("from") or conf.get("user") or "easm-alerts@example.com"
    to_raw = args.to or conf.get("to") or ""
    if not to_raw:
        print("No recipient configured. Set EASM_SMTP_TO env or 'to' in config.ini or pass --to on CLI.")
        return 1
    to_list = [x.strip() for x in to_raw.split(",") if x.strip()]
    if not to_list:
        print("No valid recipients parsed. Aborting.")
        return 1

    try:
        msg = build_message(args.subject, args.body, mail_from, to_list, attach_path=args.attach)
    except Exception as e:
        print("Error building message:", e)
        return 1

    ok, err = send(conf, msg, verbose=args.verbose)
    if ok:
        print("Mail inviata con successo a:", ", ".join(to_list))
        return 0
    else:
        print("Invio fallito. Stacktrace:")
        print(err)
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
