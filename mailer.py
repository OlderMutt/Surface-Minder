#!/usr/bin/env python3
"""
mailer.py - invi a mail in modo robusto:
 - supporta SMTP SSL (port 465)
 - supporta STARTTLS solo se il server lo annuncia (o se forzato via config)
 - non tenta il login se user/pass non sono configurati
 - opzionalmente allega un file
"""
import os
import mimetypes
import smtplib
from email.message import EmailMessage
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

# leggi valori con fallback
SMTP_HOST = cfg.get('smtp', 'host', fallback='localhost')
SMTP_PORT = cfg.getint('smtp', 'port', fallback=25)
SMTP_USER = cfg.get('smtp', 'user', fallback='').strip()
SMTP_PASS = cfg.get('smtp', 'pass', fallback='').strip()
FROM = cfg.get('smtp', 'from', fallback='easm-alerts@example.com')
TO = [x.strip() for x in cfg.get('smtp', 'to', fallback='').split(',') if x.strip()]

# opzioni comportamentali (configurabili)
# starttls: se True proverà STARTTLS *solo se il server lo annuncia*;
# se vuoi forzare la STARTTLS anche se non annunciata, imposta starttls_force = True (NON consigliato)
SMTP_STARTTLS = cfg.getboolean('smtp', 'starttls', fallback=True)
SMTP_STARTTLS_FORCE = cfg.getboolean('smtp', 'starttls_force', fallback=False)
SMTP_USE_SSL = cfg.getboolean('smtp', 'use_ssl', fallback=False)  # True -> SMTP_SSL (porta tipica 465)

def send_mail(subject, body_text, attachment_path=None):
    msg = EmailMessage()
    msg['From'] = FROM
    msg['To'] = ', '.join(TO)
    msg['Subject'] = subject
    msg.set_content(body_text)

    # allegato opzionale
    if attachment_path and os.path.exists(attachment_path):
        ctype, encoding = mimetypes.guess_type(attachment_path)
        if ctype is None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        with open(attachment_path, 'rb') as f:
            data = f.read()
        msg.add_attachment(data, maintype=maintype, subtype=subtype,
                           filename=os.path.basename(attachment_path))

    try:
        if SMTP_USE_SSL:
            # Connessione SSL (es. Gmail 465)
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.ehlo()
                # STARTTLS: solo se richiesto e se il server lo supporta,
                # oppure se forzato tramite starttls_force (attenzione)
                if SMTP_STARTTLS_force_or_supported(s):
                    try:
                        s.starttls()
                        s.ehlo()
                    except Exception as e:
                        # se fallisce starttls per qualche motivo, logga e prosegui senza terminare
                        print(f"[!] starttls fallito: {e} — proseguo senza TLS")
                # login solo se user è stato configurato
                if SMTP_USER:
                    try:
                        s.login(SMTP_USER, SMTP_PASS)
                    except Exception as e:
                        print(f"[!] Login SMTP fallito: {e} — controlla user/pass o server auth.")
                s.send_message(msg)
        print('[*] Mail inviata a', TO)
    except Exception as e:
        print('[!] Errore invio mail', e)

def SMTP_STARTTLS_force_or_supported(smtp_obj):
    """
    Decide se tentare starttls:
    - se starttls_force è impostato a True -> True
    - altrimenti True solo se server annuncia STARTTLS (has_extn)
    """
    if SMTP_STARTTLS_FORCE:
        return True
    if not SMTP_STARTTLS:
        return False
    try:
        # has_extn prende il nome dell'estensione (case-insensitive)
        return smtp_obj.has_extn('STARTTLS')
    except Exception:
        return False
