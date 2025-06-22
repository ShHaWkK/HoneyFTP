#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced FTP Honeypot.

Ce script installe automatiquement ses dépendances manquantes,
prend en charge Python 3.7 (avec pin de cryptography), et utilise
les shells Twisted FTPShell/FTPAnonymousShell (pas de FileSystem).
"""

import subprocess
import sys

def ensure_installed(pkg_name, import_name=None):
    """
    Vérifie qu'on peut importer import_name (ou pkg_name si None).
    Si l'import échoue, lance pip install pkg_name.
    """
    name = import_name or pkg_name
    try:
        __import__(name)
    except ImportError:
        print(f"[BOOTSTRAP] Installation de {pkg_name} …")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--upgrade", pkg_name
        ])

# ——— Dépendances et pin crypto pour Python 3.7 ———
dependencies = [
    ("twisted", None),
    ("requests", None),
    ("service-identity", "service_identity"),
    ("cryptography<39", None),  # pin si on reste en Python 3.7
]

for pkg, imp in dependencies:
    ensure_installed(pkg, imp)

# ——— Imports principaux —————————————————————

import os
import uuid
import hashlib
import logging
import random
import smtplib

from datetime import datetime

import requests
from twisted.cred import portal, checkers
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath

# ——— Configuration globale —————————————

ROOT_DIR        = "virtual_fs"
QUARANTINE_DIR  = "quarantine"
SESSION_LOG_DIR = "sessions"
LOG_FILE        = "honeypot.log"
TOR_EXIT_LIST   = "https://check.torproject.org/torbulkexitlist"
BRUTEFORCE_THRESHOLD = 5
DELAY_SECONDS        = 2
CANARY_FILES    = {"passwords.txt", "secrets/ssh_key"}

# Alertes via env vars
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")
SMTP_SERVER   = os.environ.get("SMTP_SERVER")
SMTP_PORT     = int(os.environ.get("SMTP_PORT","0")) or None
SMTP_USER     = os.environ.get("SMTP_USER")
SMTP_PASS     = os.environ.get("SMTP_PASS")
ALERT_FROM    = os.environ.get("ALERT_FROM")
ALERT_TO      = os.environ.get("ALERT_TO")
LISTEN_PORT   = int(os.environ.get("HONEYFTP_PORT","2121"))

# ——— Logging & dossiers ————————————————

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[ logging.FileHandler(LOG_FILE), logging.StreamHandler() ],
)

os.makedirs(ROOT_DIR,       exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SESSION_LOG_DIR,exist_ok=True)

# Fichiers-leurres initiaux
lure_files = {
    "passwords.txt": "admin:admin",
    "secrets/ssh_key": "FAKE_SSH_KEY",
    "docs/readme.txt": "Welcome to the FTP server",
}
for rel, content in lure_files.items():
    full = os.path.join(ROOT_DIR, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if not os.path.exists(full):
        with open(full, "w") as f:
            f.write(content)

failed_attempts = {}

# ——— Fonctions utilitaires ——————————————————

def alert(message: str) -> None:
    """Envoie un message via Slack et/ou SMTP si configurés."""
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5)
        except Exception as e:
            logging.warning("Slack alert failed: %s", e)
    if SMTP_SERVER and ALERT_FROM and ALERT_TO:
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT or 25, timeout=5) as s:
                if SMTP_USER:
                    s.starttls()
                    s.login(SMTP_USER, SMTP_PASS or "")
                msg = f"Subject: HoneyFTP Alert\nFrom: {ALERT_FROM}\nTo: {ALERT_TO}\n\n{message}"
                s.sendmail(ALERT_FROM, [ALERT_TO], msg)
        except Exception as e:
            logging.warning("SMTP alert failed: %s", e)

def is_tor_exit(ip: str) -> bool:
    """Vérifie si l'IP figure dans la liste des nœuds de sortie Tor."""
    try:
        resp = requests.get(TOR_EXIT_LIST, timeout=5)
        if resp.status_code == 200:
            return ip.strip() in resp.text.splitlines()
    except Exception as e:
        logging.warning("Tor exit list check failed: %s", e)
    return False

# ——— Shell FTP personnalisé ——————————————————

class HoneyShell(ftp.FTPShell):
    """Avatar FTP qui utilise un faux FS avec logging & quarantines."""

    def __init__(self, avatar_id: str):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = avatar_id

    def openForReading(self, path):
        rel = "/".join(path)
        if rel in CANARY_FILES:
            alert(f"Canary file accessed: {rel} by {self.avatarId}")
        return super().openForReading(path)

    def openForWriting(self, path):
        p = self._path(path)
        if p.isdir():
            return defer.fail(ftp.IsADirectoryError(path))
        try:
            real_f = p.open("wb")
        except OSError as e:
            return ftp.errnoToFailure(e.errno, path)

        session = uuid.uuid4().hex
        qf = open(os.path.join(QUARANTINE_DIR, session), "wb")
        md5 = hashlib.md5(); sha = hashlib.sha256()

        class _Tee:
            def registerProducer(self, prod, streaming):
                self.prod = prod
            def unregisterProducer(self):
                real_f.close(); qf.close()
            def write(self, data):
                real_f.write(data); qf.write(data)
                md5.update(data); sha.update(data)

        class _Writer:
            def __init__(self): self._once=False
            def receive(self):
                if self._once: raise RuntimeError("receive() déjà appelé")
                self._once=True
                return defer.succeed(_Tee())
            def close(self):
                real_f.close(); qf.close()
                logging.info(
                    "UPLOAD ip=%s file=%s md5=%s sha256=%s session=%s",
                    self.avatarId, "/".join(path),
                    md5.hexdigest(), sha.hexdigest(), session
                )
                if os.path.basename(path[-1]) in CANARY_FILES:
                    alert(f"Canary upload {'/'.join(path)} by {self.avatarId}")
                return defer.succeed(None)

        return defer.succeed(_Writer())

# ——— Protocole FTP avec détection & logs —————————

class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session_id = uuid.uuid4().hex
        ip = self.transport.getPeer().host
        self.session_log = open(os.path.join(SESSION_LOG_DIR, f"{self.session_id}.log"), "a")
        self.start_time, self.cmd_count = datetime.utcnow(), 0
        logging.info("CONNECT ip=%s session=%s", ip, self.session_id)
        if is_tor_exit(ip):
            logging.info("TOR_EXIT ip=%s", ip)
            alert(f"Tor exit node: {ip}")

    def connectionLost(self, reason):
        ip = getattr(self.transport.getPeer(), "host", "?")
        logging.info("DISCONNECT ip=%s session=%s", ip, self.session_id)
        self.session_log.close()
        super().connectionLost(reason)

    def ftp_USER(self, user):
        ip = self.transport.getPeer().host
        self.username = user
        logging.info("USER ip=%s user=%s", ip, user)
        self.session_log.write(f"USER {user}\n")
        return super().ftp_USER(user)

    def ftp_PASS(self, pw):
        ip = self.transport.getPeer().host
        if failed_attempts.get(ip,0) >= BRUTEFORCE_THRESHOLD:
            logging.info("BRUTEFORCE_BLOCK ip=%s", ip)
            d = defer.Deferred()
            reactor.callLater(DELAY_SECONDS, d.callback, (ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d

        logging.info("PASS ip=%s user=%s pw=%s", ip, getattr(self,"username","?"), pw)
        self.session_log.write(f"PASS {pw}\n")
        d = super().ftp_PASS(pw)

        def on_fail(err):
            failed_attempts[ip] = failed_attempts.get(ip,0)+1
            logging.info("LOGIN_FAIL ip=%s count=%s", ip, failed_attempts[ip])
            self.session_log.write("LOGIN_FAIL\n")
            if failed_attempts[ip] >= BRUTEFORCE_THRESHOLD:
                alert(f"Bruteforce from {ip}")
            return err

        def on_succ(res):
            failed_attempts.pop(ip,None)
            logging.info("LOGIN_SUCCESS ip=%s", ip)
            self.session_log.write("LOGIN_SUCCESS\n")
            return res

        d.addCallbacks(on_succ, on_fail)
        return d

    def ftp_RETR(self, path):
        rel = path.lstrip("/")
        if rel in CANARY_FILES:
            ip = self.transport.getPeer().host
            alert(f"Canary download {rel} by {ip}")
        self.session_log.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def lineReceived(self, line):
        ip = self.transport.getPeer().host
        cmd = line.decode("latin-1")
        logging.info("CMD ip=%s cmd=%s", ip, cmd)
        self.session_log.write(cmd+"\n")
        self.cmd_count += 1
        if self.cmd_count>20 and (datetime.utcnow()-self.start_time).total_seconds()<10:
            alert(f"Fast scanner {ip}")
            reactor.callLater(random.uniform(1,3), lambda: None)
        return super().lineReceived(line)

class HoneyFTPFactory(ftp.FTPFactory):
    protocol = HoneyFTP

class HoneyRealm(ftp.FTPRealm):
    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")
    def avatarForUsername(self, user):
        return HoneyShell(user)

# ——— Point d'entrée ——————————————————————————

def main():
    realm   = HoneyRealm(ROOT_DIR)
    port    = portal.Portal(realm)
    checker = checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret")
    port.registerChecker(checker)

    factory = HoneyFTPFactory(port)

    # SSL: server.key & server.crt au format PEM non chiffré
    context = ssl.DefaultOpenSSLContextFactory("server.key", "server.crt")
    ep = endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, context)
    ep.listen(factory)

    logging.info("Honeypot listening on port %s", LISTEN_PORT)
    reactor.run()

if __name__ == "__main__":
    main()
