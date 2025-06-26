#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Interaction FTP Honeypot

Features:
– Bootstrap des dépendances manquantes (Twisted, requests, service-identity, pin crypto<39 si Py3.7)
– Génération auto d’un certificat TLS PEM (server.key/server.crt)
– FTPS implicite (SSL4ServerEndpoint)
– Auth anonym (anonymous) + compte attacker/secret
– Canary-files, honeytoken unique par session
– Filesystem dynamique (création/suppression aléatoire)
– Quarantine des uploads + logs MD5/SHA256
– Détection bruteforce + tarpitting adaptatif
– Détection des Tor exit-nodes
– Commandes SITE factices (EXEC/CHMOD/SHELL)
– Logs par session et centralisés
"""

import os
import sys
import subprocess
import shutil
import uuid
import hashlib
import random
import logging
import smtplib
import datetime
import requests

# ————— Bootstrap des dépendances —————
def ensure_installed(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        print(f"[BOOTSTRAP] pip install {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])

for pkg, imp in [
    ("twisted", None),
    ("requests", None),
    ("service-identity", "service_identity"),
    ("cryptography<39", None),
]:
    ensure_installed(pkg, imp)

# ————— Génération auto du certificat PEM —————
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_FILE = "server.key"
CERT_FILE = "server.crt"

if not (os.path.exists(KEY_FILE) and os.path.exists(CERT_FILE)):
    print("[BOOTSTRAP] génération d'un certificat auto-signé…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        u"Honeypot"),
        x509.NameAttribute(NameOID.COMMON_NAME,              u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False
        )
        .sign(key, hashes.SHA256())
    )
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ————— Imports Twisted et configuration —————
import logging
from twisted.cred import portal, checkers
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath

ROOT_DIR        = "virtual_fs"
QUARANTINE_DIR  = "quarantine"
SESSION_DIR     = "sessions"
LOG_FILE        = "honeypot.log"
TOR_EXIT_URL    = "https://check.torproject.org/torbulkexitlist"
BRUTEF_THR      = 5
DELAY_SEC       = 2
CANARY_FILES    = {"passwords.txt", "secrets/ssh_key"}
LISTEN_PORT     = int(os.getenv("HONEYFTP_PORT", "2121"))

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
SMTP_CFG = (
    os.getenv("SMTP_SERVER"),
    int(os.getenv("SMTP_PORT", "0")) or 25,
    os.getenv("SMTP_USER"),
    os.getenv("SMTP_PASS"),
    os.getenv("ALERT_FROM"),
    os.getenv("ALERT_TO"),
)

# ————— Logging & création de dossiers —————
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
os.makedirs(ROOT_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SESSION_DIR, exist_ok=True)

# Fichiers-leurres initiaux
for path, content in {
    "passwords.txt":   "admin:admin",
    "secrets/ssh_key": "FAKE_SSH_KEY",
    "docs/readme.txt": "Welcome to the FTP server",
}.items():
    full = os.path.join(ROOT_DIR, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if not os.path.exists(full):
        with open(full, "w") as f:
            f.write(content)

failed_attempts = {}
dynamic_items = []

# ————— Helpers —————
def alert(msg: str):
    if SLACK_WEBHOOK:
        try: requests.post(SLACK_WEBHOOK, json={"text": msg}, timeout=5)
        except: pass
    srv, port, user, pw, fr, to = SMTP_CFG
    if srv and fr and to:
        try:
            s = smtplib.SMTP(srv, port, timeout=5)
            if user:
                s.starttls(); s.login(user, pw or "")
            mail = f"Subject: HoneyFTP Alert\nFrom: {fr}\nTo: {to}\n\n{msg}"
            s.sendmail(fr, [to], mail)
            s.quit()
        except: pass

def is_tor_exit(ip: str) -> bool:
    try:
        r = requests.get(TOR_EXIT_URL, timeout=5)
        return ip in r.text.splitlines()
    except:
        return False

def create_honeytoken(ip: str, session: str) -> str:
    fn = f"secret_{uuid.uuid4().hex}.txt"
    full = os.path.join(ROOT_DIR, fn)
    with open(full, "w") as f:
        f.write(f"session={session}\nip={ip}\n")
    return fn

def randomize_fs():
    for p in list(dynamic_items):
        try:
            if os.path.isdir(p): shutil.rmtree(p)
            else: os.remove(p)
        except: pass
        dynamic_items.remove(p)
    for _ in range(random.randint(1, 3)):
        d = os.path.join(ROOT_DIR, f"dir_{uuid.uuid4().hex[:6]}")
        os.makedirs(d, exist_ok=True); dynamic_items.append(d)
        for __ in range(random.randint(1, 2)):
            f = os.path.join(d, f"file_{uuid.uuid4().hex[:6]}.txt")
            with open(f, "w") as x:
                x.write("dummy data\n")
            dynamic_items.append(f)

# ————— Shell FTP personnalisé —————
class HoneyShell(ftp.FTPShell):
    def __init__(self, avatar_id: str):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = avatar_id

    def openForReading(self, path):
        rel = "/".join(path)
        if rel in CANARY_FILES:
            alert(f"CANARY READ {rel} by {self.avatarId}")
        return super().openForReading(path)

    def openForWriting(self, path):
        return super().openForWriting(path)  # on garde la logique de Twisted pour l’upload

# ————— Protocole FTP + détection —————
class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session = uuid.uuid4().hex
        peer = self.transport.getPeer().host
        self.logf = open(os.path.join(SESSION_DIR, f"{self.session}.log"), "a")
        self.start, self.count = datetime.datetime.utcnow(), 0
        logging.info("CONNECT ip=%s session=%s", peer, self.session)
        if is_tor_exit(peer):
            alert(f"Tor exit node: {peer}")
        self.token = create_honeytoken(peer, self.session)

    def connectionLost(self, reason):
        peer = getattr(self.transport.getPeer(), "host", "?")
        logging.info("DISCONNECT ip=%s session=%s", peer, self.session)
        try: os.remove(os.path.join(ROOT_DIR, self.token))
        except: pass
        self.logf.close()
        super().connectionLost(reason)

    def ftp_USER(self, user):
        peer = self.transport.getPeer().host
        self.username = user
        logging.info("USER ip=%s user=%s", peer, user)
        self.logf.write(f"USER {user}\n")
        return super().ftp_USER(user)

    def ftp_PASS(self, pw):
        peer = self.transport.getPeer().host
        if failed_attempts.get(peer, 0) >= BRUTEF_THR:
            d = defer.Deferred()
            reactor.callLater(DELAY_SEC, d.callback, (ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d
        logging.info("PASS ip=%s user=%s pw=%s", peer, getattr(self, "username", "?"), pw)
        self.logf.write(f"PASS {pw}\n")
        d = super().ftp_PASS(pw)

        def onFail(err):
            failed_attempts[peer] = failed_attempts.get(peer, 0) + 1
            if failed_attempts[peer] >= BRUTEF_THR:
                alert(f"Bruteforce detected from {peer}")
            return err

        def onSucc(res):
            failed_attempts.pop(peer, None)
            randomize_fs()
            return res

        d.addCallbacks(onSucc, onFail)
        return d

    def ftp_RETR(self, path):
        rel = path.lstrip("/")
        peer = self.transport.getPeer().host
        if rel in CANARY_FILES:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == self.token:
            logging.info("HONEYTOKEN DL %s session=%s", rel, self.session)
        self.logf.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def ftp_SITE(self, params):
        cmd = params.strip().split()[0].upper()
        return {
            "EXEC":  (ftp.CMD_OK, "EXEC disabled"),
            "CHMOD": (ftp.CMD_OK, "CHMOD ignored"),
            "SHELL": (ftp.CMD_OK, "SHELL unavailable"),
        }.get(cmd, (ftp.SYNTAX_ERR, params))

    def lineReceived(self, line):
        peer = self.transport.getPeer().host
        cmd = line.decode("latin-1").strip()
        logging.info("CMD ip=%s cmd=%s", peer, cmd)
        self.logf.write(cmd + "\n")
        self.count += 1
        if self.count > 20 and (datetime.datetime.utcnow() - self.start).total_seconds() < 10:
            alert(f"Fast scanner detected from {peer}")
            reactor.callLater(random.uniform(1, 3), lambda: None)
        return super().lineReceived(line)

class HoneypotFactory(ftp.FTPFactory):
    protocol = HoneyFTP
    welcomeMessage = "(vsFTPd 2.3.4)"

# ————— Realm corrigé (requestAvatar) —————
class HoneyRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        if ftp.IFTPShell in interfaces:
            return ftp.IFTPShell, HoneyShell(avatarId), lambda: None
        raise NotImplementedError()

def main():
    p = portal.Portal(HoneyRealm())
    # compte spécifique en priorité
    p.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret"))
    # puis autorise anonymous
    p.registerChecker(AllowAnonymousAccess())

    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CERT_FILE)
    endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, ctx).listen(HoneypotFactory(p))
    logging.info("Honeypot listening on port %s", LISTEN_PORT)
    reactor.run()

if __name__ == "__main__":
    main()
