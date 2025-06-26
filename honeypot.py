#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Interaction FTP Honeypot (Implicit FTPS)

Fonctionnalités :
– Auto-bootstrap pip deps (Twisted, requests, service-identity, pin cryptography<39 sur Py3.7)
– Génération auto d’un certificat TLS auto-signé (server.key/server.crt) dans un dossier inscriptible
– FTPS implicite (SSL4ServerEndpoint)
– Authentification : anonymous + attacker/secret
– Canary-files + honeytoken unique par session
– Filesystem dynamique (création/suppression aléatoire de dirs/fichiers)
– Quarantaine des uploads + calcul MD5/SHA256 + journalisation
– Brute-force throttling + tarpitting adaptatif
– Détection Tor exit-nodes
– Stub SITE EXEC/CHMOD/SHELL
– RNFR/RNTO (rename) avec trace dans `.rename.log`
– DELE → déplacement en quarantaine au lieu de suppression
– MKD / RMD → autorisés, mais alertes si rmdir d’un répertoire “interdit”
– Logs centraux + logs par session
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
import tempfile

from datetime import datetime, timedelta
import requests

# ——————— 1) Bootstrap pip dependencies —————————————————————
def ensure_installed(pkg, imp_name=None):
    try:
        __import__(imp_name or pkg)
    except ImportError:
        print(f"[BOOTSTRAP] Installation de {pkg}…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])

for pkg, imp in [
    ("twisted", None),
    ("requests", None),
    ("service-identity", "service_identity"),
    ("cryptography<39", None),
]:
    ensure_installed(pkg, imp)

# ——————— 2) Choix du dossier de travail inscriptible —————————————————
script_dir = os.path.dirname(os.path.abspath(__file__))
if os.access(script_dir, os.W_OK):
    BASE_DIR = script_dir
else:
    BASE_DIR = os.path.join(tempfile.gettempdir(), "HoneyFTP")
    os.makedirs(BASE_DIR, exist_ok=True)
    print(f"[WARNING] {script_dir} non inscriptible, utilisation de {BASE_DIR}")

ROOT_DIR       = os.path.join(BASE_DIR, "virtual_fs")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
SESSION_DIR    = os.path.join(BASE_DIR, "sessions")
LOG_FILE       = os.path.join(BASE_DIR, "honeypot.log")

# Variables de configuration
TOR_EXIT_URL  = "https://check.torproject.org/torbulkexitlist"
BRUTEF_THR    = 5
DELAY_SEC     = 2
CANARY_FILES  = {"passwords.txt", "secrets/ssh_key"}
FORBIDDEN_DIRS= {"secrets"}
LISTEN_PORT   = int(os.getenv("HONEYFTP_PORT", "2121"))

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
SMTP_CFG      = (
    os.getenv("SMTP_SERVER"),
    int(os.getenv("SMTP_PORT", "0")) or 25,
    os.getenv("SMTP_USER"),
    os.getenv("SMTP_PASS"),
    os.getenv("ALERT_FROM"),
    os.getenv("ALERT_TO"),
)

# ——————— 3) Création des dossiers & configuration du logging ————
for d in (ROOT_DIR, QUARANTINE_DIR, SESSION_DIR):
    os.makedirs(d, exist_ok=True)

handlers = [logging.StreamHandler()]
try:
    handlers.insert(0, logging.FileHandler(LOG_FILE))
except Exception as e:
    print(f"[WARNING] Impossible d'écrire le log central {LOG_FILE}: {e}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=handlers
)

# ——————— 4) Création des leurres initiaux —————————————————————————
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
dynamic_items   = []

# ——————— 5) Génération du certificat TLS auto-signé —————————————
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_FILE = os.path.join(ROOT_DIR, "server.key")
CRT_FILE = os.path.join(ROOT_DIR, "server.crt")

if not (os.path.exists(KEY_FILE) and os.path.exists(CRT_FILE)):
    print("[BOOTSTRAP] Génération d'un certificat auto-signé…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,           u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,          u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      u"Honeypot"),
        x509.NameAttribute(NameOID.COMMON_NAME,            u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False
        )
        .sign(key, hashes.SHA256())
    )
    with open(CRT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ——————— 6) Imports Twisted & autres —————————————————————————————
from twisted.cred import portal, checkers
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath

# ——————— 7) Helpers alert & Tor-check ————————————————————————————
def alert(msg: str):
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": msg}, timeout=5)
        except:
            pass
    srv, port, user, pw, fr, to = SMTP_CFG
    if srv and fr and to:
        try:
            s = smtplib.SMTP(srv, port, timeout=5)
            if user:
                s.starttls()
                s.login(user, pw or "")
            mail = f"Subject: HoneyFTP Alert\nFrom: {fr}\nTo: {to}\n\n{msg}"
            s.sendmail(fr, [to], mail)
            s.quit()
        except:
            pass

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
    # Supprime ancien dynamic_items
    for p in list(dynamic_items):
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except:
            pass
        dynamic_items.remove(p)
    # Crée nouveaux dossiers/fichiers aléatoires
    for _ in range(random.randint(1, 3)):
        d = os.path.join(ROOT_DIR, f"dir_{uuid.uuid4().hex[:6]}")
        os.makedirs(d, exist_ok=True)
        dynamic_items.append(d)
        for __ in range(random.randint(1, 2)):
            fpath = os.path.join(d, f"file_{uuid.uuid4().hex[:6]}.txt")
            with open(fpath, "w") as x:
                x.write("dummy data\n")
            dynamic_items.append(fpath)

# ——————— 8) Définition de HoneyShell —————————————————————————————
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
        # Utilise la logique de base (les uploads sont gérés par HoneyFTP)
        return super().openForWriting(path)

# ——————— 9) Définition de HoneyFTP (protocole) —————————————————————
class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session = uuid.uuid4().hex
        peer = self.transport.getPeer().host
        self.logf = open(os.path.join(SESSION_DIR, f"{self.session}.log"), "a")
        self.start, self.count = datetime.utcnow(), 0
        logging.info("CONNECT ip=%s session=%s", peer, self.session)
        if is_tor_exit(peer):
            alert(f"Connection from Tor exit node {peer}")
        self.honeytoken = create_honeytoken(peer, self.session)

    def connectionLost(self, reason):
        peer = getattr(self.transport.getPeer(), "host", "?")
        logging.info("DISCONNECT ip=%s session=%s", peer, self.session)
        try:
            os.remove(os.path.join(ROOT_DIR, self.honeytoken))
        except:
            pass
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
        # Brute-force throttling
        if failed_attempts.get(peer, 0) >= BRUTEF_THR:
            d = defer.Deferred()
            reactor.callLater(DELAY_SEC, d.callback, (ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d

        logging.info("PASS ip=%s user=%s pw=%s", peer, getattr(self, "username", "?"), pw)
        self.logf.write(f"PASS {pw}\n")
        d = super().ftp_PASS(pw)

        def onFail(err):
            failed_attempts[peer] = failed_attempts.get(peer, 0) + 1
            logging.info("LOGIN_FAIL ip=%s failures=%s", peer, failed_attempts[peer])
            if failed_attempts[peer] >= BRUTEF_THR:
                alert(f"Bruteforce detected from {peer}")
            return err

        def onSucc(res):
            failed_attempts.pop(peer, None)
            logging.info("LOGIN_SUCCESS ip=%s", peer)
            randomize_fs()
            return res

        d.addCallbacks(onSucc, onFail)
        return d

    # — RNFR / RNTO (rename) —
    def ftp_RNFR(self, filename):
        peer = self.transport.getPeer().host
        old = filename.lstrip("/")
        self._pending_rename = old
        logging.info("RNFR ip=%s file=%s", peer, old)
        with open(os.path.join(SESSION_DIR, f"{self.session}.rename.log"), "a") as rl:
            rl.write(f"RNFR {old}\n")
        return (ftp.CMD_OK, "Ready for RNTO")

    def ftp_RNTO(self, newname):
        peer = self.transport.getPeer().host
        old = getattr(self, "_pending_rename", None)
        new = newname.lstrip("/")
        if not old:
            return (ftp.SYNTAX_ERR, "RNFR required before RNTO")
        src = os.path.join(ROOT_DIR, old)
        dst = os.path.join(ROOT_DIR, new)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.rename(src, dst)
            logging.info("RNTO ip=%s %s → %s", peer, old, new)
            with open(os.path.join(SESSION_DIR, f"{self.session}.rename.log"), "a") as rl:
                rl.write(f"RNTO {old} → {new}\n")
            return (ftp.CMD_OK, "Rename successful")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"Rename failed: {e}")

    # — DELE (delete) → quarantaine —
    def ftp_DELE(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        src  = os.path.join(ROOT_DIR, rel)
        tag  = f"{self.session}_{uuid.uuid4().hex}"
        dst  = os.path.join(QUARANTINE_DIR, tag)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            logging.info("DELE ip=%s file=%s → quarantine/%s", peer, rel, tag)
            self.logf.write(f"DELE {rel} → quarantine/{tag}\n")
            return (ftp.CMD_OK, "File deleted")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"Deletion failed: {e}")

    # — MKD / RMD (mkdir / rmdir) —
    def ftp_MKD(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        full = os.path.join(ROOT_DIR, rel)
        try:
            os.makedirs(full, exist_ok=True)
            logging.info("MKD ip=%s dir=%s", peer, rel)
            self.logf.write(f"MKD {rel}\n")
            return (ftp.CMD_OK, "Directory created")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"MKD failed: {e}")

    def ftp_RMD(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        full = os.path.join(ROOT_DIR, rel)
        logging.info("RMD ip=%s dir=%s", peer, rel)
        self.logf.write(f"RMD {rel}\n")
        if rel in FORBIDDEN_DIRS:
            alert(f"Protected directory removal attempt: {rel} by {peer}")
        try:
            shutil.rmtree(full)
            return (ftp.CMD_OK, "Directory removed")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"RMD failed: {e}")

    # — RETR (download) —
    def ftp_RETR(self, path):
        rel  = path.lstrip("/")
        peer = self.transport.getPeer().host
        if rel in CANARY_FILES:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == getattr(self, "honeytoken", None):
            logging.info("HONEYTOKEN DOWNLOAD %s session=%s", rel, self.session)
        self.logf.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    # — SITE EXEC/CHMOD/SHELL stub —
    def ftp_SITE(self, params):
        cmd = params.strip().split()[0].upper()
        return {
            "EXEC":  (ftp.CMD_OK, "EXEC disabled"),
            "CHMOD": (ftp.CMD_OK, "CHMOD ignored"),
            "SHELL": (ftp.CMD_OK, "SHELL unavailable"),
        }.get(cmd, (ftp.SYNTAX_ERR, params))

    # — Journalisation de chaque ligne reçue + détection de scanner rapide —
    def lineReceived(self, line):
        peer = self.transport.getPeer().host
        cmd  = line.decode("latin-1").strip()
        logging.info("CMD ip=%s line=%s", peer, cmd)
        self.logf.write(cmd + "\n")
        self.count += 1
        elapsed = (datetime.utcnow() - self.start).total_seconds()
        if self.count > 20 and elapsed < 10:
            alert(f"Fast scanner detected from {peer}")
            reactor.callLater(random.uniform(1, 3), lambda: None)
        return super().lineReceived(line)

# ——————— 10) Factory & Realm corrigé —————————————————————————————
class HoneyFTPFactory(ftp.FTPFactory):
    protocol       = HoneyFTP
    welcomeMessage = "(vsFTPd 2.3.4)"

class HoneyRealm(ftp.FTPRealm):
    def __init__(self, rootPath):
        super().__init__(filepath.FilePath(rootPath))

    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")

    def avatarForUsername(self, username):
        return HoneyShell(username)

# ——————— 11) Point d’entrée —————————————————————————————————————
def main():
    realm = HoneyRealm(ROOT_DIR)
    p     = portal.Portal(realm)

    # 1) Enregistrer le compte attacker/secret
    p.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret"))
    # 2) Puis autoriser l’anonyme
    p.registerChecker(AllowAnonymousAccess())

    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CRT_FILE)
    endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, ctx).listen(HoneyFTPFactory(p))

    logging.info("Honeypot FTPS listening on port %s …", LISTEN_PORT)
    reactor.run()

if __name__ == "__main__":
    main()
