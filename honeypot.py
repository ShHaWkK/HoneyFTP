#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced FTP Honeypot.

– Bootstrap des dépendances manquantes (Twisted, requests, service-identity, pin crypto<39 sous 3.7)  
– Génération auto d’un server.key/server.crt PEM non chiffré si introuvables  
– Autorisation FTP anonyme + compte attacker/secret  
– Shell Twisted FTPShell/FTPAnonymousShell (plus de FileSystem)  
"""

import subprocess, sys, os, shutil

def ensure_installed(pkg_name, import_name=None):
    name = import_name or pkg_name
    try:
        __import__(name)
    except ImportError:
        print(f"[BOOTSTRAP] installation de {pkg_name}…")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "--upgrade", pkg_name
        ])

# 1) Dépendances + pin crypto pour Python 3.7
deps = [
    ("twisted",              None),
    ("requests",             None),
    ("service-identity",    "service_identity"),
    ("cryptography<39",       None),
]
for pkg, imp in deps:
    ensure_installed(pkg, imp)

# 2) Génération d'une paire clé/certif auto-signée si manquante
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

KEY_FILE, CERT_FILE = "server.key", "server.crt"

def generate_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,           u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,          u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      u"Honeypot"),
        x509.NameAttribute(NameOID.COMMON_NAME,            u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
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

if not (os.path.exists(KEY_FILE) and os.path.exists(CERT_FILE)):
    print("[BOOTSTRAP] génération d'un certificat auto-signé…")
    generate_cert()

# ——— Imports Twisted & co —————————————————————————————————

import logging, uuid, hashlib, random, smtplib
from datetime import datetime

import requests
from twisted.cred import portal, checkers
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath

# ——— Configuration générale —————————————————————————————

ROOT_DIR        = "virtual_fs"
QUARANTINE_DIR  = "quarantine"
SESSION_LOG_DIR = "sessions"
LOG_FILE        = "honeypot.log"
TOR_EXIT_LIST   = "https://check.torproject.org/torbulkexitlist"
BRUTEFORCE_THRESHOLD = 5
DELAY_SECONDS        = 2
CANARY_FILES         = {"passwords.txt", "secrets/ssh_key"}

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")
SMTP_SERVER   = os.environ.get("SMTP_SERVER")
SMTP_PORT     = int(os.environ.get("SMTP_PORT","0")) or None
SMTP_USER     = os.environ.get("SMTP_USER")
SMTP_PASS     = os.environ.get("SMTP_PASS")
ALERT_FROM    = os.environ.get("ALERT_FROM")
ALERT_TO      = os.environ.get("ALERT_TO")
LISTEN_PORT   = int(os.environ.get("HONEYFTP_PORT","2121"))

# ——— Logging & dossiers ——————————————————————————————————

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[ logging.FileHandler(LOG_FILE), logging.StreamHandler() ],
)

os.makedirs(ROOT_DIR,       exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SESSION_LOG_DIR, exist_ok=True)

# fichiers-leurres initiaux
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
DYNAMIC_ITEMS = []

# ——— Fonctions d’alerte ——————————————————————————————————

def alert(msg: str):
    if SLACK_WEBHOOK:
        try: requests.post(SLACK_WEBHOOK, json={"text": msg}, timeout=5)
        except Exception as e: logging.warning("Slack failed: %s", e)
    if SMTP_SERVER and ALERT_FROM and ALERT_TO:
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT or 25, timeout=5) as s:
                if SMTP_USER:
                    s.starttls(); s.login(SMTP_USER, SMTP_PASS or "")
                body = f"Subject: HoneyFTP Alert\nFrom: {ALERT_FROM}\nTo: {ALERT_TO}\n\n{msg}"
                s.sendmail(ALERT_FROM, [ALERT_TO], body)
        except Exception as e:
            logging.warning("SMTP failed: %s", e)

def is_tor_exit(ip: str) -> bool:
    try:
        r = requests.get(TOR_EXIT_LIST, timeout=5)
        return ip.strip() in r.text.splitlines() if r.status_code == 200 else False
    except Exception as e:
        logging.warning("Tor check failed: %s", e)
        return False

# ——— Honeytoken & filesystem helpers ——————————————————————

def create_honeytoken(ip: str, session: str) -> str:
    """Create a unique honeytoken file and return its relative path."""
    name = f"secret_{uuid.uuid4().hex}.txt"
    path = os.path.join(ROOT_DIR, name)
    with open(path, "w") as f:
        f.write(f"session={session}\nip={ip}\n")
    return name

def randomize_filesystem():
    """Add and remove random files/directories in the virtual FS."""
    # Remove old dynamic items
    for p in list(DYNAMIC_ITEMS):
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except FileNotFoundError:
            pass
        finally:
            DYNAMIC_ITEMS.remove(p)

    # Create new random structure
    for _ in range(random.randint(1, 3)):
        d = os.path.join(ROOT_DIR, f"dir_{uuid.uuid4().hex[:6]}")
        os.makedirs(d, exist_ok=True)
        DYNAMIC_ITEMS.append(d)
        for _ in range(random.randint(1, 2)):
            fname = os.path.join(d, f"file_{uuid.uuid4().hex[:6]}.txt")
            with open(fname, "w") as f:
                f.write("dummy data\n")
            DYNAMIC_ITEMS.append(fname)

# ——— Shell FTP personnalisé ——————————————————————————————

class HoneyShell(ftp.FTPShell):
    def __init__(self, avatar_id):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = avatar_id

    def openForReading(self, path):
        rel = "/".join(path)
        if rel in CANARY_FILES:
            alert(f"Canary read: {rel} by {self.avatarId}")
        return super().openForReading(path)

    def openForWriting(self, path):
        p = self._path(path)
        if p.isdir(): return defer.fail(ftp.IsADirectoryError(path))
        try:
            real = p.open("wb")
        except OSError as e:
            return ftp.errnoToFailure(e.errno, path)

        sess = uuid.uuid4().hex
        qf   = open(os.path.join(QUARANTINE_DIR, sess), "wb")
        md5  = hashlib.md5(); sha = hashlib.sha256()

        class Tee:
            def registerProducer(self,*a): pass
            def unregisterProducer(self):
                real.close(); qf.close()
            def write(self, data):
                real.write(data); qf.write(data)
                md5.update(data); sha.update(data)

        class Writer:
            def __init__(self): self._once=False
            def receive(self):
                if self._once: raise RuntimeError("receive() déjà appelé")
                self._once=True
                return defer.succeed(Tee())
            def close(self):
                real.close(); qf.close()
                logging.info(
                    "UPLOAD ip=%s file=%s md5=%s sha256=%s session=%s",
                    self.avatarId, "/".join(path),
                    md5.hexdigest(), sha.hexdigest(), sess
                )
                if os.path.basename(path[-1]) in CANARY_FILES:
                    alert(f"Canary upload: {'/'.join(path)} by {self.avatarId}")
                return defer.succeed(None)

        return defer.succeed(Writer())

# ——— Protocole FTP + détection ——————————————————————————

class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session_id  = uuid.uuid4().hex
        ip               = self.transport.getPeer().host
        self.session_log = open(
            os.path.join(SESSION_LOG_DIR, f"{self.session_id}.log"), "a"
        )
        self.start, self.count = datetime.utcnow(), 0
        logging.info("CONNECT ip=%s session=%s", ip, self.session_id)
        if is_tor_exit(ip):
            logging.info("TOR_EXIT ip=%s", ip)
            alert(f"Tor exit node: {ip}")
        # create a unique honeytoken for this session
        self.honeytoken = create_honeytoken(ip, self.session_id)

    def connectionLost(self, reason):
        ip = getattr(self.transport.getPeer(), "host", "?")
        logging.info("DISCONNECT ip=%s session=%s", ip, self.session_id)
        try:
            os.remove(os.path.join(ROOT_DIR, getattr(self, "honeytoken", "")))
        except OSError:
            pass
        self.session_log.close()
        super().connectionLost(reason)

    def ftp_USER(self, u):
        ip = self.transport.getPeer().host
        self.username = u
        logging.info("USER ip=%s user=%s", ip, u)
        self.session_log.write(f"USER {u}\n")
        return super().ftp_USER(u)

    def ftp_PASS(self, pw):
        ip = self.transport.getPeer().host
        if failed_attempts.get(ip, 0) >= BRUTEFORCE_THRESHOLD:
            d = defer.Deferred()
            reactor.callLater(
                DELAY_SECONDS, d.callback, (ftp.RESPONSE[ftp.AUTH_FAILED][0],)
            )
            return d

        logging.info("PASS ip=%s user=%s pw=%s", ip, getattr(self,"username","?"), pw)
        self.session_log.write(f"PASS {pw}\n")
        d = super().ftp_PASS(pw)

        def on_fail(err):
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            logging.info("LOGIN_FAIL ip=%s count=%s", ip, failed_attempts[ip])
            self.session_log.write("LOGIN_FAIL\n")
            if failed_attempts[ip] >= BRUTEFORCE_THRESHOLD:
                alert(f"Bruteforce detected from {ip}")
            return err

        def on_succ(res):
            failed_attempts.pop(ip, None)
            logging.info("LOGIN_SUCCESS ip=%s", ip)
            self.session_log.write("LOGIN_SUCCESS\n")
            randomize_filesystem()
            return res

        d.addCallbacks(on_succ, on_fail)
        return d

    def ftp_RETR(self, path):
        rel = path.lstrip("/")
        if rel in CANARY_FILES:
            alert(f"Canary download: {rel} by {self.transport.getPeer().host}")
        if rel == getattr(self, "honeytoken", None):
            logging.info(
                "HONEYTOKEN_DOWNLOAD ip=%s file=%s session=%s",
                self.transport.getPeer().host,
                rel,
                self.session_id,
            )
        self.session_log.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def ftp_SITE(self, params):
        parts = params.strip().split()
        cmd = parts[0].upper() if parts else ""
        if cmd == "EXEC":
            return (ftp.CMD_OK, "EXEC disabled")
        elif cmd == "CHMOD":
            return (ftp.CMD_OK, "CHMOD ignored")
        elif cmd == "SHELL":
            return (ftp.CMD_OK, "SHELL unavailable")
        else:
            return (ftp.SYNTAX_ERR, params)

    def lineReceived(self, line):
        ip  = self.transport.getPeer().host
        cmd = line.decode("latin-1")
        logging.info("CMD ip=%s cmd=%s", ip, cmd)
        self.session_log.write(cmd + "\n")
        self.count += 1
        if self.count > 20 and (datetime.utcnow() - self.start).total_seconds() < 10:
            alert(f"Fast scanner detected from {ip}")
            reactor.callLater(random.uniform(1,3), lambda: None)
        return super().lineReceived(line)

class HoneyFTPFactory(ftp.FTPFactory):
    protocol = HoneyFTP
    welcomeMessage = "(vsFTPd 2.3.4)"

class HoneyRealm(ftp.FTPRealm):
    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")
    def avatarForUsername(self, u):
        return HoneyShell(u)

def main():
    realm = HoneyRealm(ROOT_DIR)
    port  = portal.Portal(realm)
    # 1) autorise l’anonyme
    port.registerChecker(AllowAnonymousAccess())
    # 2) puis le compte attacker/secret
    port.registerChecker(
        checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret")
    )

    factory = HoneyFTPFactory(port)
    ctx     = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CERT_FILE)
    ep      = endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, ctx)
    ep.listen(factory)

    logging.info("Honeypot listening on port %s", LISTEN_PORT)
    reactor.run()

if __name__ == "__main__":
    main()
