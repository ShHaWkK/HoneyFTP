#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Interaction FTP Honeypot (Implicit FTPS)

Fonctionnalités :
– Bootstrap pip (Twisted, requests, service-identity, cryptography<39)  
– Certificat TLS auto-signé dans un répertoire inscriptible  
– FTPS implicite (SSL4ServerEndpoint)  
– Auth anonymous + attacker/secret  
– Canary-files + honeytoken par session  
– FS dynamique (dirs/fichiers aléatoires)  
– RNFR/RNTO → trace dans .rename.log  
– DELE → quarantaine + log  
– MKD/RMD → alertes sur dirs “interdits”  
– Brute-force throttling + tarpitting  
– Détection Tor exit-nodes  
– SITE EXEC/CHMOD/SHELL factices
– SITE BOF/DEBUG/SQLMAP factices
– Port-knocking optionnel
– Logs centraux + par session
"""

import os, sys, subprocess, shutil, uuid, random, logging, smtplib, tempfile
from datetime import datetime, timedelta

# 1) Bootstrap pip deps
def ensure(pkg, imp=None):
    try: __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])

for pkg, imp in [
    ("twisted", None),
    ("requests", None),
    ("service-identity","service_identity"),
    ("cryptography<39", None),
]:
    ensure(pkg, imp)

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# 2) Choix du répertoire de base
script_dir = os.path.dirname(os.path.abspath(__file__))
if os.access(script_dir, os.W_OK):
    BASE = script_dir
else:
    BASE = os.path.join(tempfile.gettempdir(), "HoneyFTP")
    os.makedirs(BASE, exist_ok=True)
    print(f"[WARN] {script_dir} non-écritable → {BASE}")

ROOT_DIR     = os.path.join(BASE, "virtual_fs")
QUAR_DIR     = os.path.join(BASE, "quarantine")
SESS_DIR     = os.path.join(BASE, "sessions")
LOG_FILE     = os.path.join(BASE, "honeypot.log")
for d in (ROOT_DIR, QUAR_DIR, SESS_DIR):
    os.makedirs(d, exist_ok=True)

# 3) Logging central
handlers = [logging.StreamHandler()]
try:
    handlers.insert(0, logging.FileHandler(LOG_FILE))
except Exception as e:
    print(f"[WARN] ne peut écrire log central : {e}")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(message)s",
                    handlers=handlers)

# 4) Leurrage initial
for rel, content in {
    "passwords.txt":   "admin:admin",
    "secrets/ssh_key": "FAKE_SSH_KEY",
    "docs/readme.txt": "Welcome to the FTP server",
}.items():
    fp = os.path.join(ROOT_DIR, rel)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    if not os.path.exists(fp):
        with open(fp, "w") as f:
            f.write(content)

failed_attempts = {}
dynamic_items   = []
FAKE_FILES      = ["root.txt", "shadow.bak"]
UPLOADS_DIR     = os.path.join(ROOT_DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

# 5) Génération du certificat TLS
KEY_FILE = os.path.join(ROOT_DIR, "server.key")
CRT_FILE = os.path.join(ROOT_DIR, "server.crt")
if not (os.path.exists(KEY_FILE) and os.path.exists(CRT_FILE)):
    logging.info("Génération du certificat auto-signé…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
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
           .not_valid_after(datetime.utcnow()+timedelta(days=365))
           .add_extension(
               x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
               critical=False
           )
           .sign(key, hashes.SHA256())
    )
    with open(CRT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# 6) Twisted & config
from twisted.cred import portal, checkers
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath
from twisted.internet.protocol import Protocol, Factory

TOR_LIST   = "https://check.torproject.org/torbulkexitlist"
BRUTEF_THR = 5
DELAY_SEC  = 2
CANARY     = {"passwords.txt","secrets/ssh_key"}
FORBID     = {"secrets"}
PORT       = int(os.getenv("HONEYFTP_PORT","2121"))
SLACK_URL  = os.getenv("SLACK_WEBHOOK")
KNOCK_SEQ  = [int(p) for p in os.getenv("KNOCK_SEQ","" ).split(',') if p]
SMTP_CFG   = (
    os.getenv("SMTP_SERVER"),
    int(os.getenv("SMTP_PORT","0")) or 25,
    os.getenv("SMTP_USER"),
    os.getenv("SMTP_PASS"),
    os.getenv("ALERT_FROM"),
    os.getenv("ALERT_TO"),
)

def alert(msg: str):
    if SLACK_URL:
        try: requests.post(SLACK_URL, json={"text":msg}, timeout=5)
        except: pass
    srv,port,u,pw,fr,to = SMTP_CFG
    if srv and fr and to:
        try:
            s = smtplib.SMTP(srv, port, timeout=5)
            if u:
                s.starttls(); s.login(u,pw or "")
            mail = f"Subject:HoneyFTP Alert\nFrom:{fr}\nTo:{to}\n\n{msg}"
            s.sendmail(fr,[to], mail); s.quit()
        except: pass

def is_tor_exit(ip: str) -> bool:
    try:
        r = requests.get(TOR_LIST, timeout=5)
        return ip in r.text.splitlines()
    except:
        return False

def create_honeytoken(ip: str, sess: str) -> str:
    fn = f"secret_{uuid.uuid4().hex}.txt"
    with open(os.path.join(ROOT_DIR, fn), "w") as f:
        f.write(f"session={sess}\nip={ip}\n")
    return fn

def randomize_fs():
    for p in list(dynamic_items):
        try: shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
        except: pass
        dynamic_items.remove(p)
    for _ in range(random.randint(1,3)):
        d = os.path.join(ROOT_DIR, f"dir_{uuid.uuid4().hex[:6]}")
        os.makedirs(d, exist_ok=True); dynamic_items.append(d)
        for __ in range(random.randint(1,2)):
            f = os.path.join(d, f"file_{uuid.uuid4().hex[:6]}.txt")
            with open(f,"w") as x: x.write("dummy\n")
            dynamic_items.append(f)

# 7) Shell personnalisé
class HoneyShell(ftp.FTPShell):
    def __init__(self, avatar_id: str):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = avatar_id

    def list(self, path, keys=()):
        d = super().list(path, keys)
        def inject(entries):
            p = path
            if p in (None, [], [''], ['.']):
                for f in FAKE_FILES:
                    entries.append((f, []))
            return entries
        return d.addCallback(inject)

    def openForReading(self, path):
        rel = "/".join(path)
        if rel in CANARY:
            alert(f"CANARY READ {rel} by {self.avatarId}")
        return super().openForReading(path)

    def openForWriting(self, path):
        rel = "/".join(path)
        if not rel.startswith("uploads/"):
            rel = os.path.join("uploads", rel)
        return super().openForWriting(rel.split("/"))

# 8) Protocole avec pièges
class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session = uuid.uuid4().hex
        peer        = self.transport.getPeer().host
        self.logf   = open(os.path.join(SESS_DIR, f"{self.session}.log"), "a")
        self.start, self.count = datetime.utcnow(), 0
        logging.info("CONNECT %s session=%s", peer, self.session)
        if is_tor_exit(peer):
            alert(f"Tor exit node: {peer}")
        self.token = create_honeytoken(peer, self.session)

    def connectionLost(self, reason):
        peer = getattr(self.transport.getPeer(),"host","?")
        logging.info("DISCONNECT %s session=%s", peer, self.session)
        try: os.remove(os.path.join(ROOT_DIR, self.token))
        except: pass
        self.logf.close()
        super().connectionLost(reason)

    def ftp_USER(self, u):
        peer = self.transport.getPeer().host
        self.username = u
        logging.info("USER %s %s", peer, u)
        self.logf.write(f"USER {u}\n")
        return super().ftp_USER(u)

    def ftp_PASS(self, pw):
        peer = self.transport.getPeer().host
        if failed_attempts.get(peer,0) >= BRUTEF_THR:
            d = defer.Deferred()
            reactor.callLater(DELAY_SEC, d.callback,
                              (ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d
        logging.info("PASS %s %s %s", peer, self.username, pw)
        self.logf.write(f"PASS {pw}\n")
        d = super().ftp_PASS(pw)
        def onFail(e):
            failed_attempts[peer] = failed_attempts.get(peer,0) + 1
            if failed_attempts[peer] >= BRUTEF_THR:
                alert(f"Brute-force from {peer}")
            return e
        def onSucc(r):
            failed_attempts.pop(peer,None)
            randomize_fs()
            return r
        d.addCallbacks(onSucc,onFail)
        return d

    def ftp_RNFR(self, fn):
        peer = self.transport.getPeer().host
        old  = fn.lstrip("/")
        self._old = old
        logging.info("RNFR %s %s", peer, old)
        with open(os.path.join(SESS_DIR, f"{self.session}.rename.log"),"a") as rl:
            rl.write(f"RNFR {old}\n")
        return (ftp.CMD_OK, "Ready for RNTO")

    def ftp_RNTO(self, new):
        peer = self.transport.getPeer().host
        old  = getattr(self, "_old", None)
        new  = new.lstrip("/")
        if not old:
            return (ftp.SYNTAX_ERR, "RNFR first")
        src = os.path.join(ROOT_DIR, old)
        dst = os.path.join(ROOT_DIR, new)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.rename(src, dst)
            logging.info("RNTO %s %s→%s", peer, old, new)
            with open(os.path.join(SESS_DIR, f"{self.session}.rename.log"),"a") as rl:
                rl.write(f"RNTO {old}→{new}\n")
            return (ftp.CMD_OK, "Rename done")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"Rename failed: {e}")

    def ftp_DELE(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        tag  = f"{self.session}_{uuid.uuid4().hex}"
        dst  = os.path.join(QUAR_DIR, tag)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(os.path.join(ROOT_DIR, rel), dst)
            logging.info("DELE %s %s→quarantine/%s", peer, rel, tag)
            self.logf.write(f"DELE {rel}→quarantine/{tag}\n")
            return (ftp.CMD_OK, "Deleted")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"Del failed: {e}")

    def ftp_MKD(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        full = os.path.join(ROOT_DIR, rel)
        try:
            os.makedirs(full, exist_ok=True)
            logging.info("MKD %s %s", peer, rel)
            self.logf.write(f"MKD {rel}\n")
            return (ftp.CMD_OK, "MKD done")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"MKD failed: {e}")

    def ftp_RMD(self, path):
        peer = self.transport.getPeer().host
        rel  = path.lstrip("/")
        full = os.path.join(ROOT_DIR, rel)
        logging.info("RMD %s %s", peer, rel)
        self.logf.write(f"RMD {rel}\n")
        if rel in FORBID:
            alert(f"Protected RMD: {rel} by {peer}")
        try:
            shutil.rmtree(full)
            return (ftp.CMD_OK, "RMD done")
        except Exception as e:
            return (ftp.FILE_UNAVAILABLE, f"RMD failed: {e}")

    def ftp_CWD(self, path):
        if path.startswith("../"):
            self.logf.write(f"CWD {path} (traversal)\n")
            return (ftp.CMD_OK, "CWD successful")
        return super().ftp_CWD(path)

    def ftp_RETR(self, path):
        rel  = path.lstrip("/")
        peer = self.transport.getPeer().host
        if rel in CANARY:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == getattr(self, "token", None):
            logging.info("HONEYTOKEN DL %s session=%s", rel, self.session)
        if rel in FAKE_FILES:
            self.logf.write(f"RETR {rel} (fake)\n")
            return (ftp.CMD_OK, f"Contents of {rel}...")
        self.logf.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def ftp_SITE(self, params):
        parts = params.strip().split(None, 1)
        cmd = parts[0].upper() if parts else ""
        arg = parts[1] if len(parts) > 1 else ""
        table = {
            "EXEC":  (ftp.CMD_OK, f"Fake exec: {arg}"),
            "CHMOD": (ftp.CMD_OK, "CHMOD ignored"),
            "SHELL": (ftp.CMD_OK, "SHELL unavailable"),
            "BOF":   (ftp.CMD_OK, "Segmentation fault (simulated)"),
            "DEBUG": (ftp.CMD_OK, open(self.logf.name).read()[-200:]),
            "SQLMAP": (ftp.CMD_OK, "Injection failed: 0 rows"),
        }
        return table.get(cmd, (ftp.SYNTAX_ERR, params))

    def lineReceived(self, line):
        peer = self.transport.getPeer().host
        cmd  = line.decode("latin-1").strip()
        logging.info("CMD %s %s", peer, cmd)
        self.logf.write(cmd + "\n")
        self.count += 1
        elapsed = (datetime.utcnow() - self.start).total_seconds()
        if self.count > 20 and elapsed < 10:
            alert(f"Fast scanner {peer}")
            reactor.callLater(random.uniform(1, 3), lambda: None)
        return super().lineReceived(line)

# 9) Factory & Realm
class HoneyFTPFactory(ftp.FTPFactory):
    protocol       = HoneyFTP
    welcomeMessage = "(vsFTPd 2.3.4)"

class HoneyRealm(ftp.FTPRealm):
    def __init__(self, root: str):
        # root doit être converti en FilePath
        super().__init__(filepath.FilePath(root))

    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")

    def avatarForUsername(self, username: str):
        return HoneyShell(username)

# 10) Main
def main():
    realm = HoneyRealm(ROOT_DIR)
    p     = portal.Portal(realm)

    # 1) attacker/secret
    p.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret"))
    # 2) anonymous
    p.registerChecker(AllowAnonymousAccess())

    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CRT_FILE)

    def start_ftp():
        if getattr(start_ftp, "started", False):
            return
        start_ftp.started = True
        endpoints.SSL4ServerEndpoint(reactor, PORT, ctx).listen(HoneyFTPFactory(p))
        logging.info("Honeypot FTPS listening on port %s", PORT)
        logging.info("Verify firewall allows traffic on %s", PORT)

    if KNOCK_SEQ:
        knocks = {}

        class KnockProtocol(Protocol):
            def connectionMade(self):
                ip = self.transport.getPeer().host
                idx, last = knocks.get(ip, (0, reactor.seconds()))
                if reactor.seconds() - last > 5:
                    idx = 0
                port = self.factory.port
                if port == KNOCK_SEQ[idx]:
                    idx += 1
                    if idx == len(KNOCK_SEQ):
                        start_ftp()
                        idx = 0
                else:
                    idx = 1 if port == KNOCK_SEQ[0] else 0
                knocks[ip] = (idx, reactor.seconds())
                self.transport.loseConnection()

        for kp in KNOCK_SEQ:
            f = Factory(); f.protocol = KnockProtocol; f.port = kp
            reactor.listenTCP(kp, f)
        logging.info("Waiting for knock sequence %s", KNOCK_SEQ)
    else:
        start_ftp()

    reactor.run()

if __name__ == "__main__":
    main()
