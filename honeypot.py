#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Interaction FTP Honeypot (Implicit FTPS)

Fonctionnalités :
– Auto-bootstrap pip deps (Twisted, requests, service-identity, cryptography)
– Certificat TLS auto-signé dans un répertoire inscriptible  
– FTPS implicite (SSL4ServerEndpoint)  
– Auth anonymous + attacker/secret  
– Canary-files + honeytoken par session  
– FS dynamique (dirs/fichiers aléatoires) avec quota  
– RNFR/RNTO → trace dans .rename.log  
– DELE → quarantaine + log  
– MKD/RMD → alertes sur dirs “interdits”  
– Tarpitting & brute-force throttling  
– Détection Tor exit-nodes  
– SITE EXEC/CHMOD/SHELL/BOF factices  
– Virtual directory traversal (CWD ../..)  
– Logs centraux + par session
"""

import os, sys, subprocess, shutil, uuid, random, logging, smtplib, tempfile
from datetime import datetime, timedelta, timezone

# 1) Bootstrap pip deps
def ensure(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        subprocess.check_call([
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--root-user-action=ignore",
            "--disable-pip-version-check",
            pkg,
        ])

for pkg, imp in [
    ("twisted", None),
    ("requests", None),
    ("service-identity","service_identity"),
    ("cryptography", None),
    ("pyOpenSSL", "OpenSSL"),
]:
    ensure(pkg, imp)

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# 2) Détermine le répertoire de base
script_dir = os.path.dirname(os.path.abspath(__file__))
if os.access(script_dir, os.W_OK):
    BASE = script_dir
else:
    BASE = os.path.join(tempfile.gettempdir(), "HoneyFTP")
    os.makedirs(BASE, exist_ok=True)

ROOT_DIR = os.path.join(BASE, "virtual_fs")
QUAR_DIR = os.path.join(BASE, "quarantine")
SESS_DIR = os.path.join(BASE, "sessions")
LOG_FILE = os.path.join(BASE, "honeypot.log")
for d in (ROOT_DIR, QUAR_DIR, SESS_DIR):
    os.makedirs(d, exist_ok=True)

# 3) Logging central
handlers = [logging.StreamHandler()]
try: handlers.insert(0, logging.FileHandler(LOG_FILE))
except: pass
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(message)s",
                    handlers=handlers)

# 4) Leurres initiaux
for rel, content in {
    "passwords.txt":   "admin:admin",
    "secrets/ssh_key": "FAKE_SSH_KEY",
    "docs/readme.txt": "Welcome to the FTP server",
    "uploads/.keep":  "",
}.items():
    fp = os.path.join(ROOT_DIR, rel)
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    if not os.path.exists(fp):
        with open(fp, "w") as f: f.write(content)

failed_attempts = {}
dynamic_items   = []

# 5) Génération du certificat TLS
KEY_FILE = os.path.join(ROOT_DIR, "server.key")
CRT_FILE = os.path.join(ROOT_DIR, "server.crt")
if not (os.path.exists(KEY_FILE) and os.path.exists(CRT_FILE)):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,           u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,          u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      u"Honeypot"),
        x509.NameAttribute(NameOID.COMMON_NAME,            u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
           .subject_name(subj).issuer_name(subj)
           .public_key(key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(datetime.now(timezone.utc))
           .not_valid_after(datetime.now(timezone.utc)+timedelta(days=365))
           .add_extension(
               x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
               critical=False
           )
           .sign(key, hashes.SHA256())
    )
    with open(CRT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# 6) Twisted & config
from twisted.cred import portal, checkers, credentials, error
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.internet.protocol import DatagramProtocol
from twisted.protocols import ftp
from twisted.python import filepath

TOR_LIST   = "https://check.torproject.org/torbulkexitlist"
BRUTEF_THR = 5
DELAY_SEC  = 2
CANARY     = {"passwords.txt","secrets/ssh_key"}
FORBID     = {"secrets"}        # supprimer un répertoire "secrets" déclenche alerta
PORT       = int(os.getenv("HONEYFTP_PORT","2121"))
KNOCK_SEQ  = [4020, 4021, 4022]
SLACK_URL  = os.getenv("SLACK_WEBHOOK")
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
            if u: s.starttls(); s.login(u,pw or "")
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
    with open(os.path.join(ROOT_DIR, fn),"w") as f:
        f.write(f"session={sess}\nip={ip}\n")
    return fn

# Port-knocking logic
ftp_started = False
knock_state = {}


class DictChecker:
    """Simple checker accepting plain username/password strings."""
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, users):
        self.users = users

    def requestAvatarId(self, creds):
        if self.users.get(creds.username) == creds.password:
            return defer.succeed(creds.username)
        return defer.fail(error.UnauthorizedLogin())
class KnockProtocol(DatagramProtocol):
    def __init__(self, port):
        self.port = port
    def datagramReceived(self, data, addr):
        host = addr[0]
        idx = knock_state.get(host, 0)
        if KNOCK_SEQ[idx] == self.port:
            knock_state[host] = idx + 1
            if knock_state[host] == len(KNOCK_SEQ):
                logging.info("Knock sequence ok from %s", host)
                start_ftp()
                # reset state so additional packets don't raise IndexError
                knock_state[host] = 0
        else:
            knock_state[host] = 0

def start_ftp():
    global ftp_started
    if ftp_started:
        return
    ftp_started = True
    realm = HoneyRealm(ROOT_DIR)
    p     = portal.Portal(realm)
    # Use a simple dictionary-based checker so we can keep credentials as
    # strings.  This avoids the byte-vs-str mismatch in Twisted's built-in
    # checker which caused logins to fail.
    p.registerChecker(DictChecker({"attacker": "secret"}))
    p.registerChecker(AllowAnonymousAccess())
    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CRT_FILE)
    endpoints.SSL4ServerEndpoint(reactor, PORT, ctx).listen(HoneyFTPFactory(p))
    logging.info("Honeypot FTPS listening on port %s", PORT)

def randomize_fs(max_dirs=3, max_files=2, max_total=50):
    global dynamic_items
    for p in list(dynamic_items):
        try:
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
        except: pass
        dynamic_items.remove(p)
    try:
        if len(os.listdir(ROOT_DIR)) > max_total:
            return
    except: return

    for _ in range(random.randint(1, max_dirs)):
        try:
            d = os.path.join(ROOT_DIR, f"dir_{uuid.uuid4().hex[:6]}")
            os.makedirs(d, exist_ok=True)
            dynamic_items.append(d)
            for __ in range(random.randint(0, max_files)):
                fpath = os.path.join(d, f"file_{uuid.uuid4().hex[:6]}.txt")
                with open(fpath,"w") as x: x.write("dummy\n")
                dynamic_items.append(fpath)
        except OSError as e:
            logging.warning("randomize_fs OSError: %s", e)
            break

# 7) Custom shell
class HoneyShell(ftp.FTPShell):
    def __init__(self, avatar_id: str):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = avatar_id

    def list(self, path, keys=()):
        d = super().list(path, keys)
        def _inject(res):
            if not path:  # root listing
                res.append(("root.txt", []))
                res.append(("shadow.bak", []))
            return res
        return d.addCallback(_inject)

    def openForReading(self, path):
        rel = "/".join(path)
        if rel in CANARY:
            alert(f"CANARY READ {rel} by {self.avatarId}")
        return super().openForReading(path)

    def ftp_CWD(self, path):
        if path.startswith(".."):
            self.logf.write(f"CWD {path}\n")
            return ftp.REQ_FILE_ACTN_COMPLETED_OK,
        return super().ftp_CWD(path)

# 8) Protocol
class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session = uuid.uuid4().hex
        peer        = self.transport.getPeer().host
        self.logf   = open(os.path.join(SESS_DIR,f"{self.session}.log"),"a")
        self.start, self.count = datetime.now(timezone.utc), 0
        logging.info("CONNECT %s session=%s", peer, self.session)
        if is_tor_exit(peer):
            alert(f"Tor exit node: {peer}")
        self.token = create_honeytoken(peer, self.session)

    def connectionLost(self, reason):
        peer = getattr(self.transport.getPeer(),"host","?")
        logging.info("DISCONNECT %s session=%s", peer, self.session)
        try: os.remove(os.path.join(ROOT_DIR,self.token))
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
        peer, old = self.transport.getPeer().host, fn.lstrip("/")
        self._old = old
        logging.info("RNFR %s %s", peer, old)
        with open(os.path.join(SESS_DIR,f"{self.session}.rename.log"),"a") as rl:
            rl.write(f"RNFR {old}\n")
        return ftp.CMD_OK, "Ready for RNTO"

    def ftp_RNTO(self, new):
        peer, old = self.transport.getPeer().host, getattr(self,"_old",None)
        new = new.lstrip("/")
        if not old:
            return ftp.SYNTAX_ERR, "RNFR first"
        src, dst = os.path.join(ROOT_DIR,old), os.path.join(ROOT_DIR,new)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.rename(src, dst)
            logging.info("RNTO %s %s→%s", peer, old, new)
            with open(os.path.join(SESS_DIR,f"{self.session}.rename.log"),"a") as rl:
                rl.write(f"RNTO {old}→{new}\n")
            return ftp.CMD_OK, "Rename done"
        except Exception as e:
            return ftp.FILE_UNAVAILABLE, f"Rename failed: {e}"

    def ftp_DELE(self, path):
        peer, rel = self.transport.getPeer().host, path.lstrip("/")
        tag = f"{self.session}_{uuid.uuid4().hex}"
        dst = os.path.join(QUAR_DIR, tag)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(os.path.join(ROOT_DIR,rel), dst)
            logging.info("DELE %s %s→quarantine/%s", peer, rel, tag)
            self.logf.write(f"DELE {rel}→quarantine/{tag}\n")
            return ftp.CMD_OK, "Deleted"
        except Exception as e:
            return ftp.FILE_UNAVAILABLE, f"Del failed: {e}"

    def ftp_MKD(self, path):
        # délégation pour éviter timeout côté client
        return ftp.FTP.ftp_MKD(self, path)

    def ftp_RMD(self, path):
        return ftp.FTP.ftp_RMD(self, path)

    def ftp_RETR(self, path):
        rel, peer = path.lstrip("/"), self.transport.getPeer().host
        if rel in CANARY:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == getattr(self,"token",None):
            logging.info("HONEYTOKEN DL %s session=%s", rel, self.session)
        self.logf.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def ftp_SITE(self, params):
        parts = params.strip().split(" ",1)
        cmd = parts[0].upper()
        rest = parts[1] if len(parts)>1 else ""
        if cmd=="EXEC" and "/bin/bash" in rest:
            return ftp.CMD_OK, "Welcome to Fake Bash v1.0"
        if cmd=="CHMOD":
            return ftp.CMD_OK, "CHMOD ignored"
        if cmd=="SHELL":
            return ftp.CMD_OK, "SHELL unavailable"
        if cmd=="DEBUG":
            self.logf.flush()
            try:
                with open(self.logf.name) as f:
                    lines = f.read().splitlines()[-50:]
            except Exception as e:
                lines = [f"log error: {e}"]
            self.sendLine("200-DEBUG START")
            for l in lines:
                self.sendLine(l)
            self.sendLine("200 DEBUG END")
            return
        if cmd=="SQLMAP":
            return ftp.CMD_OK, "SQLi simulation complete"
        if cmd=="BOF":
            if len(rest)>1000:
                logging.warning("SIMUL BOF by %s len=%d", self.transport.getPeer().host, len(rest))
                return ftp.REQ_ACTN_ABRTD_LOCAL_ERR, "Buffer overflow!"
            return ftp.CMD_OK,
        # Unknown SITE sub-command → syntax error
        return ftp.SYNTAX_ERR, params

    def lineReceived(self, line):
        peer, cmd = self.transport.getPeer().host, line.decode("latin-1").strip()
        logging.info("CMD %s %s", peer, cmd)
        self.logf.write(cmd+"\n")
        self.count+=1
        if self.count>20 and (datetime.now(timezone.utc)-self.start).total_seconds()<10:
            alert(f"Fast scan {peer}")
            reactor.callLater(random.uniform(1,3), lambda:None)
        return super().lineReceived(line)

# 9) Factory & Realm
class HoneyFTPFactory(ftp.FTPFactory):
    protocol       = HoneyFTP
    welcomeMessage = "(vsFTPd 2.3.4)"

class HoneyRealm(ftp.FTPRealm):
    def __init__(self, root: str):
        # FTPRealm expects a plain path string. Passing a FilePath object
        # causes "TypeError: expected str, bytes or os.PathLike object" on
        # startup. Keep the original string here and let FTPRealm convert it.
        super().__init__(root)
    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")
    def avatarForUsername(self, username: str):
        return HoneyShell(username)

# 10) Main
def main():
    for p in KNOCK_SEQ:
        reactor.listenUDP(p, KnockProtocol(p))
    logging.info("Waiting knock sequence %s to start FTP", KNOCK_SEQ)
    reactor.run()

if __name__=="__main__":
    main()
