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
    ("colorama", None),
]:
    ensure(pkg, imp)

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from colorama import init as color_init, Fore, Style

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
OP_LOG   = os.path.join(BASE, "operations.log")
VERSION  = "1.1"
SERVER_START = datetime.now(timezone.utc)
for d in (ROOT_DIR, QUAR_DIR, SESS_DIR):
    os.makedirs(d, exist_ok=True)

# 3) Logging central
color_init()

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.WHITE + Style.BRIGHT,
    }
    RESET = Style.RESET_ALL

    def format(self, record):
        msg = super().format(record)
        color = self.COLORS.get(record.levelno, self.RESET)
        return color + msg + self.RESET

plain_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
color_fmt = ColorFormatter("%(asctime)s [%(levelname)s] %(message)s")

handlers = []
try:
    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(plain_fmt)
    handlers.append(fh)
except Exception:
    pass

sh = logging.StreamHandler()
sh.setFormatter(color_fmt)
handlers.append(sh)

logging.basicConfig(level=logging.INFO, handlers=handlers)

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
# Counters for SITE STATS
STATS = {
    "connections": 0,
    "logins": 0,
    "uploads": 0,
    "downloads": 0,
    "deletes": 0,
    "renames": 0,
}

# Limite maximale d'espace disque pour le faux filesystem (10 Mo)
QUOTA_BYTES = 10 * 1024 * 1024

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
from twisted.internet import endpoints, reactor, ssl, defer, error as net_error
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

def log_operation(msg: str):
    """Append an entry to the operations log."""
    try:
        with open(OP_LOG, "a") as f:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass

TOR_CACHE = {"ts": None, "ips": set()}

def is_tor_exit(ip: str) -> bool:
    """Vérifie si l'IP provient d'un noeud de sortie Tor (cache 1h)."""
    now = datetime.now(timezone.utc)
    if not TOR_CACHE["ts"] or (now - TOR_CACHE["ts"]) > timedelta(hours=1):
        try:
            r = requests.get(TOR_LIST, timeout=5)
            TOR_CACHE["ips"] = set(r.text.splitlines())
            TOR_CACHE["ts"] = now
        except Exception:
            return False
    return ip in TOR_CACHE["ips"]

def create_honeytoken(ip: str, sess: str) -> str:
    fn = f"secret_{uuid.uuid4().hex}.txt"
    with open(os.path.join(ROOT_DIR, fn),"w") as f:
        f.write(f"session={sess}\nip={ip}\n")
    return fn

def create_user_lure(user: str) -> str:
    """Create a user-specific lure file."""
    fn = f"notes_{user}.txt"
    path = os.path.join(ROOT_DIR, fn)
    try:
        with open(path, "w") as f:
            f.write(f"Private notes for {user}\n")
        log_operation(f"LURE {fn}")
    except Exception:
        pass
    return fn

def validate_path(rel: str) -> str:
    """Valide un chemin fourni par un client et retourne le chemin absolu"""
    rel = rel.lstrip("/")
    abs_path = os.path.abspath(os.path.join(ROOT_DIR, rel))
    if not abs_path.startswith(os.path.abspath(ROOT_DIR)):
        raise ValueError("Invalid path")
    return abs_path

def disk_usage(path: str) -> int:
    """Retourne la taille totale (en octets) d'un répertoire."""
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total

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
    p.registerChecker(DictChecker({
        "attacker": "secret",
        "ftpman": "ftpman",
    }))
    p.registerChecker(AllowAnonymousAccess())
    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CRT_FILE)
    def _listen_ssl(port, factory, *a, **kw):
        return reactor.listenSSL(port, factory, ctx, *a, **kw)
    HoneyFTP.listenFactory = staticmethod(_listen_ssl)
    port_range = range(60000, 60100)
    HoneyFTP.passivePortRange = port_range
    HoneyFTPFactory.passivePortRange = port_range
    factory = HoneyFTPFactory(p, ctx)
    factory.passivePortRange = port_range
    endpoints.SSL4ServerEndpoint(reactor, PORT, ctx).listen(factory)
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
            sub = os.path.join(d, f"proj_{uuid.uuid4().hex[:4]}")
            os.makedirs(sub, exist_ok=True)
            dynamic_items.append(sub)
            if random.random() > 0.5:
                sf = os.path.join(sub, "README.txt")
                with open(sf, "w") as x: x.write("project notes\n")
                dynamic_items.append(sf)
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
        try:
            validate_path(rel)
        except ValueError:
            return defer.fail(FileNotFoundError(rel))
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
        STATS["connections"] += 1
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
            lure = create_user_lure(self.username)
            log_operation(f"LOGIN {self.username} session={self.session} lure={lure}")
            STATS["logins"] += 1
            return r
        d.addCallbacks(onSucc,onFail)
        return d

    def ftp_RNFR(self, fn):
        peer = self.transport.getPeer().host
        try:
            old = validate_path(fn)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        self._old = os.path.relpath(old, ROOT_DIR)
        logging.info("RNFR %s %s", peer, old)
        with open(os.path.join(SESS_DIR, f"{self.session}.rename.log"), "a") as rl:
            rl.write(f"RNFR {old}\n")
        log_operation(f"RNFR {old} from {peer} session={self.session}")
        self.sendLine("350 Ready for RNTO")
        return

    def ftp_RNTO(self, new):
        peer = self.transport.getPeer().host
        old_rel = getattr(self, "_old", None)
        try:
            new_path = validate_path(new)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        new_rel = os.path.relpath(new_path, ROOT_DIR)
        old_path = os.path.join(ROOT_DIR, old_rel) if old_rel else None
        if not old_rel:
            self.sendLine("550 RNFR first")
            return
        src, dst = old_path, new_path
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.rename(src, dst)
            logging.info("RNTO %s %s→%s", peer, old_rel, new_rel)
            with open(os.path.join(SESS_DIR, f"{self.session}.rename.log"), "a") as rl:
                rl.write(f"RNTO {old_rel}→{new_rel}\n")
            log_operation(f"RNTO {old_rel}->{new_rel} from {peer} session={self.session}")
            STATS["renames"] += 1
            self.sendLine("250 Rename done")
            return
        except Exception as e:
            self.sendLine(f"550 Rename failed: {e}")
            return

    def ftp_DELE(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path = validate_path(path)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        rel = os.path.relpath(abs_path, ROOT_DIR)
        tag = f"{self.session}_{uuid.uuid4().hex}"
        dst = os.path.join(QUAR_DIR, tag)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(abs_path, dst)
            logging.info("DELE %s %s→quarantine/%s", peer, rel, tag)
            self.logf.write(f"DELE {rel}→quarantine/{tag}\n")
            log_operation(f"DELE {rel} by {peer} session={self.session}")
            STATS["deletes"] += 1
            self.sendLine("250 Deleted")
            return
        except Exception as e:
            self.sendLine(f"550 Del failed: {e}")
            return

    def ftp_MKD(self, path):
        try:
            validate_path(path)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        res = ftp.FTP.ftp_MKD(self, path)
        log_operation(f"MKD {path} session={self.session}")
        return res

    def ftp_RMD(self, path):
        try:
            validate_path(path)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        res = ftp.FTP.ftp_RMD(self, path)
        log_operation(f"RMD {path} session={self.session}")
        return res

    def ftp_RETR(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path = validate_path(path)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        rel = os.path.relpath(abs_path, ROOT_DIR)
        if rel in CANARY:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == getattr(self, "token", None):
            logging.info("HONEYTOKEN DL %s session=%s", rel, self.session)
        self.logf.write(f"RETR {rel}\n")
        log_operation(f"RETR {rel} by {peer} session={self.session}")
        STATS["downloads"] += 1
        return super().ftp_RETR('/' + rel)

    def ftp_STOR(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path = validate_path(path)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        if disk_usage(ROOT_DIR) >= QUOTA_BYTES:
            self.sendLine("552 Quota exceeded")
            return
        rel = os.path.relpath(abs_path, ROOT_DIR)
        self.logf.write(f"STOR {rel}\n")
        log_operation(f"STOR {rel} by {peer} session={self.session}")
        STATS["uploads"] += 1
        return super().ftp_STOR('/' + rel)

    def ftp_SITE(self, params):
        parts = params.strip().split(" ",1)
        cmd = parts[0].upper()
        rest = parts[1] if len(parts)>1 else ""
        if cmd=="EXEC" and "/bin/bash" in rest:
            self.sendLine("200 Welcome to Fake Bash v1.0")
            return
        if cmd=="CHMOD":
            self.sendLine("200 CHMOD ignored")
            return
        if cmd=="SHELL":
            self.sendLine("200 SHELL unavailable")
            return
        if cmd=="HELP":
            self.sendLine("200 EXEC CHMOD SHELL DEBUG SQLMAP BOF HELP VERSION GETLOG HISTORY UPTIME STATS")
            return
        if cmd=="VERSION":
            self.sendLine(f"200 {VERSION}")
            return
        if cmd=="GETLOG":
            logfp = OP_LOG if not rest else os.path.join(SESS_DIR, rest+".log")
            try:
                with open(logfp) as f:
                    lines = f.read().splitlines()[-20:]
            except Exception as e:
                lines = [f"log error: {e}"]
            self.sendLine("200-LOG START")
            for l in lines:
                self.sendLine(l)
            self.sendLine("200 LOG END")
            return
        if cmd=="HISTORY":
            target = rest.strip()
            try:
                with open(OP_LOG) as f:
                    lines = [l for l in f.read().splitlines() if target in l][-20:]
            except Exception as e:
                lines = [f"history error: {e}"]
            self.sendLine("200-HISTORY START")
            for l in lines:
                self.sendLine(l)
            self.sendLine("200 HISTORY END")
            return
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
        if cmd=="UPTIME":
            uptime = datetime.now(timezone.utc) - SERVER_START
            self.sendLine(f"200 {str(uptime).split('.')[0]}")
            return
        if cmd=="STATS":
            lines = [
                f"connections={STATS['connections']}",
                f"logins={STATS['logins']}",
                f"uploads={STATS['uploads']}",
                f"downloads={STATS['downloads']}",
                f"deletes={STATS['deletes']}",
                f"renames={STATS['renames']}",
            ]
            self.sendLine("200-STATS START")
            for l in lines:
                self.sendLine(l)
            self.sendLine("200 STATS END")
            return
        if cmd=="SQLMAP":
            self.sendLine("200 SQLi simulation complete")
            return
        if cmd=="BOF":
            if len(rest)>1000:
                logging.warning("SIMUL BOF by %s len=%d", self.transport.getPeer().host, len(rest))
                self.sendLine("451 Buffer overflow!")
                return
            self.sendLine("200")
            return
        # Unknown SITE sub-command → syntax error
        return ftp.SYNTAX_ERR, params

    def ftp_PBSZ(self, param):
        """Handle RFC 4217 PBSZ command used by FTPS clients."""
        self.sendLine("200 PBSZ=0")
        return

    def ftp_PROT(self, param):
        """Acknowledge PROT command without altering connections."""
        level = (param or "").strip().upper()
        if level == "P":
            self.sendLine("200 Protection level set to Private")
        else:
            self.sendLine("200 Protection level ignored")
        return

    def getDTPPort(self, factory, interface=""):
        for portn in self.passivePortRange:
            try:
                return reactor.listenSSL(portn, factory,
                                         self.factory.ctx,
                                         interface=interface)
            except net_error.CannotListenError:
                continue
        raise net_error.CannotListenError("", portn,
                                      f"No port available in range {self.passivePortRange}")

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

    def __init__(self, portal, ctx):
        super().__init__(portal)
        self.ctx = ctx

class HoneyRealm(ftp.FTPRealm):
    def __init__(self, root: str):
        """Use a single virtual filesystem for all users."""
        # FTPRealm expects a plain path string. Passing a FilePath object
        # causes "TypeError: expected str, bytes or os.PathLike object" on
        # startup. Keep the original string here and let FTPRealm convert it.
        super().__init__(root)
        self._root = root

    def requestAvatar(self, avatarId, mind, *interfaces):
        for iface in interfaces:
            if iface is ftp.IFTPShell:
                user = (
                    "anonymous"
                    if avatarId is checkers.ANONYMOUS
                    else str(avatarId)
                )
                return iface, HoneyShell(user), lambda: None
        raise NotImplementedError("Only IFTPShell interface is supported")

# 10) Main
def main():
    for p in KNOCK_SEQ:
        reactor.listenUDP(p, KnockProtocol(p))
    logging.info("Waiting knock sequence %s to start FTP", KNOCK_SEQ)
    reactor.run()

if __name__=="__main__":
    main()
