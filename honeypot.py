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
import json, zipfile, atexit, base64, threading
from cmd import Cmd
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
    ("rich", None),
    ("Pillow", "PIL"),
    ("openpyxl", None),
    ("fpdf2", "fpdf"),
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
PID_FILE = os.path.join(BASE, "honeypot.pid")
VERSION  = "1.1"
SERVER_START = datetime.now(timezone.utc)
for d in (ROOT_DIR, QUAR_DIR, SESS_DIR):
    os.makedirs(d, exist_ok=True)

def _cleanup_pid():
    try:
        os.remove(PID_FILE)
    except OSError:
        pass

atexit.register(_cleanup_pid)

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
def create_lure_files():
    from PIL import Image
    from openpyxl import Workbook
    from fpdf import FPDF
    import io

    files = {
        "passwords.txt": b"admin:admin",
        "secrets/ssh_key": b"FAKE_SSH_KEY",
        "docs/readme.txt": b"Welcome to the FTP server",
        "web/index.html": b"<html><body>Welcome</body></html>",
        "logs/syslog": b"system boot\n",
        # Liste d'employés plus complète pour rendre le leurre crédible
        "hr/employes.csv": (
            "id,name,email,dept,title,phone,hire_date\n"
            "1,Alice Smith,alice.smith@example.com,Finance,CFO,+1-555-0100,2018-01-12\n"
            "2,Bob Jones,bob.jones@example.com,IT,System Administrator,+1-555-0101,2019-03-07\n"
            "3,Charlie Ray,charlie.ray@example.com,HR,HR Manager,+1-555-0102,2017-06-21\n"
            "4,Diana Prince,diana.prince@example.com,Marketing,Lead,+1-555-0103,2020-09-30\n"
            "5,Eric Yuan,eric.yuan@example.com,Engineering,Developer,+1-555-0104,2016-11-11\n"
            "6,Francis Bean,francis.bean@example.com,Sales,Account Exec,+1-555-0105,2021-05-19\n"
            "7,Gwen Stark,gwen.stark@example.com,Support,Technician,+1-555-0106,2015-02-14\n"
            "8,Hugh Grant,hugh.grant@example.com,Finance,Accountant,+1-555-0107,2018-12-01\n"
            "9,Ivy Chen,ivy.chen@example.com,IT,DevOps,+1-555-0108,2019-07-23\n"
            "10,John Doe,john.doe@example.com,Management,CEO,+1-555-0109,2014-04-04\n"
        ).encode("utf-8"),
        "docs/README.md": b"Internal documentation\n",
        # Les identifiants incluent l'adresse du serveur SSH leurre
        "credentials.json": (
            "{\n"
            "  \"user\": \"admin\",\n"
            "  \"pass\": \"secret\",\n"
            "  \"server\": \"SSH 192.168.100.51:2224\"\n"
            "}"
        ).encode("utf-8"),
    }

    buf = io.BytesIO()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.cell(40, 10, "Manual")
    pdf.output(buf)
    files["docs/manual.pdf"] = buf.getvalue()

    buf = io.BytesIO()
    Image.new("RGB", (1, 1), (255, 0, 0)).save(buf, format="JPEG")
    files["images/photo.jpg"] = buf.getvalue()

    buf = io.BytesIO()
    Image.new("RGB", (1, 1), (0, 255, 0)).save(buf, format="PNG")
    files["public/images/confidentiel.png"] = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("logs.txt", "log")
    files["backups/backup.zip"] = buf.getvalue()
    files["backups/logs_2025-07-04.zip"] = buf.getvalue()

    wb = Workbook()
    ws = wb.active
    ws.append(["ID", "Value"])
    ws.append([1, 100])
    buf = io.BytesIO()
    wb.save(buf)
    files["finance/Q3_Report.xlsx"] = buf.getvalue()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    files["it/ssh_keys/id_rsa"] = priv
    files["aws_keys.pem"] = priv

    files["uploads/.keep"] = b""

    for rel, data in files.items():
        fp = os.path.join(ROOT_DIR, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        if not os.path.exists(fp):
            mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
            with open(fp, mode) as f:
                f.write(data)

create_lure_files()

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
    "ls": 0,
    "cd": 0,
}


class AdminShell(Cmd):
    """Simple administrative shell."""
    prompt = "hpot> "

    def do_sessions(self, arg):
        """List session IDs"""
        for p in os.listdir(SESS_DIR):
            if p.endswith('.log'):
                print(p.split('.')[0])

    def do_show(self, arg):
        """show <id> - display full log"""
        sid = arg.strip()
        if not sid:
            print("usage: show <id>")
            return
        fp = os.path.join(SESS_DIR, f"{sid}.log")
        if os.path.exists(fp):
            with open(fp) as f:
                for line in f:
                    print(line.rstrip())
        else:
            print("session not found")

    def do_attacks(self, arg):
        """Show attack statistics"""
        print(json.dumps(STATS, indent=2))

    def do_quit(self, arg):
        return True

# Limite maximale d'espace disque pour le faux filesystem (env HONEYFTP_QUOTA_MB)
QUOTA_BYTES = int(os.getenv("HONEYFTP_QUOTA_MB", "10")) * 1024 * 1024

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
CANARY     = {
    "passwords.txt",
    "secrets/ssh_key",
    "credentials.json",
    "aws_keys.pem",
}
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

def validate_path(rel: str, cwd=None):
    """Validate a client-supplied path taking the current directory into account."""
    try:
        segs = ftp.toSegments(cwd or [], rel)
    except Exception:
        raise ValueError("Invalid path")
    abs_path = os.path.abspath(os.path.join(ROOT_DIR, *segs))
    if not abs_path.startswith(os.path.abspath(ROOT_DIR)):
        raise ValueError("Invalid path")
    return abs_path, "/".join(segs)

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

def finalize_session(sess: str, start: datetime, dls=0, ups=0, cds=0, rns=0):
    """Archive logs and stats for a session"""
    end = datetime.now(timezone.utc)
    stats_path = os.path.join(SESS_DIR, f"stats_{sess}.json")
    data = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "downloads": dls,
        "uploads": ups,
        "cd": cds,
        "rename": rns,
    }
    try:
        with open(stats_path, "w") as f:
            json.dump(data, f)
        zpath = os.path.join(SESS_DIR, f"session_{sess}.zip")
        with zipfile.ZipFile(zpath, "w") as z:
            z.write(stats_path, os.path.basename(stats_path))
            slog = os.path.join(SESS_DIR, f"{sess}.log")
            if os.path.exists(slog):
                z.write(slog, "session.log")
        alert(f"Session {sess} archived")
    except Exception:
        pass

# Port-knocking logic
ftp_started = False
knock_state = {}


class AcceptAllChecker:
    """Checker accepting any username/password and returning the username."""
    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, creds):
        return defer.succeed(creds.username)
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
    # Accept any credentials so we can observe attempts
    p.registerChecker(AcceptAllChecker())
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
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass

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
        return super().openForReading(path)

    def ftp_CWD(self, path):
        if path.startswith(".."):
            self.logf.write(f"CWD {path}\n")
            log_operation(f"CWD {path} by {self.avatarId}")
            STATS["cd"] += 1
            self.protocol.s_cd += 1 if hasattr(self, 'protocol') else 0
            return ftp.REQ_FILE_ACTN_COMPLETED_OK,
        log_operation(f"CWD {path} by {self.avatarId}")
        STATS["cd"] += 1
        self.protocol.s_cd += 1 if hasattr(self, 'protocol') else 0
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
        self.s_downloads = 0
        self.s_uploads = 0
        self.s_cd = 0
        self.s_ren = 0
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
        finalize_session(
            self.session,
            self.start,
            self.s_downloads,
            self.s_uploads,
            self.s_cd,
            self.s_ren,
        )
        super().connectionLost(reason)

    def ftp_USER(self, u):
        peer = self.transport.getPeer().host
        self.username = u
        logging.info("USER %s %s", peer, u)
        self.logf.write(f"USER {u}\n")
        return super().ftp_USER(u)

    def ftp_PASS(self, pw):
        peer = self.transport.getPeer().host
        attempts = failed_attempts.get(peer, 0)
        if attempts >= BRUTEF_THR:
            delay = DELAY_SEC * (2 ** (attempts - BRUTEF_THR))
            d = defer.Deferred()
            reactor.callLater(
                delay,
                d.callback,
                (ftp.RESPONSE[ftp.AUTH_FAILURE][0],),
            )
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
            old, rel = validate_path(fn, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        self._old = rel
        logging.info("RNFR %s %s", peer, rel)
        with open(os.path.join(SESS_DIR, f"{self.session}.rename.log"), "a") as rl:
            rl.write(f"RNFR {rel}\n")
        log_operation(f"RNFR {old} from {peer} session={self.session}")
        self.sendLine("350 Ready for RNTO")
        return

    def ftp_RNTO(self, new):
        peer = self.transport.getPeer().host
        old_rel = getattr(self, "_old", None)
        try:
            new_path, new_rel = validate_path(new, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
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
            self.s_ren += 1
            self.sendLine("250 Rename done")
            return
        except Exception as e:
            self.sendLine(f"550 Rename failed: {e}")
            return

    def ftp_DELE(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path, rel = validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
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
            validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        res = ftp.FTP.ftp_MKD(self, path)
        log_operation(f"MKD {path} session={self.session}")
        return res

    def ftp_RMD(self, path):
        try:
            validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        res = ftp.FTP.ftp_RMD(self, path)
        log_operation(f"RMD {path} session={self.session}")
        return res

    def ftp_RETR(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path, rel = validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        if rel in CANARY:
            alert(f"CANARY RETR {rel} by {peer}")
        if rel == getattr(self, "token", None):
            logging.info("HONEYTOKEN DL %s session=%s", rel, self.session)
            alert(f"HONEYTOKEN {rel} from {peer}")
        self.logf.write(f"RETR {rel}\n")
        log_operation(f"RETR {rel} by {peer} session={self.session}")
        STATS["downloads"] += 1
        self.s_downloads += 1
        return super().ftp_RETR(path)

    def ftp_STOR(self, path):
        peer = self.transport.getPeer().host
        try:
            abs_path, rel = validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        if disk_usage(ROOT_DIR) >= QUOTA_BYTES:
            self.sendLine("552 Quota exceeded")
            return
        self.logf.write(f"STOR {rel}\n")
        log_operation(f"STOR {rel} by {peer} session={self.session}")
        STATS["uploads"] += 1
        self.s_uploads += 1
        return super().ftp_STOR(path)

    def ftp_NLST(self, path):
        peer = self.transport.getPeer().host
        p = path or self.workingDirectory
        try:
            _, rel = validate_path(p, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        self.logf.write(f"NLST {rel}\n")
        log_operation(f"NLST {rel} by {peer} session={self.session}")
        STATS["ls"] += 1
        if "etc" in rel:
            etc = os.path.join(ROOT_DIR, "etc")
            os.makedirs(etc, exist_ok=True)
            with open(os.path.join(etc, "passwd"), "w") as f:
                f.write("root:x:0:0:root:/root:/bin/bash\n")
            with open(os.path.join(etc, "shadow"), "w") as f:
                f.write("root:*:18133:0:99999:7:::\n")
        if "var/log" in rel:
            d = os.path.join(ROOT_DIR, "var/log")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "syslog.1"), "w") as f:
                f.write("Jan 1 info fake\n")
        return super().ftp_NLST(path)

    def ftp_STAT(self, path):
        peer = self.transport.getPeer().host
        try:
            _, rel = validate_path(path, self.workingDirectory)
        except ValueError:
            self.sendLine("550 Invalid path")
            return
        if rel in CANARY:
            alert(f"CANARY STAT {rel} by {peer}")
        self.logf.write(f"STAT {rel}\n")
        log_operation(f"STAT {rel} by {peer} session={self.session}")
        return super().ftp_STAT(path)

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
            reactor.callLater(random.uniform(2,5), lambda:None)
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
def _run_reactor():
    for p in KNOCK_SEQ:
        reactor.listenUDP(p, KnockProtocol(p))
    logging.info("Waiting knock sequence %s to start FTP", KNOCK_SEQ)
    reactor.run(installSignalHandlers=False)


def main():
    threading.Thread(target=_run_reactor, daemon=True).start()
    AdminShell().cmdloop()

if __name__=="__main__":
    main()
