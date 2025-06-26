#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-Interaction FTP Honeypot

– Bootstrap des dépendances (Twisted, requests, service-identity, pin crypto<39 sous Py3.7)  
– Génération auto d’un certificat TLS PEM (server.key/server.crt)  
– FTPS implicite (SSL4ServerEndpoint)  
– Authent FTP anonyme + compte attacker/secret  
– Canary-files, honeytoken unique par session  
– FS dynamique (création/suppression aléatoire)  
– Quarantine des uploads + hash MD5/SHA256  
– Détection bruteforce + tarpitting adaptatif  
– Détection Tor exit-nodes  
– Commandes SITE personnalisées (EXEC/CHMOD/SHELL)  
– Logs par session + central  
"""

import os, sys, subprocess, shutil, uuid, hashlib, random, logging, smtplib
from datetime import datetime
import requests

# —————— BOOTSTRAP pip ——————
def ensure_installed(pkg, imp=None):
    name = imp or pkg
    try: __import__(name)
    except ImportError:
        print(f"[BOOTSTRAP] installation de {pkg}…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])

for pkg,imp in [
    ("twisted",           None),
    ("requests",          None),
    ("service-identity","service_identity"),
    ("cryptography<39",   None),
]:
    ensure_installed(pkg, imp)

# —————— CERTIFICAT auto-signé ——————
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_FILE, CERT_FILE = "server.key","server.crt"
if not (os.path.exists(KEY_FILE) and os.path.exists(CERT_FILE)):
    print("[BOOTSTRAP] génération d'un certificat auto-signé…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE,"wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    subj = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,           u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,          u"SF"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      u"Honeypot"),
        x509.NameAttribute(NameOID.COMMON_NAME,            u"localhost"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow()+datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),False)
            .sign(key,hashes.SHA256()))
    with open(CERT_FILE,"wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# —————— IMPORTS TWISTED & CONFIG ——————
import logging
from twisted.cred import portal, checkers
from twisted.cred.checkers import AllowAnonymousAccess
from twisted.internet import endpoints, reactor, ssl, defer
from twisted.protocols import ftp
from twisted.python import filepath

# Répertoires & constantes
ROOT_DIR       = "virtual_fs"
QUARANTINE_DIR = "quarantine"
SESSION_LOG    = "sessions"
LOG_FILE       = "honeypot.log"
TOR_EXIT_URL   = "https://check.torproject.org/torbulkexitlist"
BRUTEF_THR     = 5
DELAY_SEC      = 2
CANARY_FILES   = {"passwords.txt","secrets/ssh_key"}

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")
SMTP_CFG      = (os.environ.get("SMTP_SERVER"), int(os.environ.get("SMTP_PORT","0")) or 25,
                 os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS"),
                 os.environ.get("ALERT_FROM"), os.environ.get("ALERT_TO"))
LISTEN_PORT   = int(os.environ.get("HONEYFTP_PORT","2121"))

# —————— LOGGING & FS INIT ——————
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
os.makedirs(ROOT_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SESSION_LOG, exist_ok=True)

# Fichiers-leurres
for p,c in {
    "passwords.txt":"admin:admin",
    "secrets/ssh_key":"FAKE_SSH_KEY",
    "docs/readme.txt":"Welcome to the FTP server"
}.items():
    full=os.path.join(ROOT_DIR,p)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if not os.path.exists(full):
        with open(full,"w") as f: f.write(c)

failed_attempts = {}
DYNAMIC_ITEMS   = []

# —————— HELPERS ALERT & TOR ——————
def alert(msg):
    if SLACK_WEBHOOK:
        try: requests.post(SLACK_WEBHOOK,json={"text":msg},timeout=5)
        except: pass
    srv,port,user,pw,fr,to = SMTP_CFG
    if srv and fr and to:
        try:
            s=smtplib.SMTP(srv,port,timeout=5)
            if user: s.starttls(); s.login(user,pw or "")
            mail=f"Subject: HoneyFTP Alert\nFrom: {fr}\nTo: {to}\n\n{msg}"
            s.sendmail(fr,[to],mail); s.quit()
        except: pass

def is_tor_exit(ip):
    try:
        r=requests.get(TOR_EXIT_URL,timeout=5)
        return ip in r.text.splitlines()
    except: return False

def create_honeytoken(ip,session):
    fn=f"secret_{uuid.uuid4().hex}.txt"
    full=os.path.join(ROOT_DIR,fn)
    with open(full,"w") as f: f.write(f"session={session}\nip={ip}\n")
    return fn

def randomize_fs():
    # purge
    for p in DYNAMIC_ITEMS[:]:
        try:
            if os.path.isdir(p): shutil.rmtree(p)
            else: os.remove(p)
        except: pass
        DYNAMIC_ITEMS.remove(p)
    # nouvelle structure
    for _ in range(random.randint(1,3)):
        d=os.path.join(ROOT_DIR,f"dir_{uuid.uuid4().hex[:6]}")
        os.makedirs(d,exist_ok=True); DYNAMIC_ITEMS.append(d)
        for _ in range(random.randint(1,2)):
            f=os.path.join(d,f"file_{uuid.uuid4().hex[:6]}.txt")
            with open(f,"w") as x: x.write("dummy\n")
            DYNAMIC_ITEMS.append(f)

# —————— SHELL PERSONNALISÉ ——————
class HoneyShell(ftp.FTPShell):
    def __init__(self,aid):
        super().__init__(filepath.FilePath(ROOT_DIR))
        self.avatarId = aid
    def openForReading(self,path):
        rel="/".join(path)
        if rel in CANARY_FILES:
            alert(f"CANARY READ {rel} by {self.avatarId}")
        return super().openForReading(path)
    def openForWriting(self,path):
        p=self._path(path)
        if p.isdir(): return defer.fail(ftp.IsADirectoryError(path))
        try: real=p.open("wb")
        except OSError as e: return ftp.errnoToFailure(e.errno,path)
        sess=uuid.uuid4().hex
        qf=open(os.path.join(QUARANTINE_DIR,sess),"wb")
        md5,sha=hashlib.md5(),hashlib.sha256()
        class Tee:
            def registerProducer(self,*a): pass
            def unregisterProducer(self): real.close();qf.close()
            def write(self,data):
                real.write(data); qf.write(data)
                md5.update(data); sha.update(data)
        class W:
            def __init__(self): self.once=False
            def receive(self):
                if self.once: raise RuntimeError()
                self.once=True
                return defer.succeed(Tee())
            def close(self):
                real.close(); qf.close()
                logging.info("UPLOAD ip=%s file=%s md5=%s sha256=%s sess=%s",
                    self.avatarId, "/".join(path),
                    md5.hexdigest(), sha.hexdigest(), sess)
                if os.path.basename(path[-1]) in CANARY_FILES:
                    alert(f"CANARY UP {path[-1]} by {self.avatarId}")
                return defer.succeed(None)
        return defer.succeed(W())

# —————— PROTOCOLE FTP + DÉTECTION ——————
class HoneyFTP(ftp.FTP):
    def connectionMade(self):
        super().connectionMade()
        self.session_id=uuid.uuid4().hex
        self.start, self.count = datetime.utcnow(), 0
        peer=self.transport.getPeer().host
        self.session_log=open(os.path.join(SESSION_LOG,f"{self.session_id}.log"),"a")
        logging.info("CONNECT ip=%s session=%s",peer,self.session_id)
        if is_tor_exit(peer):
            alert(f"Tor exit node {peer}")
        self.honeytoken = create_honeytoken(peer,self.session_id)
    def connectionLost(self,reason):
        peer=getattr(self.transport.getPeer(),"host","?")
        logging.info("DISCONNECT ip=%s session=%s",peer,self.session_id)
        try: os.remove(os.path.join(ROOT_DIR,self.honeytoken))
        except: pass
        self.session_log.close()
        super().connectionLost(reason)
    def ftp_USER(self,u):
        peer=self.transport.getPeer().host
        logging.info("USER ip=%s user=%s",peer,u)
        self.session_log.write(f"USER {u}\n")
        return super().ftp_USER(u)
    def ftp_PASS(self,pw):
        peer=self.transport.getPeer().host
        if failed_attempts.get(peer,0)>=BRUTEF_THR:
            d=defer.Deferred()
            reactor.callLater(DELAY_SEC,d.callback,(ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d
        logging.info("PASS ip=%s user=%s pw=%s",peer,getattr(self,"username","?"),pw)
        self.session_log.write(f"PASS {pw}\n")
        d=super().ftp_PASS(pw)
        def onFail(e):
            failed_attempts[peer]=failed_attempts.get(peer,0)+1
            if failed_attempts[peer]>=BRUTEF_THR:
                alert(f"Bruteforce from {peer}")
            return e
        def onSucc(r):
            failed_attempts.pop(peer,None)
            randomize_fs()
            return r
        d.addCallbacks(onSucc,onFail)
        return d
    def ftp_RETR(self,path):
        rel=path.lstrip("/")
        if rel in CANARY_FILES:
            alert(f"CANARY RETR {rel} by {self.transport.getPeer().host}")
        if rel==self.honeytoken:
            logging.info("HONEYTOKEN DL %s session %s",rel,self.session_id)
        self.session_log.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)
    def ftp_SITE(self,p):
        cmd=p.strip().split()[0].upper()
        return {
            "EXEC": (ftp.CMD_OK,"EXEC disabled"),
            "CHMOD":(ftp.CMD_OK,"CHMOD ignored"),
            "SHELL":(ftp.CMD_OK,"SHELL unavailable")
        }.get(cmd,(ftp.SYNTAX_ERR,p))
    def lineReceived(self,line):
        ip=self.transport.getPeer().host
        cmd=line.decode("latin-1").strip()
        logging.info("CMD ip=%s cmd=%s",ip,cmd)
        self.session_log.write(cmd+"\n")
        self.count+=1
        if self.count>20 and (datetime.utcnow()-self.start).total_seconds()<10:
            alert(f"Fast scanner {ip}")
            reactor.callLater(random.uniform(1,3),lambda:None)
        return super().lineReceived(line)

class HoneyFTPFactory(ftp.FTPFactory):
    protocol = HoneyFTP
    welcomeMessage="(vsFTPd 2.3.4)"

# —————— REALM avec requestAvatar ——————
class HoneyRealm:
    def requestAvatar(self, avatarId, mind, *ifaces):
        if ftp.IFTPShell in ifaces:
            shell = HoneyShell(avatarId)
            return ftp.IFTPShell, shell, lambda: None
        raise NotImplementedError()

def main():
    p = portal.Portal(HoneyRealm())
    # compte spécifique
    p.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret"))
    # puis anonyme
    p.registerChecker(AllowAnonymousAccess())

    factory = HoneyFTPFactory(p)
    ctx = ssl.DefaultOpenSSLContextFactory(KEY_FILE, CERT_FILE)
    endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, ctx).listen(factory)
    logging.info("Honeypot listening on port %s", LISTEN_PORT)
    reactor.run()

if __name__=="__main__":
    main()
