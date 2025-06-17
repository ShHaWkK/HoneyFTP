# -*- coding: utf-8 -*-
"""Advanced FTP Honeypot.

This script implements a high-interaction FTP honeypot using Twisted. It
captures authentication attempts, logs commands, quarantines uploaded
files, and provides simple detection mechanisms for brute-force attacks
and known malicious IPs.
"""

import hashlib
import logging
import os
import uuid
from datetime import datetime
import smtplib
import json
import random

import requests
from twisted.cred import portal, checkers
from twisted.internet import endpoints, reactor, ssl
from twisted.protocols import ftp
from twisted.python import filepath

ROOT_DIR = "virtual_fs"
QUARANTINE_DIR = "quarantine"
SESSION_LOG_DIR = "sessions"
LOG_FILE = "honeypot.log"
TOR_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"
BRUTEFORCE_THRESHOLD = 5
DELAY_SECONDS = 2
CANARY_FILES = {"passwords.txt", "secrets/ssh_key"}

# Alert configuration via environment variables
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "0")) or None
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ALERT_FROM = os.environ.get("ALERT_FROM")
ALERT_TO = os.environ.get("ALERT_TO")
LISTEN_PORT = int(os.environ.get("HONEYFTP_PORT", "2121"))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)

# Initialize directories
os.makedirs(ROOT_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SESSION_LOG_DIR, exist_ok=True)

# Create basic lure files if they don't exist
lure_files = {
    "passwords.txt": "admin:admin",
    "secrets/ssh_key": "FAKE_SSH_KEY",
    "docs/readme.txt": "Welcome to the FTP server",
}
for rel_path, content in lure_files.items():
    full_path = os.path.join(ROOT_DIR, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    if not os.path.exists(full_path):
        with open(full_path, "w") as f:
            f.write(content)


failed_attempts = {}


def alert(message: str) -> None:
    """Send alert via Slack or SMTP if configured."""
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5)
        except Exception as exc:  # pragma: no cover - network might fail
            logging.warning("Slack alert failed: %s", exc)
    if SMTP_SERVER and ALERT_TO and ALERT_FROM:
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT or 25, timeout=5) as s:
                if SMTP_USER:
                    s.starttls()
                    s.login(SMTP_USER, SMTP_PASS or "")
                msg = f"Subject: HoneyFTP Alert\nFrom: {ALERT_FROM}\nTo: {ALERT_TO}\n\n{message}"
                s.sendmail(ALERT_FROM, [ALERT_TO], msg)
        except Exception as exc:  # pragma: no cover - network might fail
            logging.warning("SMTP alert failed: %s", exc)

def is_tor_exit(ip: str) -> bool:
    """Check whether an IP is listed as a Tor exit node."""
    try:
        resp = requests.get(TOR_EXIT_LIST, timeout=5)
        if resp.status_code == 200:
            return ip.strip() in resp.text.splitlines()
    except Exception as exc:  # pragma: no cover - network might fail
        logging.warning("Tor exit list check failed: %s", exc)
    return False


class HoneyShell(ftp.FileSystem):
    """Filesystem avatar used by the honeypot."""

    def __init__(self, avatar_id: str):
        super().__init__(avatar_id, ROOT_DIR)

    def openForReading(self, path):
        rel = os.path.relpath(path.path, ROOT_DIR)
        if rel in CANARY_FILES:
            alert(f"Canary file accessed: {rel} by {self.avatarId}")
        return super().openForReading(path)

    def storeFile(self, path, consumer, *args, **kwargs):
        data = consumer.read()
        session = uuid.uuid4().hex
        quarantine_path = os.path.join(QUARANTINE_DIR, session)
        with open(quarantine_path, "wb") as out:
            out.write(data)
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        logging.info(
            "UPLOAD ip=%s file=%s md5=%s sha256=%s session=%s",
            self.avatarId,
            path,
            md5,
            sha256,
            session,
        )
        if os.path.basename(path) in CANARY_FILES:
            alert(f"Canary upload {path} by {self.avatarId}")
        consumer = open(quarantine_path, "rb")
        return super().storeFile(path, consumer, *args, **kwargs)


class HoneyFTP(ftp.FTP):
    """FTP protocol with enhanced logging and detection."""

    def connectionMade(self):
        super().connectionMade()
        self.session_id = uuid.uuid4().hex
        peer_ip = self.transport.getPeer().host
        self.session_log_path = os.path.join(SESSION_LOG_DIR, f"{self.session_id}.log")
        self.session_log = open(self.session_log_path, "a")
        self.start_time = datetime.utcnow()
        self.command_count = 0
        logging.info("CONNECT ip=%s session=%s", peer_ip, self.session_id)
        if is_tor_exit(peer_ip):
            logging.info("TOR_EXIT ip=%s", peer_ip)
            alert(f"Connection from Tor exit node {peer_ip}")

    def connectionLost(self, reason):
        peer_ip = self.transport.getPeer().host if self.transport else "?"
        logging.info("DISCONNECT ip=%s session=%s", peer_ip, self.session_id)
        if hasattr(self, "session_log"):
            self.session_log.close()
        super().connectionLost(reason)

    def ftp_USER(self, username):
        self.username = username
        ip = self.transport.getPeer().host
        logging.info("USER ip=%s username=%s", ip, username)
        if hasattr(self, "session_log"):
            self.session_log.write(f"USER {username}\n")
        return super().ftp_USER(username)

    def ftp_PASS(self, password):
        ip = self.transport.getPeer().host
        if ip in failed_attempts and failed_attempts[ip] >= BRUTEFORCE_THRESHOLD:
            logging.info("BRUTEFORCE_BLOCK ip=%s", ip)
            d = ftp.defer.Deferred()
            reactor.callLater(DELAY_SECONDS, d.callback, (ftp.RESPONSE[ftp.AUTH_FAILED][0],))
            return d
        logging.info(
            "PASS ip=%s username=%s password=%s", ip, getattr(self, "username", "?"), password
        )
        if hasattr(self, "session_log"):
            self.session_log.write(f"PASS {password}\n")
        d = super().ftp_PASS(password)

        def _failed(err):
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            logging.info("LOGIN_FAIL ip=%s failures=%s", ip, failed_attempts[ip])
            if hasattr(self, "session_log"):
                self.session_log.write("LOGIN_FAIL\n")
            if failed_attempts[ip] >= BRUTEFORCE_THRESHOLD:
                alert(f"Bruteforce detected from {ip}")
            return err

        def _success(res):
            failed_attempts.pop(ip, None)
            logging.info("LOGIN_SUCCESS ip=%s", ip)
            if hasattr(self, "session_log"):
                self.session_log.write("LOGIN_SUCCESS\n")
            return res

        d.addCallbacks(_success, _failed)
        return d

    def ftp_RETR(self, path):
        rel = path.lstrip("/")
        if rel in CANARY_FILES:
            ip = self.transport.getPeer().host
            alert(f"Sensitive file {rel} downloaded by {ip}")
        if hasattr(self, "session_log"):
            self.session_log.write(f"RETR {rel}\n")
        return super().ftp_RETR(path)

    def lineReceived(self, line):
        ip = self.transport.getPeer().host
        cmd = line.decode("latin-1")
        logging.info("CMD ip=%s line=%s", ip, cmd)
        if hasattr(self, "session_log"):
            self.session_log.write(cmd + "\n")
        self.command_count += 1
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        if self.command_count > 20 and elapsed < 10:
            alert(f"Fast scanner detected from {ip}")
            reactor.callLater(random.uniform(1, 3), lambda: None)
        return super().lineReceived(line)


class HoneyFTPFactory(ftp.FTPFactory):
    protocol = HoneyFTP


class HoneyRealm(ftp.FTPRealm):
    def avatarForAnonymousUser(self):
        return HoneyShell("anonymous")

    def avatarForUsername(self, username):
        return HoneyShell(username)


def main():
    realm = HoneyRealm(ROOT_DIR)
    port = portal.Portal(realm)
    checker = checkers.InMemoryUsernamePasswordDatabaseDontUse(attacker="secret")
    port.registerChecker(checker)
    factory = HoneyFTPFactory(port)

    context = ssl.DefaultOpenSSLContextFactory("server.key", "server.crt")
    endpoint = endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, context)
    endpoint.listen(factory)
    logging.info("Honeypot listening on port %s", LISTEN_PORT)
    reactor.run()


if __name__ == "__main__":
    main()
