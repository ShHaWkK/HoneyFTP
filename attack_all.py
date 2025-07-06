#!/usr/bin/env python3
"""Execute nearly all FTP commands against HoneyFTP.

This script automatically performs a wide range of commands to
validate that the honeypot responds correctly. It acts as a
non‑interactive version of ``attacker_shell.py``.
"""

import ssl
import socket
import time
import argparse
from ftplib import FTP_TLS
from pathlib import Path

KNOCK_SEQ = [4020, 4021, 4022]


def knock(host: str) -> None:
    for p in KNOCK_SEQ:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"", (host, p))
        s.close()


def connect_ftps(host: str, port: int) -> FTP_TLS:
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection((host, port), timeout=10)
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ftp = FTP_TLS(context=ctx)
    ftp.sock = ss
    ftp.file = ss.makefile("r", encoding="utf-8", newline="\r\n")
    ftp.af = ss.family
    ftp.host = host
    ftp.passiveserver = True
    print("<", ftp.getresp())
    return ftp


def main(host: str = "127.0.0.1", port: int = 2121) -> None:
    print(f"Knocking {host}…")
    knock(host)
    time.sleep(1)
    ftp = connect_ftps(host, port)
    ftp.login("anonymous", "")
    ftp.prot_p()
    print("Logged in as anonymous")

    print("PWD", ftp.pwd())
    print("NLST", ftp.nlst())

    print("Creating dir")
    try:
        print(ftp.mkd("test_dir"))
    except Exception as e:
        print("MKD fail", e)

    print("Uploading file")
    tmp = Path("attack_temp.txt")
    tmp.write_text("attack")
    with tmp.open("rb") as f:
        ftp.storbinary("STOR attack.txt", f)

    print("Listing after upload", ftp.nlst())
    print("SIZE attack.txt", ftp.size("attack.txt"))
    print("STAT .", ftp.sendcmd("STAT ."))

    print("Renaming and deleting")
    try:
        ftp.rename("attack.txt", "attack2.txt")
        ftp.delete("attack2.txt")
    except Exception as e:
        print("Rename/delete fail", e)

    print("Downloading root.txt")
    buf = bytearray()
    ftp.retrbinary("RETR root.txt", buf.extend)
    text = buf.decode("utf-8", errors="ignore")
    print("CAT root.txt:\n", text)
    if "Bienvenue" in text:
        print("GREP Bienvenue -> found")

    print("Removing dir")
    try:
        print(ftp.rmd("test_dir"))
    except Exception as e:
        print("RMD fail", e)

    print("SITE commands")
    for cmd in ["HELP", "VERSION", "UPTIME", "STATS", "GETLOG"]:
        try:
            resp = ftp.sendcmd(f"SITE {cmd}")
        except Exception as e:
            resp = f"error: {e}"
        print(cmd, resp)

    ftp.quit()
    tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=2121)
    args = ap.parse_args()
    main(args.host, args.port)
