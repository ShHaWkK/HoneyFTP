#!/usr/bin/env python3
import ssl
from ftplib import FTP_TLS

HOST = "HOST"  # changez selon l'IP de votre honeypot
PORT = 2121

def connect_and_list(user, passwd):
    ctx = ssl._create_unverified_context()
    ftps = FTP_TLS(context=ctx)
    ftps.connect(HOST, PORT)
    ftps.login(user, passwd)
    ftps.prot_p()
    print(f"[+] Logged in as {user!r}")
    files = ftps.nlst()
    print("    Files:", files)
    ftps.quit()
    return files

def download_file(user, passwd, filename):
    ctx = ssl._create_unverified_context()
    ftps = FTP_TLS(context=ctx)
    ftps.connect(HOST, PORT)
    ftps.login(user, passwd)
    ftps.prot_p()
    local = f"{user}_{filename}"
    with open(local, "wb") as f:
        ftps.retrbinary(f"RETR {filename}", f.write)
    ftps.quit()
    print(f"[+] Downloaded {filename!r} to {local}")

def main():
    for user, pw in [("anonymous", ""), ("attacker", "secret")]:
        try:
            files = connect_and_list(user, pw)
            if "passwords.txt" in files:
                download_file(user, pw, "passwords.txt")
        except Exception as e:
            print(f"[-] {user!r} failed: {e}")

if __name__ == "__main__":
    main()
