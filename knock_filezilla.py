#!/usr/bin/env python3
"""Send the UDP port-knock sequence then launch FileZilla."""
import argparse
import socket
import subprocess
import time

KNOCK_PORTS = (4020, 4021, 4022)


def knock(host: str):
    for p in KNOCK_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (host, p))
        time.sleep(0.2)


def launch_filezilla(host: str, port: int, user: str, password: str):
    url = f"ftps://{user}:{password}@{host}:{port}"
    try:
        subprocess.Popen(["filezilla", url])
    except FileNotFoundError:
        print("FileZilla not found. Please install it or adjust PATH.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Port knock then open FileZilla")
    parser.add_argument("host", help="Honeypot IP or hostname")
    parser.add_argument("port", type=int, nargs="?", default=2121, help="FTP port")
    parser.add_argument("user", nargs="?", default="anonymous", help="Username")
    parser.add_argument("password", nargs="?", default="", help="Password")
    args = parser.parse_args()

    knock(args.host)
    time.sleep(1)
    launch_filezilla(args.host, args.port, args.user, args.password)


if __name__ == "__main__":
    main()
