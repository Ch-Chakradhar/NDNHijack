import os.path
import socket
import subprocess
import sys
from pathlib import Path
from time import sleep


def get_private_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def print_server_ip():
    ip = get_private_ip()
    print(f"Server IP address: {ip}")
    return ip


if __name__ == "__main__":
    http_prefix = "http-test"
    if len(sys.argv) != 2:
        print("Usage: python3 setup.py [server | client]")
        sys.exit(1)
    cwd = Path.cwd()
    if sys.argv[1] == "server":
        cert_file_path = cwd / "defaults" / f"{http_prefix}.cert"
        if not cert_file_path.is_file():
            try:
                with open(cert_file_path, "w") as cert_file:
                    subprocess.run(
                        ["ndnsec", "key-gen", f"/{http_prefix}"],
                        stdout=cert_file,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=True,
                    )
                print(f"Copy cert file from {cert_file_path} to client machine")
            except Exception as e:
                if cert_file_path.exists():
                    cert_file_path.unlink()
                raise Exception(f"Failed NDN Key gen: {e}")

        if not os.path.exists("/run/nfd/nfd.sock"):
            process = subprocess.Popen(
                ["nfd"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # Keeps NFD running even if this script exits
            )
            print(f"NFD process initiated with PID: {process.pid}")
        subprocess.run(["make", "Server/server"], check=True)
        print_server_ip()
    elif sys.argv[1] == "client":
        if not os.path.exists("/run/nfd/nfd.sock"):
            process = subprocess.Popen(
                ["nfd"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            print(f"NFD process initiated with PID: {process.pid}")
            sleep(2)
        res: str = subprocess.run(
            ["nfdc", "route", "list"], check=True, capture_output=True, text=True
        ).stdout
        if f"prefix:/{http_prefix}" not in res:
            server_ip = input(
                f"Route for /{http_prefix} not found. Enter server IP: "
            ).strip()
            if server_ip:
                subprocess.run(
                    [
                        "nfdc",
                        "route",
                        "add",
                        f"/{http_prefix}",
                        f"udp4://{server_ip}:6363",
                    ],
                    check=True,
                )
        subprocess.run(["make", "hijack.so"], check=True)

    else:
        raise Exception(f"Unknown Option {sys.argv[1]} - 'server' or 'client' expected")
