import subprocess
import socket
import requests
import re

#General Devices used
mac_to_user = {
    "Apple": "Apple Device",
    "Samsung": "Samsung Device",
    "TP-Link": "TP-Link Device",
    "Espressif": "IoT Device (ESP)",
    "Intel": "Intel-based Device",
    "Microsoft": "Windows Device",
    "Huawei": "Huawei Device",
    "Amazon": "Amazon Echo/Device",
}

#Try to catch NETbios
def try_netbios(ip):
    try:
        output = subprocess.check_output(
            ["nmap", "-sU", "-p", "137", "--script", "nbstat", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        match = re.search(r"NetBIOS Name:\s+([^\s]+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1) as sock:
            sock.sendall(b"\r\n")
            return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return None

def grab_http_server_header(ip):
    try:
        resp = requests.get(f"http://{ip}", timeout=1)
        return resp.headers.get("Server") or resp.text[:100]
    except:
        return None

#Use before functions to catch USER
def user_identifier(device):
    ip = device["ip"]
    mac_addr = device["mac"]
    vendor = device["vendor"]
    os_info = device["os"]

    netbios_user = try_netbios(ip)
    if netbios_user:
        return netbios_user

    hostname = reverse_dns(ip)
    if hostname and "localhost" not in hostname.lower():
        return hostname

    for key in mac_to_user:
        if key.lower() in vendor.lower():
            return mac_to_user[key]

    banner = grab_banner(ip, 22)
    if banner:
        return banner

    server_header = grab_http_server_header(ip)
    if server_header:
        return server_header

    return "Unknown"
