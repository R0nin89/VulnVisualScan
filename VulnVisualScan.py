# coding=utf-8

"""
VulnVisualScan - Herramienta para visualizar los resultados de un escaneo Nmap

Creador: Ruben Haro
Nick: R0nin89
"""

import re
import sys
from termcolor import colored

# Verificar si se proporciona el nombre del archivo
if len(sys.argv) < 2:
    print("Uso: python3 fichero.py <fichero.txt>")
    sys.exit()

filename = sys.argv[1]

try:
    with open(filename, "r") as file:
        data = file.readlines()
except FileNotFoundError:
    print(f"No se encontró el archivo: {filename}")
    sys.exit()

ip, mac, host, os, ports_info = "", "", "", "", []
port_info, additional_info = {}, []
capture_additional = False

for line in data:
    if "Nmap scan report for" in line:
        ip = re.search(r"for (\d+\.\d+\.\d+\.\d+)", line).group(1)

    elif "MAC Address" in line:
        mac = re.search(r"MAC Address: ([\dA-Fa-f:]+)", line).group(1)

    elif "Service Info:" in line:
        service_info = re.search(r"Hosts: ([^;]+); OS: ([^;]+);", line)
        if service_info:
            host, os = service_info.groups()

    elif "/tcp" in line and "open" in line:
        if port_info:
            port_info['additional'] = additional_info
            ports_info.append(port_info)
            port_info, additional_info = {}, []

        match = re.search(r"(\d+/tcp)\s+open\s+(.*?)\s+(.*)", line)
        if match:
            port, service, version = match.groups()
            port_info = {'port': port, 'service': service, 'version': version.strip()}
            capture_additional = True

    elif capture_additional and "|" in line:
        additional_info.append(line.strip())

if port_info:
    port_info['additional'] = additional_info
    ports_info.append(port_info)

# Imprimir la información
print(colored("[+] IP Servidor:", "white"), colored(ip, "green"))
print(colored("[+] Mac Address:", "white"), colored(mac, "green"))
print(colored("[+] Host:", "white"), colored(host, "green"))
print(colored("[+] Sistema Operativo:", "white"), colored(os, "green"))

for info in ports_info:
    print("")
    print(colored("    [!] puerto:", "white"), colored(info['port'], "red"))
    print(colored("        [+] servicio:", "white"), colored(info['service'], "yellow"))
    print(colored("        [+] Version:", "white"), colored(info['version'], "cyan"))
    print(colored("        [+] Información adicional:", "white"))

    for additional in info['additional']:
        key = additional.strip().split(':', 1)[0] + ':'
        value = additional.strip().split(':', 1)[1] if ':' in additional else ''
        print(colored(f"            [*] {key}", "white"), colored(value, "blue"))
