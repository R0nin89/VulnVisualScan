#!/usr/bin/env python3
# coding=utf-8

"""
VulnVisualScan - Visualizador defensivo de resultados Nmap + CVE + NVD

Creador: Ruben Haro
Nick: R0nin89

Uso:
    python3 vulnvisualscan.py scan.xml
    python3 vulnvisualscan.py scan.xml --json reporte.json
    NVD_API_KEY=TU_API_KEY python3 vulnvisualscan.py scan.xml
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime


try:
    from termcolor import colored
except ImportError:
    def colored(text, color=None, attrs=None):
        return text


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


SEVERITY_COLORS = {
    "CRITICAL": "magenta",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "white",
    "N/A": "white",
}


def color_severity(severity):
    return colored(severity, SEVERITY_COLORS.get(severity, "white"))


def safe_get_attr(element, attr, default=""):
    if element is None:
        return default
    return element.attrib.get(attr, default)


def extract_cves(text):
    if not text:
        return []

    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    return sorted(set(cve.upper() for cve in cves))


def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
    except FileNotFoundError:
        print(colored(f"[!] No se encontró el archivo: {xml_file}", "red"))
        sys.exit(1)
    except ET.ParseError as error:
        print(colored(f"[!] XML inválido: {error}", "red"))
        sys.exit(1)

    root = tree.getroot()
    parsed_hosts = []

    for host in root.findall("host"):
        status = safe_get_attr(host.find("status"), "state", "unknown")

        addresses = host.findall("address")
        ip = ""
        mac = ""
        vendor = ""

        for address in addresses:
            addr_type = address.attrib.get("addrtype", "")
            if addr_type in ["ipv4", "ipv6"]:
                ip = address.attrib.get("addr", "")
            elif addr_type == "mac":
                mac = address.attrib.get("addr", "")
                vendor = address.attrib.get("vendor", "")

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_node = hostnames.find("hostname")
            hostname = safe_get_attr(hostname_node, "name", "")

        os_matches = []
        os_node = host.find("os")
        if os_node is not None:
            for osmatch in os_node.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.attrib.get("name", ""),
                    "accuracy": osmatch.attrib.get("accuracy", "")
                })

        ports = []
        ports_node = host.find("ports")

        if ports_node is not None:
            for port in ports_node.findall("port"):
                protocol = port.attrib.get("protocol", "")
                portid = port.attrib.get("portid", "")

                state_node = port.find("state")
                state = safe_get_attr(state_node, "state", "")

                if state != "open":
                    continue

                service_node = port.find("service")
                service_name = safe_get_attr(service_node, "name", "unknown")
                product = safe_get_attr(service_node, "product", "")
                version = safe_get_attr(service_node, "version", "")
                extrainfo = safe_get_attr(service_node, "extrainfo", "")
                ostype = safe_get_attr(service_node, "ostype", "")
                cpe_list = [cpe.text for cpe in service_node.findall("cpe")] if service_node is not None else []

                scripts = []
                cves = []

                for script in port.findall("script"):
                    script_id = script.attrib.get("id", "")
                    output = script.attrib.get("output", "")

                    script_cves = extract_cves(output)
                    cves.extend(script_cves)

                    scripts.append({
                        "id": script_id,
                        "output": output,
                        "cves": script_cves,
                    })

                ports.append({
                    "port": f"{portid}/{protocol}",
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "ostype": ostype,
                    "cpe": cpe_list,
                    "scripts": scripts,
                    "cves": sorted(set(cves)),
                })

        parsed_hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "status": status,
            "os_matches": os_matches,
            "ports": ports,
        })

    return parsed_hosts


def http_get_json(url, headers=None, timeout=20):
    request = urllib.request.Request(url, headers=headers or {})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as error:
        print(colored(f"[!] Error HTTP consultando NVD: {error.code} {error.reason}", "red"))
        return None
    except urllib.error.URLError as error:
        print(colored(f"[!] Error de conexión consultando NVD: {error.reason}", "red"))
        return None
    except json.JSONDecodeError:
        print(colored("[!] Respuesta inválida de NVD.", "red"))
        return None


def extract_cvss_metrics(cve_item):
    metrics = cve_item.get("metrics", {})

    preferred_keys = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for key in preferred_keys:
        values = metrics.get(key)
        if not values:
            continue

        metric = values[0]
        cvss_data = metric.get("cvssData", {})

        return {
            "version": cvss_data.get("version", "N/A"),
            "score": cvss_data.get("baseScore", "N/A"),
            "severity": cvss_data.get("baseSeverity", metric.get("baseSeverity", "N/A")),
            "vector": cvss_data.get("vectorString", "N/A"),
            "exploitability_score": metric.get("exploitabilityScore", "N/A"),
            "impact_score": metric.get("impactScore", "N/A"),
        }

    return {
        "version": "N/A",
        "score": "N/A",
        "severity": "UNKNOWN",
        "vector": "N/A",
        "exploitability_score": "N/A",
        "impact_score": "N/A",
    }


def extract_cwe(cve_item):
    weaknesses = cve_item.get("weaknesses", [])
    cwes = []

    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value:
                cwes.append(value)

    return sorted(set(cwes))


def extract_english_description(cve_item):
    descriptions = cve_item.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")

    if descriptions:
        return descriptions[0].get("value", "")

    return "N/A"


def get_nvd_cve(cve_id, cache, sleep_without_api_key=True):
    if cve_id in cache:
        return cache[cve_id]

    api_key = os.getenv("NVD_API_KEY", "").strip()

    params = urllib.parse.urlencode({
        "cveId": cve_id
    })

    url = f"{NVD_CVE_API}?{params}"

    headers = {
        "User-Agent": "VulnVisualScan/1.0 defensive-cve-lookup"
    }

    if api_key:
        headers["apiKey"] = api_key

    data = http_get_json(url, headers=headers)

    if sleep_without_api_key and not api_key:
        time.sleep(6)

    if not data or not data.get("vulnerabilities"):
        cache[cve_id] = {
            "id": cve_id,
            "found": False,
            "severity": "UNKNOWN",
            "score": "N/A",
            "description": "No encontrado en NVD.",
            "references": [],
            "cwe": [],
            "cvss": {},
        }
        return cache[cve_id]

    cve_data = data["vulnerabilities"][0].get("cve", {})
    cvss = extract_cvss_metrics(cve_data)

    references = []
    for ref in cve_data.get("references", {}).get("referenceData", []):
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        if url:
            references.append({
                "url": url,
                "tags": tags,
            })

    result = {
        "id": cve_id,
        "found": True,
        "severity": cvss.get("severity", "UNKNOWN"),
        "score": cvss.get("score", "N/A"),
        "description": extract_english_description(cve_data),
        "references": references[:8],
        "cwe": extract_cwe(cve_data),
        "cvss": cvss,
        "published": cve_data.get("published", "N/A"),
        "last_modified": cve_data.get("lastModified", "N/A"),
    }

    cache[cve_id] = result
    return result


def enrich_with_nvd(hosts):
    cache = {}

    for host in hosts:
        for port in host["ports"]:
            enriched = []
            for cve_id in port["cves"]:
                enriched.append(get_nvd_cve(cve_id, cache))
            port["cve_details"] = sorted(
                enriched,
                key=lambda x: float(x["score"]) if isinstance(x["score"], (int, float)) else -1,
                reverse=True
            )

    return hosts


def generate_defensive_exploitation_notes(cve):
    severity = cve.get("severity", "UNKNOWN")
    cvss = cve.get("cvss", {})
    vector = cvss.get("vector", "N/A")

    notes = []

    notes.append("Uso permitido: solo en laboratorio propio o con autorización escrita.")
    notes.append("Objetivo defensivo: confirmar exposición, estimar impacto y validar mitigación.")
    notes.append(f"Vector CVSS: {vector}")

    if severity in ["CRITICAL", "HIGH"]:
        notes.append("Prioridad: revisar parcheo, exposición a red y controles compensatorios inmediatamente.")
    elif severity == "MEDIUM":
        notes.append("Prioridad: validar si el servicio vulnerable está expuesto y si existe autenticación previa.")
    else:
        notes.append("Prioridad: revisar en ciclo normal de hardening.")

    notes.append("Verificación segura: comprobar versión del servicio, configuración vulnerable y referencias oficiales.")
    notes.append("No ejecutar exploits públicos en producción. Usar snapshot, VM aislada y logs activados.")

    return notes


def print_banner():
    print(colored(r"""
 __     __    _       __     ___                 _ ____                  
 \ \   / /   | |      \ \   / (_)               | / ___|  ___ __ _ _ __  
  \ \ / /   _| |_ __   \ \ / / _ ___ _   _  __ _| \___ \ / __/ _` | '_ \ 
   \ V / | | | | '_ \   \ V / | / __| | | |/ _` | |___) | (_| (_| | | | |
    \_/| |_| | | | | |   \_/  | \__ \ |_| | (_| | |____/ \___\__,_|_| |_|
        \__,_|_|_| |_|        |_|___/\__,_|\__,_|_|                      
""", "cyan"))


def print_report(hosts):
    print_banner()

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(colored(f"[+] Reporte generado: {generated_at}", "white"))

    for host in hosts:
        print("")
        print(colored("=" * 90, "cyan"))
        print(colored("[+] Host:", "white"), colored(host["hostname"] or "N/A", "green"))
        print(colored("[+] IP:", "white"), colored(host["ip"] or "N/A", "green"))
        print(colored("[+] MAC:", "white"), colored(host["mac"] or "N/A", "green"))
        print(colored("[+] Vendor:", "white"), colored(host["vendor"] or "N/A", "green"))
        print(colored("[+] Estado:", "white"), colored(host["status"], "green"))

        if host["os_matches"]:
            print(colored("[+] Sistemas operativos posibles:", "white"))
            for item in host["os_matches"][:3]:
                print(
                    colored("    [*]", "white"),
                    colored(item["name"], "cyan"),
                    colored(f"accuracy={item['accuracy']}%", "yellow")
                )
        else:
            print(colored("[+] Sistema operativo:", "white"), colored("N/A", "yellow"))

        if not host["ports"]:
            print(colored("[!] No hay puertos abiertos.", "yellow"))
            continue

        for port in host["ports"]:
            print("")
            print(colored("    [!] Puerto:", "white"), colored(port["port"], "red"))
            print(colored("        [+] Servicio:", "white"), colored(port["service"], "yellow"))

            version_string = " ".join(
                value for value in [port["product"], port["version"], port["extrainfo"]]
                if value
            )

            print(colored("        [+] Versión:", "white"), colored(version_string or "N/A", "cyan"))

            if port["cpe"]:
                print(colored("        [+] CPE:", "white"))
                for cpe in port["cpe"]:
                    print(colored("            [*]", "white"), colored(cpe, "blue"))

            if port["scripts"]:
                print(colored("        [+] Scripts NSE:", "white"))
                for script in port["scripts"]:
                    cves = ", ".join(script["cves"]) if script["cves"] else "sin CVE directo"
                    print(
                        colored(f"            [*] {script['id']}:", "white"),
                        colored(cves, "blue")
                    )

            if not port.get("cve_details"):
                print(colored("        [+] CVEs encontrados:", "white"), colored("N/A", "green"))
                continue

            print(colored("        [+] CVEs encontrados:", "white"))

            for cve in port["cve_details"]:
                severity = cve.get("severity", "UNKNOWN")
                score = cve.get("score", "N/A")

                print("")
                print(
                    colored("            [CVE]", "white"),
                    colored(cve["id"], "red"),
                    colored("CVSS:", "white"),
                    colored(str(score), "yellow"),
                    colored("Severidad:", "white"),
                    color_severity(severity)
                )

                print(colored("                Descripción:", "white"), colored(cve.get("description", "N/A"), "cyan"))

                if cve.get("cwe"):
                    print(colored("                CWE:", "white"), colored(", ".join(cve["cwe"]), "yellow"))

                if cve.get("published"):
                    print(colored("                Publicado:", "white"), colored(cve.get("published"), "blue"))

                if cve.get("last_modified"):
                    print(colored("                Modificado:", "white"), colored(cve.get("last_modified"), "blue"))

                print(colored("                Explotabilidad defensiva:", "white"))
                for note in generate_defensive_exploitation_notes(cve):
                    print(colored("                    -", "white"), colored(note, "blue"))

                if cve.get("references"):
                    print(colored("                Referencias:", "white"))
                    for ref in cve["references"][:5]:
                        tags = ", ".join(ref.get("tags", [])) if ref.get("tags") else "sin tags"
                        print(colored("                    -", "white"), colored(ref["url"], "blue"), colored(f"[{tags}]", "yellow"))


def save_json_report(hosts, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(hosts, file, indent=4, ensure_ascii=False)

    print(colored(f"\n[+] Reporte JSON guardado en: {output_file}", "green"))


def main():
    parser = argparse.ArgumentParser(
        description="Visualizador defensivo de Nmap XML con CVEs enriquecidos desde NVD."
    )

    parser.add_argument(
        "xml_file",
        help="Archivo XML generado con Nmap: -oX scan.xml"
    )

    parser.add_argument(
        "--no-nvd",
        action="store_true",
        help="No consultar NVD. Solo extraer CVEs del XML."
    )

    parser.add_argument(
        "--json",
        dest="json_output",
        help="Guardar reporte enriquecido en JSON."
    )

    args = parser.parse_args()

    hosts = parse_nmap_xml(args.xml_file)

    if not args.no_nvd:
        hosts = enrich_with_nvd(hosts)

    print_report(hosts)

    if args.json_output:
        save_json_report(hosts, args.json_output)


if __name__ == "__main__":
    main()
