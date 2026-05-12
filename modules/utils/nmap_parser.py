"""
nmap_parser.py
Parses nmap XML output into structured port/service data.

Fix applied (audit 2026-05-12):
  B-03: interesting_ports() signature clarified to accept
        Dict[str, List[Dict]] and return List[Dict] consistently.
        active_recon.py stores the List directly under nmap['interesting'].
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List


def parse_nmap_xml(xml_path: str) -> Dict[str, List[Dict]]:
    """
    Returns {ip: [{port, protocol, state, service, product, version}]}
    """
    results: Dict[str, List[Dict]] = {}
    p = Path(xml_path)
    if not p.exists():
        return results
    try:
        tree = ET.parse(str(p))
        root = tree.getroot()
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            ports_data: List[Dict] = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state_el   = port.find("state")
                    service_el = port.find("service")
                    if state_el is not None and state_el.get("state") == "open":
                        ports_data.append({
                            "port":     int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                            "service":  service_el.get("name", "")    if service_el is not None else "",
                            "product":  service_el.get("product", "") if service_el is not None else "",
                            "version":  service_el.get("version", "") if service_el is not None else "",
                        })
            if ports_data:
                results[ip] = ports_data
    except ET.ParseError:
        pass
    return results


def interesting_ports(parsed: Dict[str, List[Dict]]) -> List[Dict]:
    """
    B-03 fix: explicitly typed as Dict[str, List[Dict]] -> List[Dict].
    Returns a flat list of flagged port dicts — one entry per interesting
    open port. active_recon.py stores this directly under nmap['interesting']
    so scorer._nmap_to_findings() can iterate it with no shape ambiguity.
    """
    INTERESTING = {
        21:    "FTP",
        22:    "SSH",
        23:    "Telnet",
        25:    "SMTP",
        3306:  "MySQL",
        5432:  "PostgreSQL",
        6379:  "Redis",
        27017: "MongoDB",
        9200:  "Elasticsearch",
        5601:  "Kibana",
        8080:  "HTTP-Alt",
        8443:  "HTTPS-Alt",
        8888:  "Jupyter",
        9090:  "Prometheus",
        3000:  "Grafana/Node",
        4848:  "Glassfish",
        7001:  "WebLogic",
        8161:  "ActiveMQ",
        9000:  "SonarQube/PHP-FPM",
        11211: "Memcached",
        2375:  "Docker API (unencrypted)",
    }
    HIGH_RISK = {6379, 27017, 9200, 2375, 11211, 23, 7001, 4848}
    flagged: List[Dict] = []
    for ip, ports in parsed.items():
        for p in ports:
            pnum = p["port"]
            if pnum in INTERESTING:
                flagged.append({
                    "ip":      ip,
                    "port":    pnum,
                    "label":   INTERESTING[pnum],
                    "service": p["service"],
                    "version": p["version"],
                    "risk":    "high" if pnum in HIGH_RISK else "medium",
                })
    return flagged
