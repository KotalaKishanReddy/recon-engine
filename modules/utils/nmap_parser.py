"""
nmap_parser.py
Parses nmap XML output into structured port/service data.

B-03 fix: interesting_ports() return type annotation corrected to List[Dict].
          This matches what active_recon.py stores and what scorer.py reads.
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

# Ports interesting from a bug bounty perspective
INTERESTING_PORT_MAP: Dict[int, dict] = {
    21:    {"label": "FTP",                     "risk": "medium"},
    22:    {"label": "SSH",                     "risk": "medium"},
    23:    {"label": "Telnet",                  "risk": "high"},
    25:    {"label": "SMTP",                    "risk": "medium"},
    3306:  {"label": "MySQL",                   "risk": "high"},
    5432:  {"label": "PostgreSQL",              "risk": "high"},
    6379:  {"label": "Redis",                   "risk": "high"},
    27017: {"label": "MongoDB",                 "risk": "high"},
    9200:  {"label": "Elasticsearch",           "risk": "high"},
    5601:  {"label": "Kibana",                  "risk": "high"},
    8080:  {"label": "HTTP-Alt",                "risk": "medium"},
    8443:  {"label": "HTTPS-Alt",               "risk": "medium"},
    8888:  {"label": "Jupyter",                 "risk": "high"},
    9090:  {"label": "Prometheus",              "risk": "medium"},
    3000:  {"label": "Grafana/Node",            "risk": "medium"},
    4848:  {"label": "Glassfish Admin",         "risk": "high"},
    7001:  {"label": "WebLogic",                "risk": "high"},
    8161:  {"label": "ActiveMQ",                "risk": "high"},
    9000:  {"label": "SonarQube/PHP-FPM",       "risk": "medium"},
    11211: {"label": "Memcached",               "risk": "high"},
    2375:  {"label": "Docker API (unencrypted)","risk": "high"},
    2376:  {"label": "Docker API (TLS)",        "risk": "medium"},
    4243:  {"label": "Docker Alt",              "risk": "high"},
    9092:  {"label": "Kafka",                   "risk": "medium"},
    2181:  {"label": "Zookeeper",               "risk": "medium"},
    5984:  {"label": "CouchDB",                 "risk": "high"},
    7474:  {"label": "Neo4j",                   "risk": "medium"},
}


def parse_nmap_xml(xml_path: str) -> Dict[str, List[Dict]]:
    """
    Returns {ip: [{port, protocol, state, service, product, version}]}
    Only includes open ports.
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
    B-03 fix: return type is List[Dict] — consistent with what active_recon.py
    stores in nmap_info['interesting'] and scorer._nmap_to_findings() reads.

    Returns flat list of {ip, port, label, service, version, risk} for each
    open port that is considered interesting from a bug bounty perspective.
    """
    flagged: List[Dict] = []
    for ip, ports in parsed.items():
        for p in ports:
            pnum = p["port"]
            if pnum in INTERESTING_PORT_MAP:
                meta = INTERESTING_PORT_MAP[pnum]
                flagged.append({
                    "ip":      ip,
                    "port":    pnum,
                    "label":   meta["label"],
                    "service": p["service"],
                    "version": p["version"],
                    "risk":    meta["risk"],
                })
    return flagged
