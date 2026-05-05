#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from pyzabbix import ZabbixAPI

ZABBIX_URL = "http://127.0.0.1/zabbix"
ZABBIX_USER = "Admin"
ZABBIX_PASSWORD = "zabbix"

MAP_NAME = "Auto Network Map"
MAP_WIDTH = 1200
MAP_HEIGHT = 800
CREATE_MAP_IF_MISSING = True

SNMP_VERSION = "2c"
SNMP_TIMEOUT = "2"
SNMP_RETRIES = "1"

DEVICES = [
    {"name": "switch-1", "ip": "10.10.10.10", "community": "public"},
    {"name": "switch-2", "ip": "10.10.10.20", "community": "public"},
    {"name": "Router-1", "ip": "10.10.10.30", "community": "public"},
]

HOSTNAME_MAPPING = {
    # "LLDP-name": "Zabbix-host-name"
}

# LLDP OIDs
OID_LLDP_REM_SYSNAME = ".1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORTID = ".1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORTDESC = ".1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_LOC_PORTDESC = ".1.0.8802.1.1.2.1.3.7.1.4"

@dataclass(frozen=True)
class Link:
    local_host: str
    local_port: str
    remote_host: str
    remote_port: str

def run_snmpwalk(ip: str, community: str, oid: str) -> str:
    cmd = [
        "snmpbulkwalk",
        "-v", SNMP_VERSION,
        "-c", community,
        "-On",
        "-t", SNMP_TIMEOUT,
        "-r", SNMP_RETRIES,
        ip,
        oid,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"SNMP walk failed for {ip}, OID {oid}: {result.stderr.strip() or result.stdout.strip()}"
        )

    return result.stdout

def parse_snmp_lines(output: str) -> List[Tuple[str, str]]:
    result: List[Tuple[str, str]] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or " = " not in line:
            continue

        left, right = line.split(" = ", 1)
        value = extract_value(right)
        result.append((left.strip(), value))

    return result

def extract_value(raw_value: str) -> str:
    raw_value = raw_value.strip()

    if ": " in raw_value:
        _, value = raw_value.split(": ", 1)
    else:
        value = raw_value

    value = value.strip()

    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]

    return value.strip()

def parse_last_indexes(oid: str, count: int) -> Tuple[int, ...]:
    """
    Берёт последние count чисел из OID.
    Для lldpRem* таблиц индекс обычно:
    timeMark.localPortNum.remIndex
    """
    numbers = re.findall(r"\d+", oid)
    if len(numbers) < count:
        raise ValueError(f"OID too short for index extraction: {oid}")
    return tuple(int(x) for x in numbers[-count:])

def walk_lldp_remote_sysname(ip: str, community: str) -> Dict[Tuple[int, int, int], str]:
    output = run_snmpwalk(ip, community, OID_LLDP_REM_SYSNAME)
    parsed = parse_snmp_lines(output)

    data: Dict[Tuple[int, int, int], str] = {}
    for oid, value in parsed:
        idx = parse_last_indexes(oid, 3)
        data[idx] = value
    return data

def walk_lldp_remote_portid(ip: str, community: str) -> Dict[Tuple[int, int, int], str]:
    output = run_snmpwalk(ip, community, OID_LLDP_REM_PORTID)
    parsed = parse_snmp_lines(output)

    data: Dict[Tuple[int, int, int], str] = {}
    for oid, value in parsed:
        idx = parse_last_indexes(oid, 3)
        data[idx] = value
    return data

def walk_lldp_local_portdesc(ip: str, community: str) -> Dict[int, str]:
    output = run_snmpwalk(ip, community, OID_LLDP_LOC_PORTDESC)
    parsed = parse_snmp_lines(output)

    data: Dict[int, str] = {}
    for oid, value in parsed:
        idx = parse_last_indexes(oid, 1)[0]
        data[idx] = value
    return data

def walk_lldp_remote_portdesc(ip: str, community: str) -> Dict[Tuple[int, int, int], str]:
    output = run_snmpwalk(ip, community, OID_LLDP_REM_PORTDESC)
    parsed = parse_snmp_lines(output)

    data: Dict[Tuple[int, int, int], str] = {}
    for oid, value in parsed:
        idx = parse_last_indexes(oid, 3)
        data[idx] = value
    return data

def normalize_host_name(hostname: str) -> str:
    hostname = hostname.strip()
    return HOSTNAME_MAPPING.get(hostname, hostname)

def collect_links_from_device(device: dict) -> List[Link]:
    local_name = device["name"]
    ip = device["ip"]
    community = device["community"]

    rem_sysname = walk_lldp_remote_sysname(ip, community)
    rem_portid = walk_lldp_remote_portid(ip, community)
    rem_portdesc = walk_lldp_remote_portdesc(ip, community)
    loc_portdesc = walk_lldp_local_portdesc(ip, community)

    links: List[Link] = []

    all_indexes = set(rem_sysname.keys()) | set(rem_portid.keys()) | set(rem_portdesc.keys())

    for idx in sorted(all_indexes):
        _, local_port_num, _ = idx

        remote_host = rem_sysname.get(idx, "").strip()
        remote_port_desc = rem_portdesc.get(idx, "").strip()
        remote_port_id = rem_portid.get(idx, "").strip()
        local_port = loc_portdesc.get(local_port_num, str(local_port_num)).strip()

        if not remote_host:
            continue

        remote_port = remote_port_desc if remote_port_desc else remote_port_id

        links.append(
            Link(
                local_host=normalize_host_name(local_name),
                local_port=local_port,
                remote_host=normalize_host_name(remote_host),
                remote_port=remote_port,
            )
        )

    return links

def collect_all_links(devices: List[dict]) -> List[Link]:
    all_links: List[Link] = []

    for device in devices:
        print(f"[INFO] Polling {device['name']} ({device['ip']})...")
        device_links = collect_links_from_device(device)
        all_links.extend(device_links)

    return all_links

def deduplicate_links(links: List[Link]) -> List[Link]:
    seen: Set[Tuple[str, str]] = set()
    result: List[Link] = []

    for link in links:
        a = link.local_host.strip()
        b = link.remote_host.strip()

        if not a or not b or a == b:
            continue

        pair = tuple(sorted((a, b)))
        if pair in seen:
            continue

        seen.add(pair)
        result.append(link)

    return result

def extract_unique_hosts(links: List[Link]) -> List[str]:
    hosts = {x.local_host for x in links} | {x.remote_host for x in links}
    return sorted(hosts)

def build_hostid_map(zapi: ZabbixAPI, host_names: List[str]) -> Dict[str, str]:
    zabbix_hosts = zapi.host.get(output=["host", "hostid", "name"])

    by_host: Dict[str, str] = {}
    by_visible_name: Dict[str, str] = {}

    for item in zabbix_hosts:
        by_host[item["host"]] = item["hostid"]
        if item.get("name"):
            by_visible_name[item["name"]] = item["hostid"]

    hostid_map: Dict[str, str] = {}
    missing: List[str] = []
    for host_name in host_names:
        if host_name in by_host:
            hostid_map[host_name] = by_host[host_name]
        elif host_name in by_visible_name:
            hostid_map[host_name] = by_visible_name[host_name]
        else:
            missing.append(host_name)

    if missing:
        raise RuntimeError(
            "Не найдены хосты в Zabbix: " + ", ".join(missing)
        )

    return hostid_map

def get_default_map_icon(zapi: ZabbixAPI) -> str:
    images = zapi.image.get(output=["imageid", "name"], filter={"imagetype": 1})

    if not images:
        raise RuntimeError("В Zabbix не найдено ни одной map icon")

    preferred_names = ["Router", "Switch", "Network device", "Server", "Cloud"]
    by_name = {img["name"]: img["imageid"] for img in images}

    for name in preferred_names:
        if name in by_name:
            return by_name[name]

    return images[0]["imageid"]


def calculate_positions(host_names: List[str], width: int, height: int) -> Dict[str, Tuple[int, int]]:
    positions: Dict[str, Tuple[int, int]] = {}

    count = len(host_names)
    if count == 0:
        return positions

    center_x = width // 2
    center_y = height // 2
    radius = max(150, min(width, height) // 3)

    for index, host_name in enumerate(host_names):
        angle = 2 * math.pi * index / count
        x = int(center_x + radius * math.cos(angle))
        y = int(center_y + radius * math.sin(angle))
        positions[host_name] = (x, y)

    return positions

def build_selements(
    hostid_map: Dict[str, str],
    positions: Dict[str, Tuple[int, int]],
    default_icon_id: str
) -> List[dict]:
    selements: List[dict] = []

    for idx, host_name in enumerate(sorted(hostid_map.keys()), start=1):
        x, y = positions[host_name]

        selements.append({
            "selementid": str(idx),
            "elements": [{"hostid": hostid_map[host_name]}],
            "elementtype": 0,
            "iconid_off": default_icon_id,
            "label": host_name,
            "label_location": "0",
            "x": str(x),
            "y": str(y),
        })

    return selements

def build_selementid_lookup(hostid_map: Dict[str, str]) -> Dict[str, str]:
    return {
        host_name: str(idx)
        for idx, host_name in enumerate(sorted(hostid_map.keys()), start=1)
    }

def build_links(links: List[Link], selementid_lookup: Dict[str, str]) -> List[dict]:
    map_links: List[dict] = []

    for link in links:
        if link.local_host not in selementid_lookup or link.remote_host not in selementid_lookup:
            continue

        label = ""
        if link.local_port or link.remote_port:
            label = f"{link.local_port} ↔ {link.remote_port}".strip()

        item = {
            "selementid1": selementid_lookup[link.local_host],
            "selementid2": selementid_lookup[link.remote_host],
        }

        if label:
            item["label"] = label

        map_links.append(item)

    return map_links

def get_existing_map(zapi: ZabbixAPI, map_name: str) -> Optional[dict]:
    result = zapi.map.get(output="extend", filter={"name": [map_name]})
    return result[0] if result else None

def create_map(
    zapi: ZabbixAPI,
    map_name: str,
    width: int,
    height: int,
    selements: List[dict],
    links: List[dict],
) -> dict:
    return zapi.map.create(
        name=map_name,
        width=str(width),
        height=str(height),
        selements=selements,
        links=links,
    )

def update_map(
    zapi: ZabbixAPI,
    sysmapid: str,
    width: int,
    height: int,
    selements: List[dict],
    links: List[dict],
) -> dict:
    return zapi.map.update(
        sysmapid=sysmapid,
        width=str(width),
        height=str(height),
        selements=selements,
        links=links,
    )

def print_summary(links: List[Link], hostid_map: Dict[str, str]) -> None:
    print("\nХосты, найденные в Zabbix:")
    for host_name, hostid in sorted(hostid_map.items()):
        print(f"  - {host_name}: hostid={hostid}")

    print("\nСвязи:")
    for link in links:
        print(f"  - {link.local_host} ({link.local_port}) <-> {link.remote_host} ({link.remote_port})")

def main() -> int:
    try:
        raw_links = collect_all_links(DEVICES)
        links = deduplicate_links(raw_links)

        if not links:
            raise RuntimeError("LLDP-связи не найдены")

        host_names = extract_unique_hosts(links)

        zapi = ZabbixAPI(ZABBIX_URL)
        zapi.login(ZABBIX_USER, ZABBIX_PASSWORD)

        hostid_map = build_hostid_map(zapi, host_names)
        default_icon_id = get_default_map_icon(zapi)

        positions = calculate_positions(host_names, MAP_WIDTH, MAP_HEIGHT)
        selements = build_selements(hostid_map, positions, default_icon_id)
        selementid_lookup = build_selementid_lookup(hostid_map)
        map_links = build_links(links, selementid_lookup)

        print_summary(links, hostid_map)

        existing_map = get_existing_map(zapi, MAP_NAME)

        if existing_map is None:
            if not CREATE_MAP_IF_MISSING:
                raise RuntimeError(f"Карта '{MAP_NAME}' не найдена")

            result = create_map(
                zapi=zapi,
                map_name=MAP_NAME,
                width=MAP_WIDTH,
                height=MAP_HEIGHT,
                selements=selements,
                links=map_links,
            )
            print(f"\nКарта '{MAP_NAME}' создана: {result}")
        else:
            result = update_map(
                zapi=zapi,
                sysmapid=existing_map["sysmapid"],
                width=MAP_WIDTH,
                height=MAP_HEIGHT,
                selements=selements,
                links=map_links,
            )
            print(f"\nКарта '{MAP_NAME}' обновлена: {result}")

        return 0

    except Exception as exc:
        print(f"\nОшибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())