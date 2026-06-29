# backend/src/network_utils.py
"""
Real network introspection utilities — no mock data.

Provides:
- list_interfaces(): the actual network interfaces on this host, for the
  Settings page's "Network Interface" dropdown (mirrors Scapy's view since
  RealTimeIDSPipeline also needs a real interface name to sniff on).
- list_arp_devices(): devices currently visible in this host's real ARP
  table — i.e. machines that have actually communicated on the local
  network recently. This powers the Dashboard's "Network Devices" panel
  with genuine local hosts instead of a placeholder card.

Both functions degrade gracefully (return an empty list with a logged
reason) rather than raising, since interface/ARP access can be restricted
depending on container privileges — but they never fabricate fake entries.
"""

import logging
import platform
import subprocess
import re

logger = logging.getLogger("IDS-NetworkUtils")

try:
    import psutil
except ImportError:
    psutil = None


def list_interfaces() -> list[dict]:
    """
    Returns real interfaces on this host:
        [{ "name": "eth0", "ipv4": "192.168.1.12", "is_up": True }, ...]
    Uses psutil (cross-platform, no special privileges required) rather than
    Scapy's get_if_list(), since the dashboard process shouldn't need raw
    socket capability just to populate a dropdown.
    """
    if psutil is None:
        logger.warning("psutil unavailable — cannot enumerate interfaces.")
        return []

    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = next((a.address for a in addr_list if a.family.name in ("AF_INET",)), None)
            is_up = stats[name].isup if name in stats else False
            interfaces.append({"name": name, "ipv4": ipv4, "is_up": is_up})
    except Exception as e:
        logger.error(f"Failed to enumerate network interfaces: {e}")
        return []

    # Real, currently-up interfaces with an IPv4 address first — these are the
    # ones actually worth monitoring; loopback/down interfaces sort last.
    interfaces.sort(key=lambda i: (not i["is_up"], i["ipv4"] is None, i["name"]))
    return interfaces


_ARP_LINE_LINUX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?\s+(?P<mac>[0-9a-fA-F:]{17})\s+.*\s(?P<iface>\S+)\s*$"
)
_ARP_LINE_WINDOWS = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F-]{17})\s+(?P<type>\w+)"
)


def _read_proc_net_arp() -> list[dict]:
    """Linux: /proc/net/arp is always readable, no subprocess/root needed."""
    devices = []
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]  # skip header row
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, _hw_type, flags, mac, _mask, iface = parts[:6]
            if mac == "00:00:00:00:00:00":
                continue  # incomplete ARP entry, device not actually resolved
            devices.append({
                "ip": ip, "mac": mac, "interface": iface,
                "status": "online" if flags != "0x0" else "stale",
            })
    except FileNotFoundError:
        logger.info("/proc/net/arp not present (non-Linux host) — trying `arp -a` instead.")
    except Exception as e:
        logger.warning(f"Failed reading /proc/net/arp: {e}")
    return devices


def _read_arp_command() -> list[dict]:
    """Fallback for Windows/macOS hosts: parse the real output of `arp -a`."""
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=3)
    except Exception as e:
        logger.warning(f"`arp -a` unavailable: {e}")
        return devices

    is_windows = platform.system().lower().startswith("win")
    pattern = _ARP_LINE_WINDOWS if is_windows else re.compile(
        r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-fA-F:]{17})"
    )

    for line in output.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        groups = match.groupdict()
        mac = groups.get("mac", "").lower()
        if not mac or mac == "ff-ff-ff-ff-ff-ff" or mac == "ff:ff:ff:ff:ff:ff":
            continue
        devices.append({
            "ip": groups.get("ip"), "mac": mac,
            "interface": None, "status": "online",
        })
    return devices


def list_arp_devices() -> list[dict]:
    """
    Returns real devices visible in this host's ARP table right now. These
    are genuine local-network neighbors the OS has actually exchanged
    packets with — not a static placeholder list.
    """
    devices = _read_proc_net_arp()
    if not devices:
        devices = _read_arp_command()

    # De-duplicate by IP in case both sources somehow ran
    seen = set()
    unique = []
    for d in devices:
        if d["ip"] in seen:
            continue
        seen.add(d["ip"])
        unique.append(d)
    return unique
