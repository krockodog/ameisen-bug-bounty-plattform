"""Network-Defense-Checks – rein lesend (Listening-Ports, Firewall, Exposure).

Kein Portscan gegen fremde Ziele. Nur lokale Beobachtung (ss/netstat) und
Firewall-Status. Ohne Tools → ehrliche skip-Findings.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Optional

log = logging.getLogger("antbb.netdef")

RISKY_PORTS = {
    21: "ftp", 23: "telnet", 69: "tftp", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 445: "smb", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 27017: "mongodb",
}


@dataclass
class NetCheck:
    check_id: str
    title: str
    status: str
    severity: str
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return f"__err__:{exc}"


def listening_ports() -> list[dict]:
    """Lokale Listening-Ports via ss oder netstat. [] wenn Tool fehlt."""
    out = []
    if shutil.which("ss"):
        raw = _run(["ss", "-lntu"])
    elif shutil.which("netstat"):
        raw = _run(["netstat", "-lntu"])
    else:
        return out
    if raw.startswith("__err__"):
        return out
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3] if "ss" in (shutil.which("ss") or "") or True else parts[3]
        # ss: Netid State Recv-Q Send-Q Local Address:Port Peer
        # try last colon split
        if ":" not in local:
            continue
        host, _, port_s = local.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            continue
        proto = (parts[0] or "").lower()
        out.append({"proto": proto, "local": local, "port": port,
                    "risky": port in RISKY_PORTS,
                    "service_hint": RISKY_PORTS.get(port, "")})
    return out


def firewall_status() -> dict:
    """Firewall vorhanden? (ufw/firewalld/nft/iptables) – read-only."""
    for name, cmd in (
        ("ufw", ["ufw", "status"]),
        ("firewalld", ["firewall-cmd", "--state"]),
        ("nftables", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables", "-L", "-n"]),
    ):
        if not shutil.which(cmd[0]):
            continue
        raw = _run(cmd)
        active = False
        low = raw.lower()
        if name == "ufw":
            active = "status: active" in low
        elif name == "firewalld":
            active = "running" in low
        elif name in ("nftables", "iptables"):
            active = bool(raw.strip()) and not raw.startswith("__err__")
        return {"tool": name, "active": active,
                "excerpt": raw[:400], "available": True}
    return {"tool": None, "active": False, "available": False,
            "excerpt": "kein Firewall-Tool gefunden"}


def run_audit() -> list[NetCheck]:
    checks: list[NetCheck] = []
    ports = listening_ports()
    if not ports:
        checks.append(NetCheck(
            check_id="listen-ports", title="Listening-Ports nicht ermittelbar",
            status="skip", severity="info",
            detail="ss/netstat nicht verfügbar oder keine Listener.",
            evidence={"tool": shutil.which("ss") or shutil.which("netstat")},
        ))
    else:
        risky = [p for p in ports if p.get("risky")]
        checks.append(NetCheck(
            check_id="listen-ports",
            title=f"{len(ports)} Listening-Port(s), davon {len(risky)} riskant",
            status="fail" if risky else "pass",
            severity="medium" if risky else "info",
            detail=("Riskante Dienste: " + ", ".join(
                f"{p['port']}/{p.get('service_hint')}" for p in risky[:12])
                    if risky else "Keine bekannten Risiko-Ports offen."),
            recommendation=("Riskante Dienste binden/firewallen oder abschalten."
                            if risky else ""),
            evidence={"port_count": len(ports), "risky": risky[:20],
                      "sample": ports[:30]},
        ))

    fw = firewall_status()
    if not fw.get("available"):
        checks.append(NetCheck(
            check_id="firewall", title="Keine Firewall-Tools gefunden",
            status="fail", severity="medium",
            detail=fw.get("excerpt") or "",
            recommendation="nftables/ufw/firewalld installieren und aktivieren.",
            evidence=fw,
        ))
    elif fw.get("active"):
        checks.append(NetCheck(
            check_id="firewall", title=f"Firewall aktiv ({fw.get('tool')})",
            status="pass", severity="info",
            detail="Firewall-Tool meldet aktiven Zustand.",
            evidence={k: v for k, v in fw.items() if k != "excerpt"},
        ))
    else:
        checks.append(NetCheck(
            check_id="firewall", title=f"Firewall inaktiv ({fw.get('tool')})",
            status="fail", severity="high",
            detail="Firewall-Tool vorhanden, aber nicht aktiv.",
            recommendation="Firewall aktivieren und Default-Deny für eingehend setzen.",
            evidence={k: v for k, v in fw.items() if k != "excerpt"},
        ))
    return checks


def capability_summary() -> dict:
    return {"risky_ports_catalog": len(RISKY_PORTS), "status": "installed"}
