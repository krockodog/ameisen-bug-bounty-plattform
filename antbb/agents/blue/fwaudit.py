"""Blue-Soldat: Firewall-Audit (read-only).

Bewertet die lokale Netz-Exposition: Regelwerk-Status (ufw/nft/iptables, soweit
ohne Root lesbar) und lauschende Dienste auf Wildcard-Adressen. Es werden
keine Regeln geändert und keine fremden Hosts kontaktiert.
"""
from __future__ import annotations

from ._sys import read, run, have
from .audit import AuditAnt, CheckResult, Playbook, Task

RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "MS-RPC",
               139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
               1433: "MSSQL", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
               11211: "Memcached", 27017: "MongoDB"}


def listeners() -> list[tuple[str, int]]:
    """TCP-LISTEN-Sockets aus /proc/net/tcp{,6} → (bind-adresse, port)."""
    out: list[tuple[str, int]] = []
    for fn, wild in (("/proc/net/tcp", "00000000"), ("/proc/net/tcp6", "0" * 32)):
        for line in read(fn).splitlines()[1:]:
            f = line.split()
            if len(f) < 4 or f[3] != "0A":
                continue
            addr, port = f[1].rsplit(":", 1)
            scope = "wildcard" if addr == wild else (
                "loopback" if addr in ("0100007F", "0" * 31 + "1") else "iface")
            out.append((scope, int(port, 16)))
    return out


def collect(task=None, scope_check=None) -> list[CheckResult]:
    res: list[CheckResult] = []
    socks = listeners()
    wild = sorted({p for s, p in socks if s == "wildcard"})
    risky = [p for p in wild if p in RISKY_PORTS]

    # 1) Risiko-Ports auf Wildcard
    cid, title = "risky-ports-exposed", "Firewall: keine riskanten Dienste auf allen Interfaces"
    if not socks:
        res.append(CheckResult(cid, title, "info", "Keine Listener lesbar (/proc/net/tcp leer)."))
    elif risky:
        res.append(CheckResult(
            cid, title, "fail",
            "Riskante Dienste lauschen auf allen Interfaces: "
            + ", ".join(f"{p}/{RISKY_PORTS[p]}" for p in risky),
            "Dienst an 127.0.0.1/internes Interface binden oder per Firewall einschränken.",
            severity="high", evidence={"ports": risky}))
    else:
        res.append(CheckResult(cid, title, "pass", "Keine Datenbank-/Legacy-Dienste auf Wildcard-Adressen.",
                               evidence={"wildcard_ports": len(wild)}))

    # 2) Wildcard-Listener-Inventar (Referenz/Info, Zahl statt Rauschen)
    res.append(CheckResult(
        "wildcard-listeners", "Firewall: Listener-Inventar (Exposition)",
        "pass" if socks else "info",
        f"{len(socks)} TCP-Listener, davon {len(wild)} Port(s) auf Wildcard, "
        f"{sum(1 for s,_ in socks if s=='loopback')} nur Loopback.",
        evidence={"total": len(socks), "wildcard_ports": wild[:40]}))

    # 3) Regelwerk-Status
    cid, title = "ruleset-active", "Firewall: Paketfilter-Regelwerk aktiv"
    seen, unreadable = {}, False
    ufw = read("/etc/ufw/ufw.conf")
    if ufw:
        seen["ufw"] = "ENABLED=yes" in ufw.replace(" ", "")
    if have("nft"):
        rc, o = run(["nft", "list", "ruleset"], timeout=6)
        if rc == 0 and o.strip():
            seen["nftables"] = "chain" in o
        elif "ermission" in o or "Operation not permitted" in o:
            unreadable = True
    if have("iptables"):
        rc, o = run(["iptables", "-S"], timeout=6)
        if rc == 0:
            seen["iptables"] = any(l.startswith("-A") or ("-P" in l and "DROP" in l) for l in o.splitlines())
        elif "ermission" in o or "root" in o.lower():
            unreadable = True
    if any(seen.values()):
        res.append(CheckResult(cid, title, "pass", "Aktiver Paketfilter erkannt: "
                               + ", ".join(k for k, v in seen.items() if v), evidence={"engines": seen}))
    elif unreadable and not seen:
        res.append(CheckResult(cid, title, "info",
                               "Regelwerk ohne Root nicht lesbar – Audit als privilegierter Dienst wiederholen."))
    elif seen:
        res.append(CheckResult(cid, title, "fail", "Firewall-Engine vorhanden, aber ohne aktive Regeln.",
                               "Default-deny Eingangsregel aktivieren.", severity="medium",
                               fix_command="sudo ufw default deny incoming && sudo ufw enable",
                               evidence={"engines": seen}))
    else:
        res.append(CheckResult(cid, title, "info", "Keine Firewall-Engine (ufw/nft/iptables) auffindbar."))

    # 4) IP-Forwarding
    cid, title = "ip-forwarding", "Firewall: IP-Forwarding nur bewusst aktiv"
    v = read("/proc/sys/net/ipv4/ip_forward").strip()
    if v == "":
        res.append(CheckResult(cid, title, "info", "ip_forward nicht lesbar."))
    elif v == "0":
        res.append(CheckResult(cid, title, "pass", "net.ipv4.ip_forward=0"))
    else:
        res.append(CheckResult(cid, title, "fail", "net.ipv4.ip_forward=1 (Router-/Container-Host?).",
                               "Nur aktiv lassen, wenn dieses System bewusst routet; sonst deaktivieren.",
                               severity="low", fix_command="sudo sysctl -w net.ipv4.ip_forward=0"))
    return res


class FirewallAuditAnt(AuditAnt):
    name = "blue-fwaudit"
    specialty = "blue-firewall-auditor"
    role = ("Firewall-Audit (read-only): Regelwerk-Status, riskante Wildcard-"
            "Listener und Forwarding bewerten – keine Regeländerung.")
    blue_phases = ("assess", "defend")
    audit_id = "fwaudit"
    playbooks = (
        Playbook("fw-ruleset-audit", "defensive", False,
                 ["ufw-conf", "nft-list", "iptables-S"],
                 "Prüft, ob ein Paketfilter mit aktiven Regeln läuft (soweit lesbar)."),
        Playbook("fw-exposure-review", "defensive", False,
                 ["proc-net-tcp", "risky-port-list", "ip-forward"],
                 "Bewertet lauschende Dienste auf Wildcard-Adressen gegen eine Risiko-Portliste."),
        Playbook("fw-rule-apply", "defensive", True,
                 ["apply-deny-rule-gated"],
                 "Firewall-Regel setzen – NUR mit Oversight (default-deny, dokumentiert)."),
    )

    def collect(self, task: Task):
        return collect(task, self.ctx.scope_check)
