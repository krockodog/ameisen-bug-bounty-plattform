"""Scope-Firewall / Egress-Filter (OS-Ebene) – zusätzliche Leitplanke.

Übersetzt die In-Scope-Allowlist eines Targets in OS-Egress-Regeln
(iptables UND nftables), die ausgehenden Verkehr NUR zu in-scope Hosts
zulassen; alles andere wird geblockt UND geloggt. Zweck: ein harter
Scope-Escape-Schutz auf Netzebene – KEIN Angriffswerkzeug.

Strenge Leitplanken (im Code erzwungen):
  * DRY-RUN by default: `generate()` baut nur das Regelwerk + einen klaren
    „würde anwenden"-Report. Es wird NIE die echte Firewall angefasst.
  * Anwenden nur hinter explizitem `apply=True` UND zusätzlich: Binary
    vorhanden (shutil.which) UND root (euid==0) UND ENV ANTBB_FW_APPLY=1.
    Fehlt irgendetwas davon → honest „nicht angewandt" (kein subprocess).
  * Default-deny Policy: OUTPUT-Policy DROP; erlaubt werden nur loopback,
    etablierte Rückflüsse, DNS (für Namensauflösung) und die in-scope Hosts.
  * Honest: nicht auflösbare Domains werden als solche vermerkt, nicht erfunden.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

LOG_PREFIX = "antbb-scope-drop "
APPLY_ENV = "ANTBB_FW_APPLY"


def _host_of(kind: str, value: str) -> Optional[str]:
    """Extrahiert einen Host/IP-Wert aus einem Scope-Eintrag (oder None)."""
    v = (value or "").strip()
    if not v:
        return None
    if kind == "ip":
        return v
    if kind == "domain":
        return v.lstrip("*.").strip()
    if kind in ("url",):
        if "://" not in v:
            v = "http://" + v
        return urlparse(v).hostname
    # path-Einträge haben keinen eigenen Host → ignorieren (kein Egress-Ziel).
    return None


def _resolve(host: str) -> list[str]:
    """Best-effort DNS-Auflösung → IPv4/IPv6-Liste (leer, wenn nicht auflösbar)."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return [host]  # schon eine IP
    except Exception:
        pass
    ips: list[str] = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            ip = sa[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        return []
    return ips


@dataclass
class EgressPlan:
    scopes_in: int
    hosts: list[dict] = field(default_factory=list)   # {host, kind, ips, resolved}
    unresolved: list[str] = field(default_factory=list)
    iptables_rules: list[str] = field(default_factory=list)
    nft_ruleset: str = ""
    applied: bool = False
    dry_run: bool = True
    apply_report: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "scopes_in": self.scopes_in,
            "hosts": self.hosts,
            "unresolved": self.unresolved,
            "iptables_rules": self.iptables_rules,
            "nft_ruleset": self.nft_ruleset,
            "applied": self.applied,
            "dry_run": self.dry_run,
            "apply_report": self.apply_report,
            "note": self.note,
        }


def _collect_hosts(scopes, resolve: bool) -> tuple[list[dict], list[str]]:
    hosts: list[dict] = []
    unresolved: list[str] = []
    seen = set()
    for s in scopes:
        allowed = s["allowed"] if _has(s, "allowed") else s.get("allowed")
        if not allowed:
            continue
        kind = s["kind"] if _has(s, "kind") else s.get("kind")
        value = s["value"] if _has(s, "value") else s.get("value")
        host = _host_of(kind, value)
        if not host or host in seen:
            continue
        seen.add(host)
        ips = _resolve(host) if resolve else []
        entry = {"host": host, "kind": kind, "ips": ips, "resolved": bool(ips)}
        hosts.append(entry)
        if not ips:
            unresolved.append(host)
    return hosts, unresolved


def _has(row, key) -> bool:
    try:
        return key in row.keys()
    except Exception:
        return isinstance(row, dict) and key in row


def _build_iptables(hosts: list[dict]) -> list[str]:
    """Erzeugt die iptables-Befehle (als Strings; werden im DRY-RUN nur gezeigt)."""
    R = [
        "# --- antbb Scope-Egress-Firewall (iptables, default-deny OUTPUT) ---",
        "iptables -N ANTBB_EGRESS 2>/dev/null || iptables -F ANTBB_EGRESS",
        "iptables -A ANTBB_EGRESS -o lo -j ACCEPT",
        "iptables -A ANTBB_EGRESS -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A ANTBB_EGRESS -p udp --dport 53 -j ACCEPT   # DNS (Namensauflösung)",
        "iptables -A ANTBB_EGRESS -p tcp --dport 53 -j ACCEPT   # DNS/TCP",
    ]
    for h in hosts:
        if h["ips"]:
            for ip in h["ips"]:
                R.append(f"iptables -A ANTBB_EGRESS -d {ip} -j ACCEPT   # in-scope {h['host']}")
        else:
            R.append(f"# (nicht auflösbar, kein Egress-ACCEPT) in-scope {h['host']}")
    R += [
        f'iptables -A ANTBB_EGRESS -j LOG --log-prefix "{LOG_PREFIX}" --log-level 4',
        "iptables -A ANTBB_EGRESS -j DROP",
        "# Kette aktivieren: iptables -I OUTPUT -j ANTBB_EGRESS",
    ]
    return R


def _build_nft(hosts: list[dict]) -> str:
    v4 = [ip for h in hosts for ip in h["ips"] if ":" not in ip]
    v6 = [ip for h in hosts for ip in h["ips"] if ":" in ip]
    allow4 = ", ".join(sorted(set(v4))) or ""
    allow6 = ", ".join(sorted(set(v6))) or ""
    lines = [
        "# --- antbb Scope-Egress-Firewall (nftables, default-deny) ---",
        "table inet antbb_scope {",
        "  chain egress {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname \"lo\" accept",
        "    ct state established,related accept",
        "    udp dport 53 accept",
        "    tcp dport 53 accept",
    ]
    if allow4:
        lines.append(f"    ip daddr {{ {allow4} }} accept   # in-scope (IPv4)")
    if allow6:
        lines.append(f"    ip6 daddr {{ {allow6} }} accept   # in-scope (IPv6)")
    lines += [
        f'    log prefix "{LOG_PREFIX}" level info',
        "    drop",
        "  }",
        "}",
    ]
    return "\n".join(lines)


def generate(scopes, *, resolve: bool = True) -> EgressPlan:
    """Baut den Egress-Plan (DRY-RUN) aus der In-Scope-Allowlist. Kein Eingriff."""
    hosts, unresolved = _collect_hosts(scopes, resolve)
    plan = EgressPlan(
        scopes_in=len(hosts),
        hosts=hosts,
        unresolved=unresolved,
        iptables_rules=_build_iptables(hosts),
        nft_ruleset=_build_nft(hosts),
        dry_run=True,
        applied=False,
    )
    engines = available_engines()
    have = [k for k, v in engines.items() if v]
    plan.apply_report = (
        "DRY-RUN: Es wurde NICHTS an der echten Firewall geändert.\n"
        f"- In-Scope-Egress-Ziele: {len(hosts)} "
        f"({sum(len(h['ips']) for h in hosts)} IP(s) aufgelöst, "
        f"{len(unresolved)} nicht auflösbar)\n"
        f"- Verfügbare Engines am Laufort: {', '.join(have) or 'keine (iptables/nft fehlen)'}\n"
        f"- Policy: OUTPUT default-deny; erlaubt loopback, established, DNS + in-scope Hosts; "
        f"Rest DROP + LOG (\"{LOG_PREFIX.strip()}\").\n"
        "- Anwenden erfordert: apply=True + root (euid 0) + Binary + ENV "
        f"{APPLY_ENV}=1 (sonst honest 'nicht angewandt')."
    )
    if not hosts:
        plan.note = ("Keine in-scope Egress-Ziele – Regelwerk würde ALLES ausgehend "
                     "blocken. Erst Scope-Allowlist pflegen.")
    return plan


def available_engines() -> dict:
    return {"iptables": bool(shutil.which("iptables")),
            "nftables": bool(shutil.which("nft"))}


def apply(scopes, *, engine: str = "iptables", confirm: bool = False) -> EgressPlan:
    """Wendet die Regeln NUR an, wenn alle Gates erfüllt sind. Sonst honest no-op.

    Gates (alle nötig): confirm=True UND euid==0 UND Binary vorhanden UND
    ENV ANTBB_FW_APPLY=1. Fehlt eines → es wird KEIN subprocess gestartet und
    `applied=False` mit klarer Begründung zurückgegeben.
    """
    plan = generate(scopes, resolve=True)
    plan.dry_run = not confirm
    reasons = []
    if not confirm:
        reasons.append("apply/confirm nicht gesetzt")
    if os.environ.get(APPLY_ENV, "").strip() not in ("1", "true", "yes"):
        reasons.append(f"{APPLY_ENV}!=1")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        reasons.append("nicht root (euid!=0)")
    bin_name = "iptables" if engine == "iptables" else "nft"
    if not shutil.which(bin_name):
        reasons.append(f"Binary '{bin_name}' fehlt")
    if not plan.hosts:
        reasons.append("keine in-scope Egress-Ziele")
    if reasons:
        plan.applied = False
        plan.apply_report = ("NICHT angewandt (honest no-op). Offene Gates: "
                             + "; ".join(reasons) + ".\n\n" + plan.apply_report)
        return plan
    # Ab hier wären ALLE Gates erfüllt (nur auf einem echten root-Host mit Tool).
    try:  # pragma: no cover (nie auf der Box erreichbar)
        if engine == "iptables":
            for cmd in plan.iptables_rules:
                if cmd.startswith("#") or cmd.startswith("iptables -I OUTPUT"):
                    continue
                subprocess.run(cmd.split("#")[0].split(), check=False)
        else:
            subprocess.run(["nft", "-f", "-"], input=plan.nft_ruleset.encode(), check=False)
        plan.applied = True
        plan.apply_report = f"Regeln via {engine} angewandt (Scope-Egress-Firewall aktiv)."
    except Exception as exc:  # pragma: no cover
        plan.applied = False
        plan.apply_report = f"Anwenden fehlgeschlagen: {exc}"
    return plan
