"""Basis-Infrastruktur für alle Agenten (Ameisen).

- `Task`: eine Arbeitseinheit, die die Königin dispatcht.
- `AgentFinding`: normalisiertes Ergebnis eines Agenten – trägt jetzt ein
  verpflichtendes `status`-Label (Beweis-Stufe) und ein strukturiertes
  `evidence`-Objekt.
- `Playbook`: deklarative Beschreibung eines ausführbaren Playbooks eines
  Soldaten (Single Source of Truth für die Capability-Registry).
- `AgentContext`: geteilter Kontext (Scope-Check-Callback, Logger, Store-Infos).
- `AntAgent`: abstrakte Basisklasse mit gemeinsamem Lebenszyklus + Logging.

Alle Agenten sind asyncio-fähig: `run()` ist eine Coroutine. So kann die
Königin Agenten-Gruppen parallel dispatchen.
"""
from __future__ import annotations

import abc
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Status-Taxonomie (Beweis-Stufen). EINZIGE gültige Labels für Findings.
# ---------------------------------------------------------------------------
#: Aktiv belegt – KONKRETER Request/Response-Nachweis in DIESEM Lauf erfasst.
STATUS_VERIFIED = "VERIFIZIERT"
#: Passiv/öffentlich belegt (beobachtet, aber nicht aktiv ausgenutzt/erzwungen).
STATUS_PASSIVE = "BESTÄTIGT(PASSIV)"
#: Anwendbarkeit offen – abgeleitet/versionsbasiert, noch zu bestätigen.
STATUS_TO_CONFIRM = "ZU BESTÄTIGEN"
#: Nur unter einer Bedingung gültig (z.B. Technologie tatsächlich eingesetzt).
STATUS_CONDITIONAL = "BEDINGT"
#: Fremd-CVE / Muster / Hypothese (Referenz, kein eigener Nachweis).
STATUS_REFERENCE = "REFERENZ"

ALL_STATUSES = frozenset({
    STATUS_VERIFIED, STATUS_PASSIVE, STATUS_TO_CONFIRM,
    STATUS_CONDITIONAL, STATUS_REFERENCE,
})

#: Evidence-Schlüssel, die einen echten Request belegen.
_REQUEST_KEYS = ("request", "request_true", "request_false")
#: Evidence-Schlüssel, die eine echte Response/Beobachtung aus diesem Lauf
#: belegen (mind. einer muss zusätzlich zu einem Request vorhanden sein).
_RESPONSE_PROOF_KEYS = (
    "response_excerpt", "status", "location", "signature_matched",
    "body_similarity_true_false", "access_control_allow_origin",
    "hits", "len_true", "len_false", "reflected_unescaped",
)


@dataclass
class Playbook:
    """Deklaratives, ausführbares Playbook eines Soldaten.

    `mode` ist "defensive" (immer erlaubt, read-only) oder "offensive"
    (nur unter Oversight + offensive/aktiv-Freischaltung). `tools` zählt die
    konkret nutzbaren Checks/Tools dieses Playbooks auf (für die Registry).
    """
    name: str
    mode: str                       # "defensive" | "offensive"
    oversight_required: bool
    tools: list[str] = field(default_factory=list)
    description: str = ""
    #: Konkrete Aufgaben/Checks dieses Playbooks (für GUI-Checklisten). Leer =
    #: wird in der Registry aus dem zentralen TASK_CATALOG ergänzt.
    tasks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mode": self.mode,
            "oversight_required": bool(self.oversight_required),
            "tools": list(self.tools),
            "description": self.description,
            "tasks": list(self.tasks),
        }


@dataclass
class Task:
    """Eine Arbeitseinheit im Schwarm."""
    phase: str                       # recon | scan | verify | analyze | report
    target_id: int
    target_name: str
    assets: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    # Ergebnisse vorheriger Phasen (von der Königin gefüllt)
    context_findings: list["AgentFinding"] = field(default_factory=list)


@dataclass
class AgentFinding:
    """Normalisiertes Finding, das Agenten zurückgeben.

    `status` ist das verpflichtende Beweis-Stufen-Label (siehe STATUS_*).
    `evidence` ist ein strukturiertes Objekt (dict), KEIN Freitext.
    `false_positive` markiert Catch-all-/Baseline-Artefakte, die aus den
    Zählungen ausgeschlossen werden.
    """
    agent: str
    title: str
    category: str
    severity: str                    # info|low|medium|high|critical
    asset: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    dedup_key: str = ""
    status: str = ""
    false_positive: bool = False

    def key(self) -> str:
        return self.dedup_key or f"{self.category}:{self.title}:{self.asset}"

    def has_active_evidence(self) -> bool:
        """True nur, wenn Request UND Response-Nachweis aus diesem Lauf vorliegen."""
        ev = self.evidence or {}
        if not isinstance(ev, dict):
            return False
        has_request = any(ev.get(k) for k in _REQUEST_KEYS)
        has_response = any(k in ev and ev.get(k) not in (None, "") for k in _RESPONSE_PROOF_KEYS)
        return bool(has_request and has_response)


ScopeChecker = Callable[[str], bool]


@dataclass
class AgentContext:
    """Geteilter Kontext, den die Königin an jeden Agenten übergibt."""
    run_id: str
    #: Prüft, ob ein Asset in-scope ist. Agenten MÜSSEN das vor jedem
    #: Request aufrufen; out-of-scope Assets werden übersprungen.
    scope_check: ScopeChecker
    logger: logging.Logger
    #: Live-Event-Callback (für Web-Feed). Optional.
    emit: Optional[Callable[[dict], None]] = None
    #: Optionaler LLM-Client (None, wenn kein Provider konfiguriert ist).
    llm: Optional[Any] = None
    #: Router-Hook der Königin: route(task_type, complexity) -> RouteDecision.
    route: Optional[Callable[..., Any]] = None
    #: Geteilter, scope- und ratengebundener Netzwerk-Client (echte Requests).
    net: Optional[Any] = None
    #: Aktive Verifikation (TIEFE, kontrollierte Checks) freigeschaltet?
    active: bool = False
    #: Offensives Fuzzing freigeschaltet? Unabhängig von `active`.
    fuzz: bool = False
    #: Soldaten-Overrides {soldier: [{playbook,key,value}]} (editierbar in GUI).
    soldier_overrides: dict = field(default_factory=dict)
    #: Soldaten-Mems {soldier: [text, ...]} – als Lauf-Kontext mitgegeben.
    soldier_mems: dict = field(default_factory=dict)

    @property
    def llm_ready(self) -> bool:
        return bool(self.llm and getattr(self.llm, "configured", False))

    def log(self, msg: str) -> None:
        self.logger.info(msg)
        if self.emit:
            self.emit({"ts": time.time(), "msg": msg})


class AntAgent(abc.ABC):
    """Abstrakte Basis-Ameise (Soldat)."""

    #: Kurzname (eindeutig), z.B. "recon".
    name: str = "ant"
    #: Menschlich lesbare Rolle.
    role: str = "Generische Ameise"
    #: Roster-/Spezialitäts-Name (z.B. "recon-master").
    specialty: str = ""
    #: Phasen, für die diese Ameise zuständig ist.
    phases: tuple[str, ...] = ()
    #: Deklarative, ausführbare Playbooks (Single Source of Truth für Registry).
    playbooks: tuple[Playbook, ...] = ()

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx

    # ---- Registry-Hilfen (Klassenmethoden, damit die Registry ohne ctx baut) ----
    @classmethod
    def describe(cls) -> dict:
        """Capability-Beschreibung dieses Soldaten (für die Registry)."""
        return {
            "name": cls.name,
            "specialty": cls.specialty or cls.name,
            "role": cls.role,
            "phases": list(cls.phases),
            "playbooks": [pb.to_dict() for pb in cls.playbooks],
        }

    def my_overrides(self) -> list:
        return list((self.ctx.soldier_overrides or {}).get(self.name, []))

    def my_mems(self) -> list:
        return list((self.ctx.soldier_mems or {}).get(self.name, []))

    def is_enabled(self) -> bool:
        """Soldat-weiter Override key='enabled' (playbook=''); Default aktiviert."""
        for o in self.my_overrides():
            if o.get("playbook", "") == "" and o.get("key") == "enabled":
                return str(o.get("value", "true")).lower() not in ("false", "0", "no", "off")
        return True

    def playbook_enabled(self, playbook: str) -> bool:
        for o in self.my_overrides():
            if o.get("playbook") == playbook and o.get("key") == "enabled":
                return str(o.get("value", "true")).lower() not in ("false", "0", "no", "off")
        return True

    def _in_scope(self, asset: str) -> bool:
        ok = self.ctx.scope_check(asset)
        if not ok:
            self.ctx.log(f"[{self.name}] ⛔ übersprungen (out-of-scope): {asset}")
        return ok

    async def run(self, task: Task) -> list[AgentFinding]:
        """Führt die Aufgabe aus und gibt Findings zurück."""
        if not self.is_enabled():
            self.ctx.log(f"[{self.name}] ⏸ deaktiviert (Soldaten-Override) – übersprungen.")
            return []
        mems = self.my_mems()
        if mems:
            self.ctx.log(f"[{self.name}] 🧠 {len(mems)} Mem(s) als Kontext geladen.")
        self.ctx.log(f"[{self.name}] 🐜 startet Phase '{task.phase}' für {task.target_name}")
        t0 = time.time()
        try:
            findings = await self.work(task)
        except Exception as exc:  # defensiv: ein Agent darf den Schwarm nicht killen
            self.ctx.log(f"[{self.name}] ❌ Fehler: {exc}")
            return []
        dt = time.time() - t0
        self.ctx.log(
            f"[{self.name}] ✅ fertig ({len(findings)} Findings, {dt:.2f}s)"
        )
        return findings

    @abc.abstractmethod
    async def work(self, task: Task) -> list[AgentFinding]:
        """Eigentliche Arbeit – von jeder Ameise implementiert."""
        raise NotImplementedError
