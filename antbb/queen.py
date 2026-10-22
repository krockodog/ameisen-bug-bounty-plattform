"""Die Ameisenkönigin (Queen / Orchestrator).

Verteilt Aufgaben in Phasen an die Arbeiter-Ameisen, dispatcht Agenten-
Gruppen parallel (asyncio), sammelt Findings zentral im Store, dedupliziert
und priorisiert. Erzwingt vor jeder aktiven Phase das Oversight-Gate und
prüft jedes Asset gegen die Scope-Allowlist.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import config as config_mod
from . import llm as llm_mod
from . import netutil as net_mod
from . import router as router_mod
from . import scope as scope_mod
from . import proofgate as proofgate_mod
from . import registry as registry_mod
from .agents import WORKER_AGENTS
from .agents.base import AgentContext, AgentFinding, Task
from .oversight import require_oversight
from .store import Store

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Reihenfolge der Phasen in der Kill-Chain.
PHASES = ("recon", "scan", "verify", "analyze", "report")


@dataclass
class SwarmResult:
    run_id: str
    target_id: int
    target_name: str
    findings: list[AgentFinding] = field(default_factory=list)
    phase_log: list[str] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    #: Proof-Gate-Validierungsreport (downgrades, false-positives, violations).
    validation: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def by_severity(self) -> dict[str, int]:
        # Single Source of Truth: aus der Finding-Liste, ohne False-Positives.
        return proofgate_mod.severity_counts(self.findings)

    def by_status(self) -> dict[str, int]:
        return proofgate_mod.status_counts(self.findings)


class Queen:
    """Orchestriert den Ameisen-Schwarm."""

    def __init__(self, store: Store, logger: Optional[logging.Logger] = None,
                 emit: Optional[Callable[[dict], None]] = None,
                 llm_provider: Optional[str] = None,
                 use_llm: bool = True,
                 ask_user: Optional[Callable[[object], str]] = None):
        self.store = store
        self.logger = logger or logging.getLogger("antbb.queen")
        self.emit = emit
        # Capability-Registry FRISCH aufbauen und ins Königin-Gedächtnis legen
        # (Single Source of Truth, aktualisiert sich bei jedem Start automatisch).
        try:
            reg = registry_mod.persist_registry(self.store)
            self.logger.info(
                "👑 Capability-Registry aktualisiert: %d Soldaten, %d Playbooks, "
                "%d Tools (im Königin-Gedächtnis).",
                reg.get("soldier_count", 0), reg.get("playbook_count", 0),
                reg.get("tool_count", 0))
        except Exception as exc:  # Registry darf den Schwarm nie blockieren
            self.logger.warning("👑 Registry-Aufbau fehlgeschlagen: %s", exc)
        #: Hook für Nutzer-Rückfragen bei kritischen Router-Entscheidungen.
        #: None → headless (Default-Option automatisch).
        self.ask_user = ask_user or router_mod.headless_ask()
        #: Optionaler LLM-Client. Fällt sauber auf None zurück, wenn kein
        #: Provider/Key konfiguriert ist – dann läuft alles wie bisher.
        self.llm = None
        if use_llm:
            try:
                client = llm_mod.LLMClient(llm_provider)
                if client.configured:
                    self.llm = client
            except Exception:  # defensiv: LLM darf den Schwarm nie blockieren
                self.llm = None

    # ---- Phasen-Planung: welche Agenten-Klassen gehören zu welcher Phase ----
    def _agents_for_phase(self, phase: str, ctx: AgentContext):
        return [cls(ctx) for cls in WORKER_AGENTS if phase in cls.phases]

    async def run_swarm(self, target_id: int, phases: tuple[str, ...] = PHASES,
                         active: bool = False, fuzz: bool = False) -> SwarmResult:
        """Startet den Schwarm für ein Target. Erzwingt Oversight + Scope.

        `active` schaltet die TIEFE, aktive Verifikations-Phase frei. Default
        False → rein passives Verhalten wie bisher. Greift nur zusätzlich zum
        Oversight-Häkchen; der Scope-Gate bleibt unverändert.

        `fuzz` schaltet kontrolliertes offensives Fuzzing (Content-Discovery)
        frei – eigener Schalter, unabhängig von `active`. Default False.
        """
        target = self.store.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} existiert nicht.")

        # HARTES GATE: ohne Häkchen kein Scan.
        require_oversight(self.store, target_id)

        run_id = uuid.uuid4().hex[:12]
        result = SwarmResult(
            run_id=run_id, target_id=target_id, target_name=target["name"],
            started_at=time.time(),
        )

        def _emit(ev: dict) -> None:
            ev = {**ev, "run_id": run_id, "target_id": target_id}
            result.phase_log.append(ev.get("msg", ""))
            if self.emit:
                self.emit(ev)

        def _scope_check(asset: str) -> bool:
            return bool(scope_mod.check_asset(self.store, target_id, asset))

        def _route(task_type, complexity=0.0):
            return router_mod.route(task_type, complexity, ask_user=self.ask_user)

        # Scope- und ratengebundener Netzwerk-Client: ALLE echten Requests der
        # Agenten laufen hierüber; jeder Zugriff wird gegen den Scope geprüft.
        net = net_mod.NetClient(
            scope_check=_scope_check, cfg=config_mod.scan_config(),
            logger=self.logger, emit=_emit,
        )
        self._net = net

        # Aktive Verifikation / Fuzzing nur, wenn Config-Schalter ODER expliziter
        # Aufruf-Flag es erlaubt. Default (beides aus) → passives Verhalten.
        # scan_config() einmal laden (Env-Overrides inklusive).
        scfg = config_mod.scan_config()
        cfg_active = bool(getattr(scfg, "active_verification", False))
        effective_active = bool(active or cfg_active)
        cfg_fuzz = bool(getattr(scfg, "fuzz_enabled", False))
        effective_fuzz = bool(fuzz or cfg_fuzz)

        try:
            soldier_overrides = self.store.all_soldier_overrides()
            soldier_mems = self.store.all_soldier_mems()
        except Exception:
            soldier_overrides, soldier_mems = {}, {}

        ctx = AgentContext(
            run_id=run_id,
            scope_check=_scope_check,
            logger=self.logger,
            emit=_emit,
            llm=self.llm,
            route=_route,
            net=net,
            active=effective_active,
            fuzz=effective_fuzz,
            soldier_overrides=soldier_overrides,
            soldier_mems=soldier_mems,
        )

        assets = scope_mod.allowed_assets(self.store, target_id)
        ctx.log(f"👑 Königin startet Schwarm (run {run_id}) für '{target['name']}' "
                f"mit {len(assets)} In-Scope-Assets.")
        if self.llm:
            ctx.log(f"👑 LLM-Unterstützung aktiv (Provider '{self.llm.cfg.name}', "
                    f"Hauptmodell '{llm_mod.MAIN_MODEL}', Flash-Modell "
                    f"'{llm_mod.FAST_MODEL}'; Modellwahl dynamisch pro Aufgabentyp).")
        else:
            ctx.log("👑 Kein LLM konfiguriert – Agenten laufen im Fallback-Modus.")

        if effective_active:
            ctx.log("👑 AKTIVE VERIFIKATION ist freigeschaltet (autorisiert) – "
                    "die Verify-Ameise führt kontrollierte, nicht-destruktive Aktiv-Checks aus.")
        else:
            ctx.log("👑 Aktive Verifikation AUS (Default) – rein passives Verhalten; "
                    "Verify-Phase wird übersprungen.")

        try:
            pol = self.store.get_mode_policy(target_id)
        except Exception:
            pol = "auto"
        ctx.log(f"👑 mode_policy={pol} · active={effective_active} · fuzz={effective_fuzz}")

        if effective_fuzz:
            ctx.log("👑 OFFENSIVES FUZZING ist freigeschaltet (autorisiert) – "
                    "die Fuzz-Ameise führt GET-basierte Content-Discovery mit "
                    "Catch-all-Baseline aus.")
        else:
            ctx.log("👑 Offensives Fuzzing AUS (Default) – Fuzz-Ameise bleibt still.")

        collected: list[AgentFinding] = []
        for phase in phases:
            if phase == "verify" and not effective_active:
                continue
            agents = self._agents_for_phase(phase, ctx)
            if not agents:
                continue
            ctx.log(f"👑 Phase '{phase}': dispatche {len(agents)} Ameisen parallel.")
            task = Task(
                phase=phase, target_id=target_id, target_name=target["name"],
                assets=assets, context_findings=list(collected),
            )
            # Agenten-Gruppe parallel laufen lassen
            results = await asyncio.gather(*(a.run(task) for a in agents))
            phase_findings = [f for sub in results for f in sub]
            # Dedup + Persistenz zentral durch die Königin
            new = self._merge(collected, phase_findings)
            # Proof-Gate schon beim Persistieren anwenden (Status normalisieren,
            # VERIFIZIERT ohne Evidence herabstufen, Catch-all als FP markieren).
            proofgate_mod.enforce(new, self.logger)
            for f in new:
                self.store.add_finding(
                    target_id=target_id, run_id=run_id, agent=f.agent,
                    title=f.title, category=f.category, severity=f.severity,
                    asset=f.asset, description=f.description, evidence=f.evidence,
                    dedup_key=f.key(), status=f.status,
                    false_positive=f.false_positive,
                )
            ctx.log(f"👑 Phase '{phase}' abgeschlossen: +{len(new)} neue Findings "
                    f"(gesamt {len(collected)}).")

        # Scope-Blocks (abgewehrte out-of-scope Zugriffe) sichtbar machen.
        if net.blocked:
            ctx.log(f"👑 Scope-Wächter: {len(net.blocked)} out-of-scope Zugriffsversuch(e) "
                    f"blockiert und protokolliert.")
        ctx.log(f"👑 Netzwerk-Operationen gesamt (nur in-scope): {net.request_count}.")

        # HARTER Proof-Gate über den Gesamtbestand (idempotent) + Validierung.
        validation = proofgate_mod.enforce(collected, self.logger)
        if validation["downgraded"]:
            ctx.log(f"👑 Proof-Gate: {len(validation['downgraded'])} Finding(s) von "
                    f"VERIFIZIERT auf ZU BESTÄTIGEN herabgestuft (keine aktive Evidence).")
        if validation["flagged_false_positive"]:
            ctx.log(f"👑 Proof-Gate: {len(validation['flagged_false_positive'])} Catch-all-/"
                    f"Baseline-Artefakt(e) als False-Positive markiert und aus der Zählung "
                    f"ausgeschlossen.")
        if validation["violations"]:
            ctx.log(f"👑 ⚠️ Proof-Gate-VERLETZUNG: {len(validation['violations'])} Finding(s) "
                    f"behaupten VERIFIZIERT ohne Evidence – bitte prüfen.")
        else:
            ctx.log("👑 Proof-Gate OK: kein VERIFIZIERT ohne aktive Evidence.")
        result.validation = validation

        # Priorisierung
        collected.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        result.findings = collected
        result.finished_at = time.time()
        ctx.log(f"👑 Schwarm fertig in {result.duration:.2f}s. "
                f"Verteilung: {result.by_severity()} · Status: {result.by_status()}")
        return result

    @staticmethod
    def _merge(collected: list[AgentFinding], new: list[AgentFinding]) -> list[AgentFinding]:
        """Dedupliziert gegen bereits gesammelte Findings (per key)."""
        seen = {f.key() for f in collected}
        added: list[AgentFinding] = []
        for f in new:
            if f.key() in seen:
                continue
            seen.add(f.key())
            collected.append(f)
            added.append(f)
        return added

    def run_swarm_sync(self, target_id: int, phases: tuple[str, ...] = PHASES,
                        active: bool = False, fuzz: bool = False) -> SwarmResult:
        """Synchroner Wrapper für CLI."""
        return asyncio.run(self.run_swarm(target_id, phases, active=active, fuzz=fuzz))
