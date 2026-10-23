"""Die Blaue Königin (Blue Queen / Verteidigungs-Orchestrator).

Pendant zur offensiven Königin, aber DEFENSIV: plant und dispatcht die Blue-
Team-Soldaten in Phasen (Assess → Watch → Harden → Defend → Remediate → Verify),
sammelt Findings zentral, wendet den Proof-Gate an und belegt Remediations
„nachweislich geschlossen". Human-Oversight-gated und scope-gebunden wie der
Rest der Plattform.

Standard-Verhalten: rein lesend/non-destruktiv. Aktive/verändernde Schritte
(Fix-Apply, Honeypot-Start) laufen NUR über das Oversight-Gate.
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
from .agents.base import AgentContext, AgentFinding, Task
from .agents.blue import BLUE_AGENTS, BLUE_PHASES
from .active_oversight import enforce_active_oversight
from .store import Store

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Phasen der Verteidigungs-Kolonie.
PHASES = BLUE_PHASES   # ("assess", "harden", "defend", "remediate", "verify")


@dataclass
class BlueResult:
    run_id: str
    target_id: Optional[int]
    target_name: str
    findings: list[AgentFinding] = field(default_factory=list)
    phase_log: list[str] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    validation: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def by_severity(self) -> dict:
        return proofgate_mod.severity_counts(self.findings)

    def by_status(self) -> dict:
        return proofgate_mod.status_counts(self.findings)

    def closed_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.category == "blue-remediation-verified")


class BlueQueen:
    """Orchestriert die Verteidigungs-Kolonie."""

    def __init__(self, store: Store, logger: Optional[logging.Logger] = None,
                 emit: Optional[Callable[[dict], None]] = None,
                 use_llm: bool = True):
        self.store = store
        self.logger = logger or logging.getLogger("antbb.blue_queen")
        self.emit = emit
        self.llm = None
        if use_llm:
            try:
                client = llm_mod.LLMClient()
                if client.configured:
                    self.llm = client
            except Exception:
                self.llm = None

    def _agents_for_phase(self, phase: str, ctx: AgentContext,
                           only_agents: Optional[list] = None):
        agents = [cls(ctx) for cls in BLUE_AGENTS
                  if phase in getattr(cls, "blue_phases", ())]
        if only_agents:
            want = set(only_agents)
            agents = [a for a in agents if a.name in want]
        return agents

    async def run_colony(self, target_id: Optional[int] = None,
                         phases: tuple[str, ...] = PHASES,
                         apply_fixes: bool = False,
                         oversight_ack: Optional[bool] = None,
                         params: Optional[dict] = None) -> BlueResult:
        """Startet die Verteidigungs-Kolonie.

        `target_id=None` → lokaler System-Modus (read-only Checks ohne Scope-
        Bindung an ein Target; Scope-Check erlaubt nur 'localhost'/eigene Assets).
        `apply_fixes=True` ist eine AKTIVE Aktion → hartes Oversight-Gate.
        """
        params = dict(params or {})
        params.setdefault("_store", self.store)
        target_name = "localhost (lokales System)"
        assets: list[str] = ["localhost"]
        if target_id is not None:
            target = self.store.get_target(target_id)
            if not target:
                raise ValueError(f"Target {target_id} existiert nicht.")
            target_name = target["name"]
            assets = scope_mod.allowed_assets(self.store, target_id) or ["localhost"]

        run_id = "blue-" + uuid.uuid4().hex[:10]
        result = BlueResult(run_id=run_id, target_id=target_id,
                            target_name=target_name, started_at=time.time())

        def _emit(ev: dict) -> None:
            ev = {**ev, "run_id": run_id, "target_id": target_id, "colony": "blue"}
            result.phase_log.append(ev.get("msg", ""))
            if self.emit:
                self.emit(ev)

        # Aktive Fixes = oversight-gated (default-deny). Rein lesender Lauf ungated.
        if apply_fixes:
            _log = lambda m: _emit({"ts": time.time(), "msg": m})
            enforce_active_oversight(oversight_ack,
                                     action="Blue-Queen aktiver Fix/Härtung/Honeypot-Start",
                                     log=_log)

        # Scope-Check: lokaler Modus erlaubt localhost/Monitoring/Decoy-Pseudo-Assets.
        def _scope_check(asset: str) -> bool:
            # Blue-Queen-Pseudo-Assets (lokale Checks / Monitoring / Decoys)
            # sind immer lesend erlaubt – sie treffen keine fremden Ziele.
            if asset in ("localhost", "monitoring", "decoy"):
                return True
            if target_id is None:
                return False  # default-deny für alles andere ohne Target
            return bool(scope_mod.check_asset(self.store, target_id, asset))

        def _route(task_type, complexity=0.0):
            return router_mod.route(task_type, complexity,
                                    ask_user=router_mod.headless_ask())

        net = net_mod.NetClient(scope_check=_scope_check,
                                cfg=config_mod.scan_config(),
                                logger=self.logger, emit=_emit)
        try:
            soldier_overrides = self.store.all_soldier_overrides()
            soldier_mems = self.store.all_soldier_mems()
        except Exception:
            soldier_overrides, soldier_mems = {}, {}

        ctx = AgentContext(
            run_id=run_id, scope_check=_scope_check, logger=self.logger,
            emit=_emit, llm=self.llm, route=_route, net=net,
            active=bool(apply_fixes), fuzz=False,
            soldier_overrides=soldier_overrides, soldier_mems=soldier_mems,
        )

        ctx.log(f"👑🛡 Blaue Königin startet Verteidigungs-Kolonie (run {run_id}) "
                f"für '{target_name}'.")
        ctx.log("👑🛡 Modus: " + ("AKTIVE Fixes freigegeben (Oversight)" if apply_fixes
                                   else "rein lesend/non-destruktiv (Default)") + ".")

        collected: list[AgentFinding] = []
        for phase in phases:
            agents = self._agents_for_phase(
                phase, ctx, only_agents=(params or {}).get("only_agents"))
            if not agents:
                continue
            ctx.log(f"👑🛡 Phase '{phase}': dispatche {len(agents)} Blue-Soldat(en).")
            task = Task(phase=phase, target_id=target_id or 0,
                        target_name=target_name, assets=assets,
                        params=params, context_findings=list(collected))
            results = await asyncio.gather(*(a.run(task) for a in agents),
                                           return_exceptions=True)
            phase_findings: list[AgentFinding] = []
            for sub in results:
                if isinstance(sub, Exception):
                    ctx.log(f"👑🛡 ⚠️ Soldat-Fehler in Phase '{phase}': {sub}")
                    continue
                phase_findings.extend(sub)
            new = self._merge(collected, phase_findings)
            proofgate_mod.enforce(new, self.logger)
            if target_id is not None:
                for f in new:
                    try:
                        self.store.add_finding(
                            target_id=target_id, run_id=run_id, agent=f.agent,
                            title=f.title, category=f.category, severity=f.severity,
                            asset=f.asset, description=f.description,
                            evidence=f.evidence, dedup_key=f.key(), status=f.status,
                            false_positive=f.false_positive)
                    except Exception:
                        pass
            ctx.log(f"👑🛡 Phase '{phase}' fertig: +{len(new)} Finding(s) (gesamt {len(collected)}).")

        validation = proofgate_mod.enforce(collected, self.logger)
        result.validation = validation
        collected.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        result.findings = collected
        result.finished_at = time.time()
        ctx.log(f"👑🛡 Verteidigungs-Kolonie fertig in {result.duration:.2f}s. "
                f"Findings: {len(collected)} · nachweislich geschlossen: "
                f"{result.closed_count()} · Severity: {result.by_severity()}.")
        return result

    @staticmethod
    def _merge(collected: list[AgentFinding], new: list[AgentFinding]) -> list[AgentFinding]:
        seen = {f.key() for f in collected}
        added: list[AgentFinding] = []
        for f in new:
            if f.key() in seen:
                continue
            seen.add(f.key())
            collected.append(f)
            added.append(f)
        return added

    def run_colony_sync(self, target_id: Optional[int] = None,
                        phases: tuple[str, ...] = PHASES, apply_fixes: bool = False,
                        oversight_ack: Optional[bool] = None,
                        params: Optional[dict] = None) -> BlueResult:
        return asyncio.run(self.run_colony(target_id, phases, apply_fixes=apply_fixes,
                                           oversight_ack=oversight_ack, params=params))
