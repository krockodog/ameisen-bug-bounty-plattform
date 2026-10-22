"""Ameisen-Schwarm Agenten (Soldaten)."""
from .base import AntAgent, Task, AgentFinding, AgentContext, Playbook
from .recon import ReconAnt
from .scanning import ScanningAnt
from .verify import VerifyAnt
from .api import ApiAnt
from .infra import InfraAnt
from .fuzz import FuzzAnt
from .analysis import AnalysisAnt
from .poc import PocAnt
from .reporting import ReportingAnt
from .osint import OsintHunterAnt
from .cloud import CloudHunterAnt
from .auth import AuthSpecialistAnt
from .mobile import MobileHunterAnt
from .threatintel import ThreatIntelAnt
from .llmsec import LlmSecurityAnt
from .wifi import WifiHunterAnt
from .takeover import TakeoverAnt
from .codeaudit import CodeAuditAnt

#: Alle verfügbaren Arbeiter-Ameisen (ohne Königin).
WORKER_AGENTS = [
    ReconAnt, MobileHunterAnt, ScanningAnt, ApiAnt, InfraAnt, OsintHunterAnt,
    CloudHunterAnt, AuthSpecialistAnt, LlmSecurityAnt, FuzzAnt, VerifyAnt,
    AnalysisAnt, ThreatIntelAnt, PocAnt, ReportingAnt, WifiHunterAnt,
    TakeoverAnt, CodeAuditAnt,
]

__all__ = [
    "AntAgent", "Task", "AgentFinding", "AgentContext", "Playbook",
    "ReconAnt", "ScanningAnt", "VerifyAnt", "ApiAnt", "InfraAnt", "FuzzAnt",
    "AnalysisAnt", "PocAnt", "ReportingAnt", "OsintHunterAnt", "CloudHunterAnt",
    "AuthSpecialistAnt", "MobileHunterAnt", "ThreatIntelAnt", "LlmSecurityAnt", "WifiHunterAnt",
    "TakeoverAnt", "CodeAuditAnt",
    "WORKER_AGENTS",
]
