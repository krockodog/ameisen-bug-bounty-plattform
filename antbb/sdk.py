"""Module-SDK: saubere, lokale Plugin-Schnittstelle für eigene Checks/Soldaten.

Nutzer legen eine Python-Datei in den Plugins-Ordner (`antbb/plugins/` bzw.
ANTBB_PLUGINS_DIR) und definieren darin eine Subklasse von `CheckPlugin`. Der
Loader findet, validiert und registriert sie – rein LOKAL, KEIN Netzwerk-Fetch,
kein Marketplace.

Vertrag (CheckPlugin):
  * Klassen-Attribute: name, version, author, description, category (Strings).
  * Methode run(context) -> list[dict|AgentFinding]: liefert Findings.
    `context` ist ein PluginContext mit scope_check(asset)->bool, log(msg),
    und den In-Scope-Assets. Plugins MÜSSEN scope_check vor Requests nutzen.
  * mode (optional): "defensive" (Default) | "offensive".

Sicherheit: ein fehlerhaftes Plugin darf den Loader nicht crashen (isoliert
geladen, Fehler werden gesammelt). Secrets werden nie aus Plugins übernommen.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

PLUGINS_DIR = os.environ.get(
    "ANTBB_PLUGINS_DIR", os.path.join(os.path.dirname(__file__), "plugins"))

# Pflicht-Metadaten, die ein gültiges Plugin deklarieren muss.
_REQUIRED_META = ("name", "version", "author", "description", "category")


@dataclass
class PluginContext:
    """Geteilter Kontext, den der Host an jedes Plugin übergibt."""
    scope_check: Callable[[str], bool] = lambda a: False
    assets: list = field(default_factory=list)
    target_id: Optional[int] = None
    logger: Optional[object] = None

    def log(self, msg: str) -> None:
        if self.logger is not None:
            try:
                self.logger.info(msg)
                return
            except Exception:
                pass


class CheckPlugin:
    """Basisklasse für alle Plugins. Subklassen setzen Metadaten + run()."""

    name: str = ""
    version: str = "0.0.0"
    author: str = ""
    description: str = ""
    category: str = "custom"
    mode: str = "defensive"   # "defensive" | "offensive"

    @classmethod
    def meta(cls) -> dict:
        return {
            "name": cls.name, "version": cls.version, "author": cls.author,
            "description": cls.description, "category": cls.category,
            "mode": getattr(cls, "mode", "defensive"),
            "class": cls.__name__,
        }

    def run(self, context: "PluginContext") -> list:
        """Von jedem Plugin implementiert. Liefert eine Liste von Findings."""
        raise NotImplementedError


@dataclass
class LoadedPlugin:
    cls: type
    meta: dict
    source: str


@dataclass
class LoadReport:
    plugins: list = field(default_factory=list)   # list[LoadedPlugin]
    errors: list = field(default_factory=list)    # list[{source, error}]

    def metas(self) -> list[dict]:
        return [p.meta for p in self.plugins]


def validate_plugin(cls) -> list[str]:
    """Prüft den CheckPlugin-Vertrag. Gibt eine Liste von Problemen (leer=ok)."""
    problems: list[str] = []
    if not (inspect.isclass(cls) and issubclass(cls, CheckPlugin) and cls is not CheckPlugin):
        return ["ist keine CheckPlugin-Subklasse"]
    for attr in _REQUIRED_META:
        val = getattr(cls, attr, "")
        if not isinstance(val, str) or not val.strip():
            problems.append(f"Metadatum '{attr}' fehlt/leer")
    if getattr(cls, "mode", "defensive") not in ("defensive", "offensive"):
        problems.append("mode muss 'defensive' oder 'offensive' sein")
    run = getattr(cls, "run", None)
    if not callable(run):
        problems.append("Methode run() fehlt")
    elif getattr(cls, "run") is CheckPlugin.run:
        problems.append("run() nicht überschrieben")
    return problems


def _load_file(path: str) -> tuple[list, list]:
    found, errors = [], []
    modname = "antbb_plugin_" + os.path.splitext(os.path.basename(path))[0]
    try:
        spec = importlib.util.spec_from_file_location(modname, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception as exc:
        return [], [{"source": path, "error": f"{type(exc).__name__}: {exc}"}]
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj is CheckPlugin or not issubclass(obj, CheckPlugin):
            continue
        if obj.__module__ != modname:  # nur im Plugin definierte Klassen
            continue
        problems = validate_plugin(obj)
        if problems:
            errors.append({"source": path, "error": "; ".join(problems),
                           "class": obj.__name__})
            continue
        found.append(LoadedPlugin(cls=obj, meta=obj.meta(), source=path))
    return found, errors


def discover_plugins(plugins_dir: Optional[str] = None) -> LoadReport:
    """Findet + validiert alle Plugins im Ordner (rekursiv eine Ebene). Lokal."""
    d = plugins_dir or PLUGINS_DIR
    report = LoadReport()
    if not os.path.isdir(d):
        return report
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        found, errors = _load_file(os.path.join(d, fn))
        report.plugins.extend(found)
        report.errors.extend(errors)
    return report


def run_plugin(cls, context: PluginContext) -> dict:
    """Führt ein Plugin isoliert aus. Fehler werden gefangen (kein Host-Crash)."""
    try:
        inst = cls()
        results = inst.run(context) or []
        norm = []
        for r in results:
            if isinstance(r, dict):
                norm.append(r)
            elif hasattr(r, "__dict__"):
                norm.append(dict(r.__dict__))
        return {"ok": True, "plugin": cls.meta()["name"],
                "findings": norm, "count": len(norm)}
    except Exception as exc:
        return {"ok": False, "plugin": getattr(cls, "name", cls.__name__),
                "error": f"{type(exc).__name__}: {exc}", "findings": [], "count": 0}


def registry_block(plugins_dir: Optional[str] = None) -> dict:
    """Kompakter Registry-Block (für die Capability-Registry der Königin)."""
    rep = discover_plugins(plugins_dir)
    return {
        "built_at": time.time(),
        "plugins_dir": plugins_dir or PLUGINS_DIR,
        "plugin_count": len(rep.plugins),
        "plugins": rep.metas(),
        "errors": rep.errors,
        "note": ("Lokale Plugins (CheckPlugin-Vertrag). Kein Netzwerk-Fetch, "
                 "kein Marketplace. Scope-Check-Pflicht im Plugin."),
    }
