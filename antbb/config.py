"""Konfigurations-Loader für antbb.

Lädt die Standard-Konfiguration aus ``config/default.yaml`` (relativ zum
Projekt-Root) und erlaubt gezielte Overrides über Umgebungsvariablen.
Wird beim Start von CLI und Webserver (lazy, beim ersten Zugriff) geladen,
da das Framework kein dauerhaft laufender Prozess ist – die Werte werden
also bei jedem Start frisch gelesen.

Diese Datei und die YAML enthalten NIEMALS API-Key-Werte; Keys kommen
ausschließlich aus Umgebungsvariablen (siehe ``llm.key_env``).
"""
from __future__ import annotations

import os
import pathlib
from functools import lru_cache
from typing import Any

#: Projekt-Root = Verzeichnis oberhalb des Packages ``antbb``.
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CONFIG_PATH = _ROOT / "config" / "default.yaml"
#: Verzeichnis für lokale Daten (DB, Exports, verschlüsselter Token-Store).
DATA_DIR = _ROOT / "data"

#: Fallback, falls die YAML fehlt – hält das Framework lauffähig.
_FALLBACK: dict[str, Any] = {
    "llm": {
        "provider": "minimax",
        "base_url": "https://api.minimax.io/v1",
        "key_env": "MINIMAX_API_KEY",
        "main_model": "MiniMax-M3",
        "fast_model": "MiniMax-M3.1-Flash",
    },
}


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    """Liest die YAML-Config (einmal pro Prozess gecached)."""
    data: dict[str, Any] = {}
    try:
        import yaml
        if _CONFIG_PATH.is_file():
            with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
    except Exception:
        data = {}
    # mit Fallback mischen (flach pro Top-Level-Key)
    merged: dict[str, Any] = {}
    for key, default_val in _FALLBACK.items():
        got = data.get(key) if isinstance(data, dict) else None
        if isinstance(default_val, dict):
            m = dict(default_val)
            if isinstance(got, dict):
                m.update({k: v for k, v in got.items() if v is not None})
            merged[key] = m
        else:
            merged[key] = got if got is not None else default_val
    return merged


def llm_config() -> dict[str, Any]:
    """LLM-Teil der Config mit Env-Overrides.

    Env-Overrides (optional):
      ANTBB_LLM_PROVIDER, ANTBB_LLM_BASE_URL, ANTBB_LLM_KEY_ENV,
      ANTBB_MAIN_MODEL, ANTBB_FAST_MODEL
    """
    cfg = dict(load_config().get("llm", {}))
    env_map = {
        "provider": "ANTBB_LLM_PROVIDER",
        "base_url": "ANTBB_LLM_BASE_URL",
        "key_env": "ANTBB_LLM_KEY_ENV",
        "main_model": "ANTBB_MAIN_MODEL",
        "fast_model": "ANTBB_FAST_MODEL",
    }
    for field, env in env_map.items():
        val = os.environ.get(env)
        if val and val.strip():
            cfg[field] = val.strip()
    return cfg


def scan_config():
    """Lädt den `scan`-Abschnitt und liefert eine `ScanConfig`-Instanz.

    Fällt auf dokumentierte Defaults zurück, wenn die YAML den Abschnitt nicht
    enthält. Env-Overrides: ANTBB_SCAN_MAX_RPS, ANTBB_SCAN_DELAY.
    """
    from .netutil import ScanConfig
    raw: dict = {}
    try:
        import yaml
        if _CONFIG_PATH.is_file():
            with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
                raw = (yaml.safe_load(fh) or {}).get("scan", {}) or {}
    except Exception:
        raw = {}
    recon = raw.get("recon", {}) or {}
    scanner = raw.get("scanner", {}) or {}
    cfg = ScanConfig()
    if "max_rps_per_host" in raw:
        cfg.max_rps_per_host = float(raw["max_rps_per_host"])
    if "request_delay" in raw:
        cfg.request_delay = float(raw["request_delay"])
    if "http_timeout" in raw:
        cfg.http_timeout = float(raw["http_timeout"])
    if raw.get("user_agent"):
        cfg.user_agent = str(raw["user_agent"])
    if "verify_tls" in raw:
        cfg.verify_tls = bool(raw["verify_tls"])
    if "enable_portscan" in recon:
        cfg.enable_portscan = bool(recon["enable_portscan"])
    if recon.get("ports"):
        cfg.ports = list(recon["ports"])
    if "port_timeout" in recon:
        cfg.port_timeout = float(recon["port_timeout"])
    if "dns_timeout" in recon:
        cfg.dns_timeout = float(recon["dns_timeout"])
    if recon.get("subdomain_wordlist"):
        cfg.subdomain_wordlist = list(recon["subdomain_wordlist"])
    if scanner.get("paths"):
        cfg.paths = list(scanner["paths"])
    if scanner.get("reflect_param"):
        cfg.reflect_param = str(scanner["reflect_param"])
    # ── Aktive Verifikation (Default: AUS) ──
    av = raw.get("active_verification", {}) or {}
    if "enabled" in av:
        cfg.active_verification = bool(av["enabled"])
    if "max_payloads_per_param" in av:
        cfg.av_max_payloads_per_param = int(av["max_payloads_per_param"])
    if "time_based_threshold" in av:
        cfg.av_time_based_threshold = float(av["time_based_threshold"])
    if "time_based_delay" in av:
        cfg.av_time_based_delay = int(av["time_based_delay"])
    if "time_based_attempts" in av:
        cfg.av_time_based_attempts = int(av["time_based_attempts"])
    if av.get("checks"):
        cfg.av_checks = list(av["checks"])
    if av.get("param_candidates"):
        cfg.av_param_candidates = list(av["param_candidates"])
    if av.get("redirect_param_candidates"):
        cfg.av_redirect_param_candidates = list(av["redirect_param_candidates"])
    if av.get("file_param_candidates"):
        cfg.av_file_param_candidates = list(av["file_param_candidates"])
    if av.get("ssrf_param_candidates"):
        cfg.av_ssrf_param_candidates = list(av["ssrf_param_candidates"])
    if "ssrf_max_params" in av:
        cfg.av_ssrf_max_params = int(av["ssrf_max_params"])
    # Env-Override: ANTBB_ACTIVE_VERIFICATION=1/0 (hat Vorrang vor YAML)
    env_av = os.environ.get("ANTBB_ACTIVE_VERIFICATION")
    if env_av is not None and env_av.strip() != "":
        cfg.active_verification = env_av.strip() not in ("0", "false", "False", "no", "")
    # ── Offensives Fuzzing (Default: AUS) ──
    fz = raw.get("fuzz", {}) or {}
    if "enabled" in fz:
        cfg.fuzz_enabled = bool(fz["enabled"])
    if "max_requests" in fz:
        cfg.fuzz_max_requests = int(fz["max_requests"])
    if "baseline_samples" in fz:
        cfg.fuzz_baseline_samples = int(fz["baseline_samples"])
    if "length_tolerance" in fz:
        cfg.fuzz_length_tolerance = int(fz["length_tolerance"])
    if "similarity_threshold" in fz:
        cfg.fuzz_similarity_threshold = float(fz["similarity_threshold"])
    if "catchall_min_samples" in fz:
        cfg.catchall_min_samples = int(fz["catchall_min_samples"])
    if fz.get("wordlist"):
        cfg.fuzz_wordlist = list(fz["wordlist"])
    if fz.get("param_candidates"):
        cfg.fuzz_param_candidates = list(fz["param_candidates"])
    if fz.get("param_markers"):
        cfg.fuzz_param_markers = list(fz["param_markers"])
    # Env-Override: ANTBB_FUZZ=1/0 (hat Vorrang vor YAML; unabhängig von --active)
    env_fz = os.environ.get("ANTBB_FUZZ")
    if env_fz is not None and env_fz.strip() != "":
        cfg.fuzz_enabled = env_fz.strip() not in ("0", "false", "False", "no", "")
    # Env-Overrides
    if os.environ.get("ANTBB_SCAN_MAX_RPS"):
        try:
            cfg.max_rps_per_host = float(os.environ["ANTBB_SCAN_MAX_RPS"])
        except ValueError:
            pass
    if os.environ.get("ANTBB_SCAN_DELAY"):
        try:
            cfg.request_delay = float(os.environ["ANTBB_SCAN_DELAY"])
        except ValueError:
            pass
    return cfg
