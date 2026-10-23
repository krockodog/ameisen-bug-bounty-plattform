#!/usr/bin/env bash
# antbb – All-in-One: venv + deps + frische DB + Web-GUI
# Ein Befehl:  bash install-and-start.sh
# Optional interaktiv: Provider für die Orchestrierung (Key nur zur Laufzeit).
# Keys nur in lokale antbb.env (chmod 600), nie Code/Log. Enter = ohne Key.
#
# ROBUSTHEIT: KEIN globales `set -e`. Jeder optionale Schritt ist gekapselt und
# fehlertolerant – ein einzelner Fehlschlag bricht den Lauf NIE ab. Der Kernpfad
# (venv + pip requirements + Serverstart) läuft immer; nur er darf hart scheitern.
# Am Ende: ehrliche Bilanz (✓ installiert / ⚠ übersprungen / ✗ fehlgeschlagen).
set -o pipefail   # bewusst KEIN -e und KEIN -u (maximale Robustheit)

# ----------------------------------------------------------------------
# Optionale, anonyme Telemetrie (standardmäßig AUS). Nichts wird gesendet,
# solange diese URL leer ist. Setze sie selbst, wenn du anonyme Install-/
# Heartbeat-Events empfangen willst. Abschalten jederzeit: ANTBB_TELEMETRY=0.
# Payload ist minimal/anonym: {event, version, ts}. Details: README → Telemetrie.
export ANTBB_TELEMETRY_URL="${ANTBB_TELEMETRY_URL:-}"
# ----------------------------------------------------------------------

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || { printf 'FATAL: konnte nicht nach ROOT wechseln\n' >&2; exit 1; }

HOST="${ANTBB_HOST:-${ANTBB_WEB_HOST:-127.0.0.1}}"
PORT="${ANTBB_PORT:-${ANTBB_WEB_PORT:-8000}}"
URL="http://${HOST}:${PORT}/blue"
VENV="${ROOT}/.venv"
REQ="${ROOT}/requirements.txt"
DB_PATH="${ANTBB_DB:-${ROOT}/data/antbb.db}"
ENV_FILE="${ROOT}/antbb.env"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ======================================================================
# Robustheits-Helfer
# ======================================================================
# Komponenten-Bilanz (für die Schluss-Zusammenfassung).
COMP_OK=(); COMP_SKIP=(); COMP_FAIL=()
_comp_ok()   { COMP_OK+=("$1");   ok "$1"; }
_comp_skip() { COMP_SKIP+=("$1"); }
_comp_fail() { COMP_FAIL+=("$1"); warn "$1 (fahre fort)"; }

# Führt einen optionalen Schritt (Funktion) aus, fängt JEDEN Fehler ab und
# läuft weiter. So kann kein optionaler Schritt den Gesamtlauf killen.
_safe() {
  local desc="$1"; shift
  if "$@"; then
    return 0
  else
    warn "Schritt '${desc}' fehlgeschlagen (Rückgabe $?) – übersprungen, Lauf läuft weiter."
    return 0
  fi
}

# Retry mit exponentiellem Backoff. Nutzung: _retry <versuche> <basis_sek> cmd...
_retry() {
  local tries="$1" base="$2"; shift 2
  local n=1 delay
  while :; do
    if "$@"; then return 0; fi
    if [ "$n" -ge "$tries" ]; then return 1; fi
    delay=$(( base * n ))
    warn "Versuch ${n}/${tries} fehlgeschlagen – neuer Versuch in ${delay}s …"
    sleep "$delay"
    n=$((n+1))
  done
}

_have_bin() { command -v "$1" >/dev/null 2>&1; }

# ======================================================================
# Interaktive KI-Anbieter- und Fernzugriff-Abfrage (unverändert robust)
# ======================================================================
# Append KEY=value to antbb.env (mode 600). Never echoes the value.
_env_set() {
  local key="$1" val="$2"
  [ -n "$val" ] || return 0
  umask 077
  if [ -f "$ENV_FILE" ]; then
    grep -v "^[[:space:]]*${key}=" "$ENV_FILE" > "${ENV_FILE}.tmp" 2>/dev/null || true
    mv "${ENV_FILE}.tmp" "$ENV_FILE" 2>/dev/null || true
  else
    : > "$ENV_FILE"
  fi
  printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  export "${key}=${val}"
}

_read_secret() {
  local prompt="$1" entered=""
  printf '%s' "$prompt" >&2
  IFS= read -r -s entered || true
  printf '\n' >&2
  printf '%s' "$entered"
}

_prompt_provider_auth() {
  local label="$1" envvar="$2" oauth="$3"
  local choice key note
  printf '\n\033[1;36m── %s ──\033[0m\n' "$label"
  case "$oauth" in
    gui)
      printf '  Auth-Varianten:\n'
      printf '    [1] API-Schlüssel eingeben → antbb.env (chmod 600)\n'
      printf '    [2] OAuth über die Web-GUI nach dem Start\n'
      printf '        (Browser: %sauth/<provider>/login — wo verdrahtet)\n' "$URL"
      printf '    [Enter] überspringen\n' ;;
    none)
      printf '  OAuth für API-Zugang: nicht verfügbar (laut Anbieter/Config).\n'
      printf '  Auth-Varianten:\n'
      printf '    [1] API-Schlüssel eingeben → antbb.env (chmod 600)\n'
      printf '    [Enter] überspringen\n' ;;
    note:*)
      note="${oauth#note:}"
      printf '  Hinweis: %s\n' "$note"
      printf '  Auth-Varianten:\n'
      printf '    [1] API-Schlüssel eingeben → antbb.env (chmod 600)\n'
      printf '    [Enter] überspringen\n' ;;
  esac
  printf '  Wahl: '
  IFS= read -r choice || true
  case "${choice:-}" in
    1)
      if [ -z "$envvar" ]; then warn "Kein Env-Var-Name hinterlegt – übersprungen."; return 0; fi
      key="$(_read_secret "  Key für ${label} (Eingabe unsichtbar, Enter=abbrechen): ")"
      if [ -z "$key" ]; then warn "Kein Key eingegeben – ${label} übersprungen."; return 0; fi
      _env_set "$envvar" "$key"; unset key
      ok "${envvar} in antbb.env gespeichert (chmod 600) – Wert nie geloggt" ;;
    2)
      if [ "$oauth" = "gui" ]; then
        warn "OAuth: nach dem Start in der GUI anmelden (nicht hier im Terminal)."
        warn "Tokens liegen verschlüsselt in data/oauth_tokens.enc."
      else
        warn "OAuth hier nicht verfügbar – bitte Variante [1] API-Schlüssel nutzen."
      fi ;;
    *) warn "${label} übersprungen." ;;
  esac
}

_ask_providers() {
  if [ "${ANTBB_ASK_KEY:-auto}" = "0" ]; then warn "Anbieter-Abfrage übersprungen (ANTBB_ASK_KEY=0)"; return 0; fi
  if [ ! -t 0 ] && [ "${ANTBB_ASK_KEY:-}" != "1" ]; then
    warn "Kein TTY – starte ohne interaktive Key-Abfrage."
    warn "Später: bash install-and-start.sh  (mit TTY) oder antbb.env.example → antbb.env"
    return 0
  fi
  printf '\n\033[1;36mProvider für die Orchestrierung (optional, überspringbar)\033[0m\n'
  printf '  Ohne Key läuft die Kolonie. Der Router bleibt dann ohne externen Dienst.\n'
  printf '  Mehrfachauswahl möglich (z. B. 1 4 5). Enter = gar keine Anbieter.\n\n'
  printf '  [1] OpenAI\n  [2] Anthropic\n  [3] Google (Gemini)\n  [4] MiniMax          (api.minimax.io)\n'
  printf '  [5] Grok / xAI\n  [6] Kimi / Moonshot\n  [7] Ollama           (lokal, keine Auth)\n  [8] OpenCode\n  [9] Eigener Anbieter (Custom OpenAI-kompatibel)\n\n'
  printf '  Auswahl (Nummern oder Enter): '
  local sel; IFS= read -r sel || true
  if [ -z "${sel// /}" ]; then warn "Keine Anbieter gewählt – starte ohne Provider-Keys."; return 0; fi
  local n
  for n in $sel; do
    case "$n" in
      1) _prompt_provider_auth "OpenAI" "OPENAI_API_KEY" "gui" ;;
      2) _prompt_provider_auth "Anthropic" "ANTHROPIC_API_KEY" "none" ;;
      3) _prompt_provider_auth "Google Gemini" "GOOGLE_API_KEY" "none"
         if [ -z "${GOOGLE_API_KEY:-}" ] && [ -t 0 ]; then
           local g; g="$(_read_secret "  Alternativ GEMINI_API_KEY (Enter=skip): ")"
           if [ -n "$g" ]; then _env_set "GEMINI_API_KEY" "$g"; unset g; ok "GEMINI_API_KEY gespeichert"; fi
         fi ;;
      4) _prompt_provider_auth "MiniMax" "MINIMAX_API_KEY" "none" ;;
      5) _prompt_provider_auth "Grok/xAI" "XAI_API_KEY" "none" ;;
      6) _prompt_provider_auth "Kimi/Moonshot" "MOONSHOT_API_KEY" "note:Open-Platform = API-Key; kein Auth-Code-OAuth für API. Variable nur bei Eingabe." ;;
      7) printf '\n\033[1;36m── Ollama (lokal) ──\033[0m\n'
         printf '  Keine Auth nötig. Optional Base-URL (Enter = Default http://localhost:11434).\n  Base-URL: '
         local ou; IFS= read -r ou || true
         if [ -n "${ou}" ]; then _env_set "OLLAMA_BASE_URL" "$ou"; ok "OLLAMA_BASE_URL gesetzt"
         else ok "Ollama: Default http://localhost:11434 (keine Variable geschrieben)"; fi ;;
      8) _prompt_provider_auth "OpenCode" "OPENCODE_API_KEY" "none" ;;
      9) printf '\n\033[1;36m── Eigener Anbieter ──\033[0m\n'
         printf '  Base-URL (z. B. https://api.example.com/v1, Enter=skip): '
         local cu ck cm; IFS= read -r cu || true
         if [ -z "${cu}" ]; then warn "Custom übersprungen."
         else
           _env_set "CUSTOM_LLM_BASE_URL" "$cu"
           ck="$(_read_secret "  API-Key (unsichtbar, Enter=ohne Key): ")"
           if [ -n "$ck" ]; then _env_set "CUSTOM_LLM_API_KEY" "$ck"; unset ck; ok "CUSTOM_LLM_API_KEY gespeichert"; fi
           printf '  Modell-Name (Enter=skip): '; IFS= read -r cm || true
           if [ -n "${cm}" ]; then _env_set "CUSTOM_LLM_MODEL" "$cm"; ok "CUSTOM_LLM_MODEL gesetzt"; fi
           ok "Custom-Endpoint gespeichert"
         fi ;;
      *) warn "Unbekannte Auswahl: $n" ;;
    esac
  done
}

_ask_remote_access() {
  if [ "${ANTBB_ASK_REMOTE:-auto}" = "0" ]; then warn "Fernzugriff-Abfrage uebersprungen (ANTBB_ASK_REMOTE=0)"; return 0; fi
  if [ ! -t 0 ] && [ "${ANTBB_ASK_REMOTE:-}" != "1" ]; then warn "Kein TTY – Fernzugriff bleibt AUS (spaeter in der GUI waehlbar)."; return 0; fi
  printf '\n\033[1;36mFernzugriff einrichten (optional)\033[0m\n'
  printf '  Wie soll die GUI aus der Ferne erreichbar sein? (Default: Aus = nur lokal)\n'
  printf '    [0] Aus (nur 127.0.0.1)            – empfohlen fuer den Start\n'
  printf '    [1] Tailscale                      – privates Mesh-VPN, Login interaktiv\n'
  printf '    [2] Cloudflare-Tunnel              – oeffentliche URL via cloudflared\n'
  printf '  Wahl [0/1/2, Enter=0]: '
  local r; IFS= read -r r || true
  case "${r:-0}" in
    1) REMOTE_MODE="tailscale"; _safe "tailscale-install" _install_tailscale
       warn "Tailscale-Login laeuft INTERAKTIV und NICHT ueber dieses Skript:"
       printf '    sudo tailscale up        # oeffnet eine Login-URL im Browser\n'
       printf '    tailscale status         # danach pruefen\n'
       ok "Fernzugriff-Praeferenz: tailscale (kein Token im Skript/Log)" ;;
    2) REMOTE_MODE="cloudflare"; _safe "cloudflared-install" _install_cloudflared
       printf '  Cloudflare-Tunnel-Variante:\n'
       printf '    [1] Schneller Quick-Tunnel (keine Anmeldung, zufaellige *.trycloudflare.com-URL)\n'
       printf '    [2] Benannter Tunnel via Token (Token -> antbb.env, chmod 600, nie geloggt)\n'
       printf '    [Enter] nur Praeferenz setzen, spaeter in der GUI starten\n  Wahl: '
       local cfv; IFS= read -r cfv || true
       case "${cfv:-}" in
         2) local tok; tok="$(_read_secret "  CLOUDFLARE_TUNNEL_TOKEN (unsichtbar, Enter=ohne Token): ")"
            if [ -n "$tok" ]; then _env_set "CLOUDFLARE_TUNNEL_TOKEN" "$tok"; unset tok
              ok "CLOUDFLARE_TUNNEL_TOKEN in antbb.env gespeichert (chmod 600) – Wert nie geloggt"
            else warn "Kein Token eingegeben – benannter Tunnel spaeter via antbb.env/Env moeglich."; fi ;;
         1) ok "Quick-Tunnel: nach dem Start in der GUI/CLI startbar (kein Token noetig)." ;;
         *) ok "Nur Praeferenz gesetzt – Tunnel spaeter in der GUI startbar." ;;
       esac
       ok "Fernzugriff-Praeferenz: cloudflare" ;;
    *) REMOTE_MODE="off"; ok "Fernzugriff: Aus (nur lokal). Jederzeit spaeter in der GUI aenderbar." ;;
  esac
}

# ======================================================================
# System-Bootstrap (optional, idempotent, fehlertolerant)
# ======================================================================
REMOTE_MODE=""

_pm_detect() {
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf  >/dev/null 2>&1; then echo dnf
  elif command -v pacman >/dev/null 2>&1; then echo pacman
  else echo none; fi
}

_sudo_prefix() {
  if [ "$(id -u)" = "0" ]; then echo ""
  elif command -v sudo >/dev/null 2>&1; then echo "sudo"
  else echo "NONE"; fi
}

_pkg_for() {
  local pm="$1" bin="$2"
  case "$pm" in
    apt) case "$bin" in
        python3) echo python3;; venv) echo python3-venv;; pip) echo python3-pip;;
        build-essential) echo build-essential;; git) echo git;; curl) echo curl;;
        nmap) echo nmap;; iw) echo iw;; nmcli) echo network-manager;;
        ffuf) echo ffuf;; gobuster) echo gobuster;; nikto) echo nikto;;
        airmon-ng|airodump-ng|aireplay-ng|aircrack-ng) echo aircrack-ng;;
        hcxdumptool) echo hcxdumptool;; hashcat) echo hashcat;; mdk4) echo mdk4;;
        wpscan) echo wpscan;; seclists) echo seclists;; rockyou) echo wordlists;;
        *) echo "";; esac;;
    dnf) case "$bin" in
        python3) echo python3;; venv) echo python3;; pip) echo python3-pip;;
        build-essential) echo "@development-tools";; git) echo git;; curl) echo curl;;
        nmap) echo nmap;; iw) echo iw;; nmcli) echo NetworkManager;;
        aircrack-ng|airmon-ng|airodump-ng|aireplay-ng) echo aircrack-ng;;
        hashcat) echo hashcat;; nikto) echo nikto;;
        *) echo "";; esac;;
    pacman) case "$bin" in
        python3) echo python;; venv) echo python;; pip) echo python-pip;;
        build-essential) echo base-devel;; git) echo git;; curl) echo curl;;
        nmap) echo nmap;; iw) echo iw;; nmcli) echo networkmanager;;
        aircrack-ng|airmon-ng|airodump-ng|aireplay-ng) echo aircrack-ng;;
        hashcat) echo hashcat;; nikto) echo nikto;;
        *) echo "";; esac;;
  esac
}

# apt-get update einmalig (mit Retry), gecacht.
_APT_UPDATED=0
_apt_update_once() {
  [ "$_APT_UPDATED" = "1" ] && return 0
  local sp; sp="$(_sudo_prefix)"; [ "$sp" = "NONE" ] && return 1
  if _retry 3 3 bash -c "$sp env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1"; then
    _APT_UPDATED=1; return 0
  fi
  warn "apt-get update endgültig fehlgeschlagen (fahre mit Cache fort)."
  _APT_UPDATED=1; return 1
}

# Einzelnes Paket robust installieren (Retry + Backoff). Idempotent.
_install_one_pkg() {
  local sp="$1" pm="$2" pkg="$3"
  case "$pm" in
    apt)    _retry 3 4 bash -c "$sp env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '$pkg' >/dev/null 2>&1" ;;
    dnf)    _retry 3 4 bash -c "$sp dnf install -y '$pkg' >/dev/null 2>&1" ;;
    pacman) _retry 3 4 bash -c "$sp pacman -S --noconfirm --needed '$pkg' >/dev/null 2>&1" ;;
    *) return 1 ;;
  esac
}

# Generischer, gekapselter Tool-Installer: idempotent, fehlertolerant.
# Nutzung: _install_tool <logischer_bin> <menschlicher_name>
_install_tool() {
  local bin="$1" name="${2:-$1}"
  if _have_bin "$bin"; then _comp_skip "${name} (schon vorhanden)"; return 0; fi
  local pm sp pkg; pm="$(_pm_detect)"; sp="$(_sudo_prefix)"
  if [ "$pm" = "none" ]; then _comp_fail "${name} (kein Paketmanager)"; return 0; fi
  if [ "$sp" = "NONE" ]; then _comp_fail "${name} (kein root/sudo)"; return 0; fi
  pkg="$(_pkg_for "$pm" "$bin")"
  if [ -z "$pkg" ]; then _comp_fail "${name} (kein Paket für $pm)"; return 0; fi
  _apt_update_once >/dev/null 2>&1 || true
  if _install_one_pkg "$sp" "$pm" "$pkg"; then _comp_ok "${name} (apt/$pkg)"
  else _comp_fail "${name} (Paket $pkg nicht installierbar)"; fi
  return 0
}

# Spezielle Tool-Installer mit eigenen Fallbacks ------------------------
_install_tailscale() {
  if _have_bin tailscale; then _comp_skip "tailscale (schon vorhanden)"; return 0; fi
  local sp; sp="$(_sudo_prefix)"
  if [ "$sp" = "NONE" ]; then
    _comp_fail "tailscale (kein root/sudo)"
    printf '    curl -fsSL https://tailscale.com/install.sh | sh\n' >&2
    return 0
  fi
  say "Installiere Tailscale (offizielles Install-Script)"
  if _retry 3 4 bash -c "curl -fsSL --max-time 60 https://tailscale.com/install.sh | $sp sh >/dev/null 2>&1"; then
    _comp_ok "tailscale"
  else
    _comp_fail "tailscale (Install-Script fehlgeschlagen)"
  fi
  return 0
}

_install_cloudflared() {
  if _have_bin cloudflared; then _comp_skip "cloudflared (schon vorhanden)"; return 0; fi
  local sp pm; sp="$(_sudo_prefix)"; pm="$(_pm_detect)"
  if [ "$sp" = "NONE" ]; then _comp_fail "cloudflared (kein root/sudo)"; return 0; fi
  say "Installiere cloudflared (Cloudflare-Tunnel-Client)"
  if [ "$pm" = "apt" ]; then
    # Variante A: offizielles apt-Repo (mit Retry)
    if _retry 2 3 bash -c "curl -fsSL --max-time 60 https://pkg.cloudflare.com/cloudflare-main.gpg | $sp tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null 2>&1 \
         && echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | $sp tee /etc/apt/sources.list.d/cloudflared.list >/dev/null 2>&1 \
         && $sp env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 \
         && $sp env DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared >/dev/null 2>&1"; then
      _comp_ok "cloudflared (apt-Repo)"; return 0
    fi
    warn "apt-Repo fehlgeschlagen – versuche offizielles .deb-Paket (Fallback)."
    # Variante B: direktes .deb
    local arch deb; arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"; deb="/tmp/cloudflared-${arch}.deb"
    if _retry 2 3 bash -c "curl -fsSL --max-time 120 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.deb' -o '$deb' 2>/dev/null && $sp dpkg -i '$deb' >/dev/null 2>&1"; then
      rm -f "$deb"; _comp_ok "cloudflared (.deb)"; return 0
    fi
    rm -f "$deb" 2>/dev/null || true
    _comp_fail "cloudflared (apt-Repo + .deb fehlgeschlagen)"
  else
    _comp_fail "cloudflared (Auto-Install nur für apt; manuell: https://developers.cloudflare.com/cloudflared/)"
  fi
  return 0
}

# Python 3.12 robust beschaffen (deadsnakes-Fallback). Nur apt.
_ensure_python() {
  # Liefert in PY_SYS ein brauchbares Python ≥3.11; 3.12 bevorzugt.
  local best=""
  local c
  for c in python3.12 python3.13 python3.11 python3 python; do
    if _have_bin "$c"; then
      local v; v="$($c -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
      case "$v" in
        3.12|3.13|3.11) best="$c"; break ;;
        3.10|3.14|3.15) [ -z "$best" ] && best="$c" ;;
        3.*) [ -z "$best" ] && best="$c" ;;
      esac
    fi
  done
  # Wenn kein ≥3.11 da und apt+sudo verfügbar: deadsnakes-Python 3.12 versuchen.
  if [ -z "$best" ] || ! "$best" -c 'import sys;exit(0 if sys.version_info[:2]>=(3,11) else 1)' 2>/dev/null; then
    local pm sp; pm="$(_pm_detect)"; sp="$(_sudo_prefix)"
    if [ "$pm" = "apt" ] && [ "$sp" != "NONE" ] && [ "${ANTBB_SKIP_SYSTEM:-0}" != "1" ]; then
      say "Kein Python ≥3.11 gefunden – versuche Python 3.12 (deadsnakes, best effort)"
      if _retry 2 3 bash -c "$sp add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1 || $sp env DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common >/dev/null 2>&1 && $sp add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1"; then
        _apt_update_once >/dev/null 2>&1 || true
        if _install_one_pkg "$sp" apt python3.12 && _install_one_pkg "$sp" apt python3.12-venv; then
          _have_bin python3.12 && best="python3.12" && _comp_ok "python3.12 (deadsnakes)"
        fi
      fi
      [ "$best" = "python3.12" ] || _comp_fail "python3.12 (deadsnakes nicht verfügbar)"
    fi
  fi
  [ -z "$best" ] && best="$(command -v python3 || command -v python)"
  PY_SYS="$best"
}

_system_bootstrap() {
  if [ "${ANTBB_SKIP_SYSTEM:-0}" = "1" ]; then
    warn "System-Bootstrap übersprungen (ANTBB_SKIP_SYSTEM=1) – nur Python/Web."
    return 0
  fi
  local pm sp; pm="$(_pm_detect)"; sp="$(_sudo_prefix)"
  if [ "$pm" = "none" ]; then
    warn "Kein unterstützter Paketmanager (apt/dnf/pacman) – System-Bootstrap übersprungen."
    warn "Installiere manuell: python3 python3-venv python3-pip build-essential git curl"
    return 0
  fi
  say "System-Bootstrap (Paketmanager: $pm, Rechte: ${sp:-root})"
  if [ "$sp" = "NONE" ]; then
    warn "Weder root noch sudo – optionale System-Pakete werden übersprungen (Hinweise folgen)."
  fi

  # Basis-Build-Voraussetzungen (best effort, idempotent, fehlertolerant).
  local b
  for b in python3 venv pip build-essential git curl; do
    case "$b" in
      venv) python3 -c 'import venv' >/dev/null 2>&1 && { _comp_skip "python3-venv (vorhanden)"; continue; } ;;
      pip)  (_have_bin pip3 || _have_bin pip) && { _comp_skip "python3-pip (vorhanden)"; continue; } ;;
      build-essential) (_have_bin cc || _have_bin gcc) && { _comp_skip "build-essential (vorhanden)"; continue; } ;;
    esac
    _safe "install-$b" _install_tool "$b" "$b"
  done

  # Diese Ausgabe ist die Verteidigungs-Kolonie. Keine Angriffs-Werkzeuge.
  if [ "${ANTBB_FULL:-0}" = "1" ]; then
    warn "ANTBB_FULL installiert hier keine Angriffs-Werkzeuge und keine Wortlisten."
  fi
}

_install_wordlists_seclists() {
  if [ -d /usr/share/seclists ]; then _comp_skip "seclists (vorhanden)"; return 0; fi
  _install_tool seclists "seclists"
}
_install_wordlists_rockyou() {
  local rk=/usr/share/wordlists/rockyou.txt
  if [ -f "$rk" ]; then _comp_skip "rockyou (vorhanden)"; return 0; fi
  # apt-Paket 'wordlists' liefert rockyou.txt.gz → entpacken (Fallback).
  _install_tool rockyou "rockyou/wordlists"
  if [ -f "${rk}.gz" ] && [ ! -f "$rk" ]; then
    local sp; sp="$(_sudo_prefix)"; [ "$sp" = "NONE" ] || _safe "gunzip-rockyou" bash -c "$sp gunzip -kf '${rk}.gz' >/dev/null 2>&1"
  fi
  return 0
}

# ======================================================================
# LAUF
# ======================================================================
_safe "system-bootstrap" _system_bootstrap

# --- Python robust beschaffen/auswählen ---
PY_SYS=""
_safe "ensure-python" _ensure_python
if [ -z "${PY_SYS:-}" ] || ! _have_bin "${PY_SYS:-__none__}"; then
  if _have_bin python3; then PY_SYS=python3
  elif _have_bin python; then PY_SYS=python
  else die "Python 3 fehlt und konnte nicht installiert werden. Bitte python3 (>=3.11) installieren."; fi
fi
PY_VER="$($PY_SYS -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo '?')"
say "Python ${PY_VER} wird verwendet ($PY_SYS)"
case "$PY_VER" in
  3.11|3.12|3.13) ok "Python-Version geeignet." ;;
  3.14*|3.15*) warn "Python ${PY_VER}: FastAPI/pydantic könnten fehlen. Empfohlen: 3.11–3.13." ;;
  3.10) warn "Python 3.10: läuft meist, empfohlen ist 3.11–3.13." ;;
  *) warn "Python-Version ${PY_VER} ungetestet – fahre fort." ;;
esac

# Bestehende antbb.env laden (falls vorhanden)
if [ -f "$ENV_FILE" ]; then
  say "Lade lokale antbb.env"
  set -a; . "$ENV_FILE" 2>/dev/null || warn "antbb.env konnte nicht vollständig geladen werden."; set +a
  ok "antbb.env geladen (Werte werden nicht geloggt)"
fi

_safe "ask-providers" _ask_providers
_safe "ask-remote"    _ask_remote_access

# --- venv (KERN, mit Retry) ---
CORE_OK=0
if [ ! -x "${VENV}/bin/python" ]; then
  say "Lege virtuelle Umgebung an: ${VENV}"
  if _retry 2 2 "$PY_SYS" -m venv "$VENV"; then ok "venv erstellt"
  else die "venv konnte nicht erstellt werden (python3-venv installieren?)"; fi
else
  ok "venv vorhanden – wiederverwendet"
fi
PY="${VENV}/bin/python"; PIP="${VENV}/bin/pip"

[ -f "$REQ" ] || die "requirements.txt fehlt"
say "Installiere Abhängigkeiten (pip install -r requirements.txt) …"
_safe "pip-upgrade" "$PIP" install --retries 5 --timeout 60 --upgrade pip setuptools wheel
if _retry 3 5 "$PIP" install --retries 5 --timeout 60 -r "$REQ"; then
  ok "Abhängigkeiten installiert"
else
  warn "pip install hatte Probleme – prüfe, ob der Kern trotzdem importierbar ist …"
fi

# Kern-Verifikation: lässt sich die Web-App importieren?
if "$PY" -c 'import fastapi, uvicorn; import antbb.web.app' >/dev/null 2>&1; then
  CORE_OK=1; ok "Kern-Importe (fastapi/uvicorn/antbb.web.app) OK"
else
  warn "Kern-Importe fehlgeschlagen – versuche pip-Install erneut (letzter Versuch)…"
  _safe "pip-retry" "$PIP" install --retries 5 --timeout 60 -r "$REQ"
  if "$PY" -c 'import fastapi, uvicorn; import antbb.web.app' >/dev/null 2>&1; then
    CORE_OK=1; ok "Kern-Importe nach Wiederholung OK"
  else
    CORE_OK=0; warn "Kern-Importe weiterhin fehlgeschlagen."
  fi
fi

# Optionale Telemetrie
if [ -n "${ANTBB_TELEMETRY_URL:-}" ] && [ "${ANTBB_TELEMETRY:-1}" != "0" ]; then
  warn "Optionale anonyme Telemetrie an ${ANTBB_TELEMETRY_URL} ist AN – abschaltbar via ANTBB_TELEMETRY=0."
  "$PY" -c "from antbb import telemetry; telemetry.send_telemetry('install')" >/dev/null 2>&1 || true
else
  ok "Optionale anonyme Telemetrie ist AUS (keine ANTBB_TELEMETRY_URL) – nichts wird gesendet."
fi

# Frische DB (fehlertolerant)
mkdir -p "${ROOT}/data/exports" 2>/dev/null || true
export ANTBB_DB="$DB_PATH"
say "Initialisiere SQLite-DB: ${DB_PATH}"
if "$PY" - <<'PY' 2>/dev/null
import os
from pathlib import Path
db = Path(os.environ.get("ANTBB_DB", "data/antbb.db"))
db.parent.mkdir(parents=True, exist_ok=True)
from antbb.store import Store
Store(str(db))
print("DB ready:", db)
PY
then ok "DB bereit (Schema vorhanden)"
else warn "DB-Init meldete einen Fehler – Server versucht trotzdem zu starten."; fi

# Fernzugriff-Präferenz speichern (fehlertolerant)
if [ -n "${REMOTE_MODE:-}" ]; then
  if "$PY" -m antbb --db "$DB_PATH" --no-banner remote set "$REMOTE_MODE" >/dev/null 2>&1; then
    ok "Fernzugriff-Praeferenz gespeichert: ${REMOTE_MODE}"
  else
    warn "Fernzugriff-Praeferenz konnte nicht gespeichert werden (spaeter in der GUI waehlbar)."
  fi
fi

if [ -z "${MINIMAX_API_KEY:-}${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${GOOGLE_API_KEY:-}${GEMINI_API_KEY:-}${XAI_API_KEY:-}${MOONSHOT_API_KEY:-}${OPENCODE_API_KEY:-}${CUSTOM_LLM_API_KEY:-}" ]; then
  warn "Kein Provider-Key gesetzt – die Kolonie startet ohne externen Dienst."
else
  ok "Mindestens ein Provider-Key gesetzt (nur Laufzeit, nicht geloggt)"
fi

# ======================================================================
# ZUSAMMENFASSUNG
# ======================================================================
_summary() {
  printf '\n\033[1;36m====================  INSTALLATIONS-BILANZ  ====================\033[0m\n'
  local x
  if [ "${#COMP_OK[@]}" -gt 0 ]; then
    for x in "${COMP_OK[@]}"; do printf '  \033[1;32m✓ installiert\033[0m   %s\n' "$x"; done
  fi
  if [ "${#COMP_SKIP[@]}" -gt 0 ]; then
    for x in "${COMP_SKIP[@]}"; do printf '  \033[1;33m⚠ übersprungen\033[0m %s\n' "$x"; done
  fi
  if [ "${#COMP_FAIL[@]}" -gt 0 ]; then
    for x in "${COMP_FAIL[@]}"; do printf '  \033[1;31m✗ fehlgeschlagen\033[0m %s\n' "$x"; done
  fi
  printf '\033[1;36m----------------------------------------------------------------\033[0m\n'
  if [ "$CORE_OK" = "1" ]; then
    printf '  \033[1;32m✓ KERN (Web-UI): funktionsfähig – Start folgt.\033[0m\n'
  else
    printf '  \033[1;31m✗ KERN (Web-UI): NICHT importierbar. Server-Start wird versucht, kann aber scheitern.\033[0m\n'
  fi
  if [ "${#COMP_FAIL[@]}" -gt 0 ]; then
    printf '  Hinweis: fehlgeschlagene optionale Tools lassen die Plattform laufen;\n'
    printf '           betroffene Funktionen bleiben ehrlich inaktiv (kein Fake).\n'
  fi
  printf '\033[1;36m================================================================\033[0m\n\n'
}
_summary

if [ "$CORE_OK" != "1" ]; then
  warn "Kernstart ist unsicher (Importe fehlten). Prüfe Netzwerk/pip und starte das Skript erneut."
fi

say "Starte antbb Web-GUI"
printf '\n  \033[1;32mStartseite:  %s\033[0m\n' "$URL"
printf '  Stoppen:     Ctrl+C\n'
printf '  Port ändern: ANTBB_PORT=1001 bash install-and-start.sh\n\n'

( sleep 1.5
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 || true
  elif command -v termux-open-url >/dev/null 2>&1; then termux-open-url "$URL" || true
  fi ) &

export ANTBB_HOST="$HOST" ANTBB_PORT="$PORT" ANTBB_WEB_HOST="$HOST" ANTBB_WEB_PORT="$PORT"
exec "$PY" -m uvicorn antbb.web.app:app --host "$HOST" --port "$PORT"
