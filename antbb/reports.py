"""Reports-Modul: 8-Schritt-Evidence-Kette, CVSS, Markdown-Export.

Report-Struktur (8-Schritt-Evidence-Kette):
  1. scope_proof     – Scope-Nachweis
  2. baseline        – Ausgangszustand
  3. observation     – Beobachtung
  4. hypothesis      – Hypothese
  5. poc             – minimaler PoC
  6. validation      – Validierung
  7. impact          – Impact
  8. report_text     – Report-Text
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

from .store import Store

CHAIN_STEPS = [
    ("scope_proof", "1. Scope-Nachweis"),
    ("baseline", "2. Ausgangszustand"),
    ("observation", "3. Beobachtung"),
    ("hypothesis", "4. Hypothese"),
    ("poc", "5. Minimaler PoC"),
    ("validation", "6. Validierung"),
    ("impact", "7. Impact"),
    ("report_text", "8. Report-Text"),
]

_SEV_FROM_CVSS = [
    (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "info"),
]


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return ""
    for threshold, label in _SEV_FROM_CVSS:
        if score >= threshold:
            return label
    return "info"


def empty_chain() -> dict:
    return {key: "" for key, _ in CHAIN_STEPS}


@dataclass
class ReportDraft:
    target_id: int
    title: str
    chain: dict = field(default_factory=empty_chain)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""

    def severity(self) -> str:
        return severity_from_cvss(self.cvss_score)


def create_report(store: Store, draft: ReportDraft) -> int:
    """Speichert einen Report (JSON im Store)."""
    chain = {**empty_chain(), **(draft.chain or {})}
    return store.add_report(
        target_id=draft.target_id, title=draft.title, chain=chain,
        cvss_score=draft.cvss_score, cvss_vector=draft.cvss_vector,
        severity=draft.severity(),
    )


def report_to_markdown(store: Store, report_id: int) -> str:
    """Rendert einen gespeicherten Report als Markdown."""
    row = store.get_report(report_id)
    if not row:
        raise ValueError(f"Report {report_id} existiert nicht.")
    target = store.get_target(row["target_id"])
    chain = json.loads(row["chain"])
    created = datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"# {row['title']}",
        "",
        f"- **Target:** {target['name'] if target else row['target_id']}",
        f"- **Report-ID:** {row['id']}",
        f"- **Erstellt:** {created} (Europe/Berlin)",
        f"- **CVSS:** {row['cvss_score'] if row['cvss_score'] is not None else 'n/a'} "
        f"({row['cvss_vector'] or 'kein Vektor'})",
        f"- **Schweregrad:** {row['severity'] or 'n/a'}",
        "",
        "## Evidence-Kette (8 Schritte)",
        "",
    ]
    for key, label in CHAIN_STEPS:
        lines.append(f"### {label}")
        lines.append("")
        lines.append(chain.get(key) or "_(leer)_")
        lines.append("")
    # Nachträge (Addenda) – angehängt, ohne das Original zu überschreiben.
    try:
        addenda = store.list_addenda(report_id)
    except Exception:
        addenda = []
    if addenda:
        lines.append("## Nachträge (Addenda)")
        lines.append("")
        for a in addenda:
            ts = a["created_at"] if "created_at" in a.keys() else 0
            tss = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"
            author = a["author"] if "author" in a.keys() else ""
            lines.append(f"- **[{tss}] {author or 'anonym'}:** {a['text']}")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("> ⚠️ Erstellt mit antbb (lokales Framework). Tests nur im "
                 "autorisierten Scope. § 202a-c StGB / CFAA beachten.")
    return "\n".join(lines)


def export_markdown(store: Store, report_id: int, out_dir: str) -> str:
    """Schreibt den Markdown-Report in eine Datei und gibt den Pfad zurück.

    HINWEIS: Das Oversight-Gate wird vom Aufrufer (service) erzwungen.
    """
    os.makedirs(out_dir, exist_ok=True)
    md = report_to_markdown(store, report_id)
    path = os.path.join(out_dir, f"report_{report_id}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return path


def export_json(store: Store, report_id: int, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    row = store.get_report(report_id)
    if not row:
        raise ValueError(f"Report {report_id} existiert nicht.")
    data = {k: row[k] for k in row.keys()}
    data["chain"] = json.loads(data["chain"])
    try:
        data["addenda"] = [{k: a[k] for k in a.keys()} for a in store.list_addenda(report_id)]
    except Exception:
        data["addenda"] = []
    try:
        data["revisions"] = [
            {"id": r["id"], "revision": r["revision"], "instruction": r["instruction"],
             "author": r["author"], "created_at": r["created_at"]}
            for r in store.list_revisions(report_id)]
    except Exception:
        data["revisions"] = []
    path = os.path.join(out_dir, f"report_{report_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return path
