"""Human-Oversight-Gate (Pflicht-Häkchen).

Harte Blockade: Kein Scan und kein Report-Export darf laufen, solange
für das betroffene Target nicht das Bestätigungs-Häkchen gesetzt ist.
"""
from __future__ import annotations

from .store import Store


class OversightError(PermissionError):
    """Wird geworfen, wenn das Pflicht-Häkchen fehlt."""


class ScopeBlocked(PermissionError):
    """Wird geworfen, wenn ein Asset nicht in-scope ist."""


OVERSIGHT_PROMPT = (
    "Ich bestätige, dass das Target autorisiert/erlaubt ist und ich zum "
    "Testen berechtigt bin."
)


def require_oversight(store: Store, target_id: int) -> None:
    """Hartes Gate. Erlaubt die Aktion nur bei gesetztem Häkchen."""
    if not store.is_confirmed(target_id):
        raise OversightError(
            "BLOCKIERT: Human-Oversight-Häkchen fehlt. Bitte zuerst bestätigen:\n"
            f'  "{OVERSIGHT_PROMPT}"'
        )
