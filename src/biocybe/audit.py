"""Audit log immuable de BioCybe — exigence compliance SOC2/ISO 27001.

Toutes les actions destructives (quarantaine, restauration, scan,
mise à jour de signatures, intel update, démarrage/arrêt API)
sont tracées dans un journal append-only au format JSONL
(une ligne JSON par événement, parseable trivialement par jq /
Splunk / Elastic).

**Tamper-evidence par chaîne de hash** : chaque ligne contient
`prev_hash` (SHA-256 de la ligne précédente). Toute modification
ou suppression d'une ligne casse la chaîne et est détectable par
`verify()`. Ce n'est PAS une garantie cryptographique d'inviolabilité
(un attaquant qui réécrit le fichier entier peut recalculer la chaîne)
— pour ça il faut un WORM storage ou un timestamp signé. Mais ça
empêche la modification opportuniste (un opérateur qui supprime sa
trace), pré-requis compliance.

Format ligne JSONL :
    {
      "seq": N,                       # entier monotone
      "ts": "2026-05-17T16:30:00",
      "actor": "biocybe.scanner",     # qui (cellule, user, api)
      "action": "quarantine_created", # quoi
      "outcome": "success",           # success | failure
      "details": { ... },             # payload libre
      "prev_hash": "<sha256 hex>",    # hash de la ligne précédente
      "self_hash": "<sha256 hex>"     # hash de cette ligne sans self_hash
    }

Sécurité runtime :
  - Open en mode "a" (append-only) avec flush immédiat (pas de buffering).
  - Permissions 600 sur le fichier (best-effort, Linux).
  - Lock fichier pour les écritures concurrentes (multi-thread).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.audit")

DEFAULT_AUDIT_LOG = "logs/audit.jsonl"
INITIAL_HASH = "0" * 64  # hash "vide" pour la 1re ligne


@dataclass
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    outcome: str
    details: dict[str, Any]
    prev_hash: str
    self_hash: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEntry:
        return cls(
            seq=int(d["seq"]),
            ts=d["ts"],
            actor=d["actor"],
            action=d["action"],
            outcome=d["outcome"],
            details=d.get("details") or {},
            prev_hash=d["prev_hash"],
            self_hash=d["self_hash"],
        )

    def to_dict_without_self_hash(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }


def _compute_self_hash(payload_without_self_hash: dict[str, Any]) -> str:
    """SHA-256 du JSON canonique (tri des clés) sans le champ self_hash."""
    canonical = json.dumps(
        payload_without_self_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Journal append-only avec chaîne de hash.

    Thread-safe : un lock protège l'écriture pour empêcher
    l'entrelacement de lignes en cas d'usage multi-thread (le daemon,
    l'API, le watcher peuvent écrire en parallèle).
    """

    def __init__(self, log_path: str | Path = DEFAULT_AUDIT_LOG):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # État interne : dernier seq + dernier hash (lus depuis disque au init)
        self._last_seq, self._last_hash = self._read_tail_state()

        # Permissions strictes best-effort (Linux/macOS surtout)
        if self.log_path.exists():
            try:
                os.chmod(self.log_path, 0o600)
            except OSError as exc:
                logger.debug("chmod 600 sur %s impossible : %s", self.log_path, exc)

    def _read_tail_state(self) -> tuple[int, str]:
        """Lit la dernière ligne du fichier pour récupérer seq et hash."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return 0, INITIAL_HASH
        # Stratégie simple : lecture complète. Pour des logs très gros
        # (>100 Mo), on pourrait seek depuis la fin. Pas le cas typique
        # d'un audit log SOC qui rotate régulièrement.
        last_line: str | None = None
        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
        except OSError as exc:
            logger.error("Audit log illisible (%s) : %s", self.log_path, exc)
            return 0, INITIAL_HASH

        if not last_line:
            return 0, INITIAL_HASH
        try:
            d = json.loads(last_line)
            return int(d["seq"]), d["self_hash"]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("Dernière ligne d'audit malformée : %s", exc)
            return 0, INITIAL_HASH

    def append(
        self,
        action: str,
        *,
        actor: str = "biocybe",
        outcome: str = "success",
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Ajoute une entrée. Retourne l'entrée (avec hash calculés).

        L'écriture est atomique côté process (lock + flush). Pas d'O_APPEND
        atomique cross-process mais multi-thread OK ; pour multi-process,
        utiliser fcntl/msvcrt (à venir si vrai besoin).
        """
        with self._lock:
            new_seq = self._last_seq + 1
            payload = {
                "seq": new_seq,
                "ts": datetime.now().isoformat(),
                "actor": actor,
                "action": action,
                "outcome": outcome,
                "details": details or {},
                "prev_hash": self._last_hash,
            }
            self_hash = _compute_self_hash(payload)
            entry_dict = {**payload, "self_hash": self_hash}

            line = json.dumps(entry_dict, ensure_ascii=False, sort_keys=True) + "\n"
            # Open/append/flush à chaque ligne — garantit que la ligne
            # est sur disque avant retour. Coût négligeable vs valeur audit.
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass  # fsync peut échouer sur certains FS (tmpfs), pas fatal

            self._last_seq = new_seq
            self._last_hash = self_hash

            return AuditEntry(
                seq=new_seq,
                ts=payload["ts"],
                actor=actor,
                action=action,
                outcome=outcome,
                details=payload["details"],
                prev_hash=payload["prev_hash"],
                self_hash=self_hash,
            )

    def read_all(self) -> list[AuditEntry]:
        """Charge toutes les entrées (utile pour audit/recherche)."""
        if not self.log_path.exists():
            return []
        out: list[AuditEntry] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    out.append(AuditEntry.from_dict(json.loads(raw)))
                except (json.JSONDecodeError, KeyError) as exc:
                    logger.warning("Ligne audit malformée ignorée : %s", exc)
        return out

    def verify(self) -> tuple[bool, list[str]]:
        """Vérifie l'intégrité de la chaîne de hash.

        Retourne (ok, errors). `errors` liste les lignes problématiques
        avec leur seq pour investigation.
        """
        errors: list[str] = []
        prev_hash = INITIAL_HASH
        expected_seq = 1

        for entry in self.read_all():
            # 1) Séquence monotone et continue
            if entry.seq != expected_seq:
                errors.append(f"seq={entry.seq} : attendu {expected_seq} (trou ou réordre)")
            # 2) prev_hash correspond
            if entry.prev_hash != prev_hash:
                errors.append(
                    f"seq={entry.seq} : prev_hash {entry.prev_hash[:12]}... "
                    f"≠ attendu {prev_hash[:12]}..."
                )
            # 3) self_hash recalculé correspond
            expected_self = _compute_self_hash(entry.to_dict_without_self_hash())
            if entry.self_hash != expected_self:
                errors.append(
                    f"seq={entry.seq} : self_hash invalide "
                    f"({entry.self_hash[:12]}... ≠ {expected_self[:12]}...)"
                )

            prev_hash = entry.self_hash
            expected_seq = entry.seq + 1

        return len(errors) == 0, errors


# Instance singleton optionnelle, branchée par cli au démarrage
_default_log: AuditLog | None = None


def get_default() -> AuditLog | None:
    return _default_log


def set_default(log: AuditLog | None) -> None:
    """Installe le log par défaut. Appelé par cli/cmd_daemon au démarrage."""
    global _default_log
    _default_log = log


def audit(
    action: str,
    *,
    actor: str = "biocybe",
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    """Wrapper pratique : si un log par défaut est installé, append.

    Sinon no-op silencieux (l'audit est OPT-IN — on n'oblige pas le
    user à activer un audit log pour utiliser BioCybe). Tolérant aux
    exceptions : ne casse JAMAIS l'opération métier.
    """
    if _default_log is None:
        return
    try:
        _default_log.append(action, actor=actor, outcome=outcome, details=details or {})
    except Exception as exc:
        logger.error("Audit log : append a échoué (%s) — opération métier OK", exc)
