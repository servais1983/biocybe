"""Auto-régénération (self-healing) — restaure un système après une attaque.

Capacité phare bio-inspirée : après qu'un pathogène a endommagé un
tissu, l'organisme **régénère** le tissu vers son état sain. BioCybe
reproduit ce mécanisme pour les fichiers critiques.

Complète la chaîne de réponse :
  - Quarantaine : retire le fichier malveillant
  - Cellule NK : tue le processus malveillant
  - **Régénération : restaure les fichiers que l'attaque a endommagés**

Cas d'usage tueur : **ransomware**. Il chiffre les fichiers ; la
détection + NK arrêtent le process, mais les fichiers chiffrés restent
perdus. La régénération les restaure depuis une baseline protégée.

Principe (3 phases, comme un FIM avec remédiation automatique) :
  1. **Baseline** : capture l'état sain de fichiers critiques (hash
     SHA-256 + copie du contenu dans un coffre dédupliqué).
  2. **Détection de drift** : compare l'état courant à la baseline →
     fichiers modifiés / supprimés / intacts.
  3. **Heal** : restaure les fichiers modifiés/supprimés depuis le
     coffre, en vérifiant que le contenu restauré matche la baseline.

GARDE-FOUS (mêmes principes que la cellule NK) :
  - **dry-run par défaut** : `heal()` décrit sans agir tant qu'on n'a
    pas passé `dry_run=False`.
  - **Vérification d'intégrité** : le contenu restauré est re-hashé et
    comparé à la baseline avant d'être considéré valide.
  - **Écriture atomique** : tempfile + os.replace — jamais de fichier
    à moitié restauré.
  - **Caps** : taille max par fichier (baseline) + nombre max de
    fichiers restaurés par run (anti-emballement).
  - **Audit systématique** : baseline + chaque restauration journalisés.

Le coffre est stocké séparément (`db/regeneration/vault/`) ; en prod,
le monter sur un volume read-only / WORM renforce l'inviolabilité.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.regeneration")

DEFAULT_VAULT_DIR = "db/regeneration/vault"
DEFAULT_MANIFEST = "db/regeneration/baseline.json"
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 Mo / fichier baseliné
DEFAULT_MAX_HEAL_PER_RUN = 10_000  # anti-emballement


class DriftStatus(str, Enum):
    INTACT = "intact"
    MODIFIED = "modified"  # contenu changé (ransomware, tampering)
    DELETED = "deleted"  # fichier disparu


class HealAction(str, Enum):
    RESTORED = "restored"
    WOULD_RESTORE = "would_restore"  # dry-run
    SKIPPED = "skipped"  # intact, rien à faire
    FAILED = "failed"


@dataclass
class BaselineEntry:
    """État sain enregistré d'un fichier."""

    path: str
    sha256: str
    size: int
    mtime: float
    mode: int  # permissions (st_mode & 0o777)
    captured_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mtime": self.mtime,
            "mode": self.mode,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BaselineEntry:
        return cls(
            path=d["path"],
            sha256=d["sha256"],
            size=int(d["size"]),
            mtime=float(d["mtime"]),
            mode=int(d.get("mode", 0o644)),
            captured_at=d.get("captured_at", ""),
        )


@dataclass
class DriftItem:
    path: str
    status: DriftStatus
    baseline_sha256: str
    current_sha256: str | None  # None si supprimé

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status.value,
            "baseline_sha256": self.baseline_sha256,
            "current_sha256": self.current_sha256,
        }


@dataclass
class HealResult:
    path: str
    action: HealAction
    status_before: DriftStatus
    dry_run: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "action": self.action.value,
            "status_before": self.status_before.value,
            "dry_run": self.dry_run,
            "error": self.error,
        }


@dataclass
class BaselineStats:
    captured: int = 0
    skipped_too_big: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    total_bytes: int = 0


class SelfHealer:
    """Moteur d'auto-régénération basé sur une baseline d'intégrité.

    Usage :
        healer = SelfHealer()
        healer.baseline(["/etc/nginx", "/var/www/html"])   # capture l'état sain
        drift = healer.detect_drift()                       # qu'est-ce qui a changé ?
        results = healer.heal(dry_run=False)                # restaure le bon
    """

    def __init__(
        self,
        vault_dir: str | Path = DEFAULT_VAULT_DIR,
        manifest_path: str | Path = DEFAULT_MANIFEST,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_heal_per_run: int = DEFAULT_MAX_HEAL_PER_RUN,
        audit_fn=None,
    ):
        self.vault_dir = Path(vault_dir)
        self.manifest_path = Path(manifest_path)
        self.max_file_bytes = int(max_file_bytes)
        self.max_heal_per_run = int(max_heal_per_run)
        self._audit_fn = audit_fn
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, BaselineEntry] = self._load_manifest()

    # ------------------------------------------------------------------
    # Manifeste
    # ------------------------------------------------------------------

    def _load_manifest(self) -> dict[str, BaselineEntry]:
        if not self.manifest_path.exists():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return {e["path"]: BaselineEntry.from_dict(e) for e in data.get("entries", [])}
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Baseline illisible (%s) — repart de zéro", exc)
            return {}

    def _save_manifest(self) -> None:
        payload = {
            "version": 1,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        fd, tmp = tempfile.mkstemp(prefix=".baseline-", dir=str(self.manifest_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self.manifest_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Coffre (vault) — contenu sain, dédupliqué par hash
    # ------------------------------------------------------------------

    def _vault_path(self, sha256: str) -> Path:
        # Shard par préfixe pour éviter des dossiers à 1M de fichiers
        return self.vault_dir / sha256[:2] / sha256

    def _store_in_vault(self, src: Path, sha256: str) -> None:
        dst = self._vault_path(sha256)
        if dst.exists():
            return  # dédup : contenu déjà présent
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Copie atomique dans le coffre
        fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=str(dst.parent))
        os.close(fd)
        try:
            shutil.copyfile(src, tmp)
            os.replace(tmp, dst)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Phase 1 : baseline
    # ------------------------------------------------------------------

    def baseline(self, paths: list[str | Path], *, recursive: bool = True) -> BaselineStats:
        """Capture l'état sain des fichiers donnés (fichiers ou dossiers)."""
        stats = BaselineStats()
        for raw in paths:
            p = Path(raw)
            if p.is_file():
                self._baseline_one(p, stats)
            elif p.is_dir():
                it = p.rglob("*") if recursive else p.iterdir()
                for f in it:
                    if f.is_file():
                        self._baseline_one(f, stats)
            else:
                stats.errors.append(f"introuvable: {p}")
        self._save_manifest()
        self._audit(
            "regen_baseline",
            outcome="captured",
            details={"captured": stats.captured, "total_bytes": stats.total_bytes},
        )
        logger.info(
            "Baseline : %d fichiers capturés (%d octets), %d trop gros, %d erreurs",
            stats.captured,
            stats.total_bytes,
            len(stats.skipped_too_big),
            len(stats.errors),
        )
        return stats

    def _baseline_one(self, f: Path, stats: BaselineStats) -> None:
        try:
            st = f.stat()
            if st.st_size > self.max_file_bytes:
                stats.skipped_too_big.append(str(f))
                return
            sha = _sha256_file(f)
            if sha is None:
                stats.errors.append(str(f))
                return
            self._store_in_vault(f, sha)
            key = str(f.resolve())
            self._entries[key] = BaselineEntry(
                path=key,
                sha256=sha,
                size=st.st_size,
                mtime=st.st_mtime,
                mode=st.st_mode & 0o777,
                captured_at=datetime.now().isoformat(timespec="seconds"),
            )
            stats.captured += 1
            stats.total_bytes += st.st_size
        except OSError as exc:
            stats.errors.append(f"{f}: {exc}")

    # ------------------------------------------------------------------
    # Phase 2 : détection de drift
    # ------------------------------------------------------------------

    def detect_drift(self) -> list[DriftItem]:
        """Compare l'état courant à la baseline. Retourne les écarts."""
        drift: list[DriftItem] = []
        for key, entry in self._entries.items():
            p = Path(key)
            if not p.exists():
                drift.append(
                    DriftItem(key, DriftStatus.DELETED, entry.sha256, None)
                )
                continue
            cur = _sha256_file(p)
            if cur is None:
                # illisible : on traite comme drift modifié pour forcer l'attention
                drift.append(DriftItem(key, DriftStatus.MODIFIED, entry.sha256, None))
            elif cur != entry.sha256:
                drift.append(DriftItem(key, DriftStatus.MODIFIED, entry.sha256, cur))
        return drift

    def drift_summary(self) -> dict[str, Any]:
        drift = self.detect_drift()
        modified = [d for d in drift if d.status == DriftStatus.MODIFIED]
        deleted = [d for d in drift if d.status == DriftStatus.DELETED]
        return {
            "baseline_total": len(self._entries),
            "drift_total": len(drift),
            "modified": len(modified),
            "deleted": len(deleted),
            "intact": len(self._entries) - len(drift),
            "items": [d.to_dict() for d in drift],
        }

    # ------------------------------------------------------------------
    # Phase 3 : heal (régénération)
    # ------------------------------------------------------------------

    def heal(
        self,
        *,
        dry_run: bool = True,
        only_paths: list[str] | None = None,
    ) -> list[HealResult]:
        """Restaure les fichiers en drift depuis le coffre.

        En dry-run (défaut), décrit ce qui serait restauré sans agir.
        Vérifie que le contenu restauré matche la baseline (intégrité).
        """
        results: list[HealResult] = []
        drift = self.detect_drift()
        if only_paths:
            wanted = {str(Path(p).resolve()) for p in only_paths}
            drift = [d for d in drift if d.path in wanted]

        if len(drift) > self.max_heal_per_run:
            logger.warning(
                "Drift (%d) > cap heal/run (%d) — restauration tronquée par sécurité",
                len(drift),
                self.max_heal_per_run,
            )
            drift = drift[: self.max_heal_per_run]

        for item in drift:
            entry = self._entries.get(item.path)
            if entry is None:
                continue
            if dry_run:
                results.append(
                    HealResult(item.path, HealAction.WOULD_RESTORE, item.status, True)
                )
                continue
            res = self._restore_one(entry, item.status)
            results.append(res)

        executed = sum(1 for r in results if r.action == HealAction.RESTORED)
        self._audit(
            "regen_heal",
            outcome="dry_run" if dry_run else "executed",
            details={
                "candidates": len(drift),
                "restored": executed,
                "dry_run": dry_run,
            },
        )
        if not dry_run and executed:
            logger.warning("Régénération : %d fichier(s) restauré(s) depuis la baseline", executed)
        return results

    def _restore_one(self, entry: BaselineEntry, status_before: DriftStatus) -> HealResult:
        vault = self._vault_path(entry.sha256)
        if not vault.exists():
            return HealResult(
                entry.path, HealAction.FAILED, status_before, False,
                error="contenu absent du coffre",
            )
        target = Path(entry.path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Restauration atomique
            fd, tmp = tempfile.mkstemp(prefix=".heal-", dir=str(target.parent))
            os.close(fd)
            shutil.copyfile(vault, tmp)
            # Vérification d'intégrité AVANT de remplacer
            restored_hash = _sha256_file(Path(tmp))
            if restored_hash != entry.sha256:
                os.unlink(tmp)
                return HealResult(
                    entry.path, HealAction.FAILED, status_before, False,
                    error=f"intégrité KO (vault corrompu ? {restored_hash} != {entry.sha256})",
                )
            os.replace(tmp, target)
            # Restaure les permissions d'origine (best-effort)
            try:
                os.chmod(target, entry.mode)
            except OSError:
                pass
            return HealResult(entry.path, HealAction.RESTORED, status_before, False)
        except OSError as exc:
            return HealResult(entry.path, HealAction.FAILED, status_before, False, error=str(exc))

    # ------------------------------------------------------------------
    # Stats / audit
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        total_size = sum(e.size for e in self._entries.values())
        return {
            "baseline_total": len(self._entries),
            "baseline_total_bytes": total_size,
            "vault_dir": str(self.vault_dir),
            "manifest_path": str(self.manifest_path),
        }

    def _audit(self, action: str, *, outcome: str, details: dict[str, Any]) -> None:
        if self._audit_fn is not None:
            try:
                self._audit_fn(action, actor="regeneration", outcome=outcome, details=details)
                return
            except Exception as exc:
                logger.error("regen audit_fn a échoué : %s", exc)
        try:
            from ..audit import audit as _audit

            _audit(action, actor="regeneration", outcome=outcome, details=details)
        except Exception:
            pass


def _sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


__all__ = [
    "BaselineEntry",
    "BaselineStats",
    "DriftItem",
    "DriftStatus",
    "HealAction",
    "HealResult",
    "SelfHealer",
]
