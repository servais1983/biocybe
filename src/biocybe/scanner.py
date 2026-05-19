"""Scanner one-shot pour BioCybe.

Wrapper minimal autour de `BCell.scan_file_sync` qui :
  - synchronise les règles YARA livrées (`rules/yara/`) vers la base
    runtime de la cellule (`db/signatures/yara/`) ;
  - parcourt un chemin (fichier ou dossier, récursif) ;
  - retourne la liste des résultats et, optionnellement, met en
    quarantaine les fichiers détectés comme malveillants.

Utilisable depuis la CLI (`python biocybe.py scan <path>`) ou depuis les
tests d'intégration.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .isolation import DEFAULT_QUARANTINE_DIR, QuarantineEntry, quarantine_file
from .lymphocytes_b import BCell, ScanResult
from .network_sentinel import NetworkScanResult, NetworkSentinel

logger = logging.getLogger("biocybe.scanner")

DEFAULT_RULES_SRC = Path("rules/yara")
DEFAULT_RULES_DST = Path("db/signatures/yara")

# Dossiers à ignorer par défaut lors d'un scan récursif. Évite notamment
# les boucles de re-quarantaine (le dossier `quarantine/` contient les
# fichiers déjà neutralisés) et le bruit sur les artefacts internes.
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        DEFAULT_QUARANTINE_DIR,
        "db",
        "logs",
        "models",
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "node_modules",
    }
)


@dataclass
class FileVerdict:
    """Verdict pour un fichier scanné."""

    path: Path
    result: ScanResult
    quarantine: QuarantineEntry | None = None
    # En mode --dry-run, on n'agit pas mais on signale ce qu'on aurait fait.
    quarantine_dry_run: bool = False
    # Phase 3.e : IOCs réseau trouvés dans le contenu (URLs/IPs/hosts/hashes
    # référencés depuis URLhaus/ThreatFox). None si le scan réseau n'a pas
    # été activé pour ce fichier.
    network: NetworkScanResult | None = None

    @property
    def is_malicious(self) -> bool:
        if self.result.is_malicious:
            return True
        if self.network is not None and self.network.is_malicious:
            return True
        return False


def sync_yara_rules(
    src_dir: Path = DEFAULT_RULES_SRC,
    dst_dir: Path = DEFAULT_RULES_DST,
) -> int:
    """Copie les fichiers `.yar`/`.yara` de `src_dir` vers `dst_dir`.

    Une copie est faite seulement si le fichier n'existe pas à
    destination ou si la source est plus récente. Retourne le nombre
    de fichiers copiés.
    """
    src_dir = Path(src_dir)
    dst_dir = Path(dst_dir)

    if not src_dir.is_dir():
        logger.warning("Dossier de règles YARA source absent : %s", src_dir)
        return 0

    dst_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for rule_file in src_dir.rglob("*"):
        if rule_file.suffix.lower() not in (".yar", ".yara"):
            continue
        dst_file = dst_dir / rule_file.name
        if dst_file.exists() and dst_file.stat().st_mtime >= rule_file.stat().st_mtime:
            continue
        shutil.copy2(rule_file, dst_file)
        copied += 1
        logger.debug("Règle YARA synchronisée : %s -> %s", rule_file, dst_file)

    if copied:
        logger.info("%d règle(s) YARA synchronisée(s) vers %s", copied, dst_dir)
    return copied


def _iter_files(
    path: Path,
    recursive: bool = True,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Iterator[Path]:
    """Itère sur les fichiers de `path`, en excluant certains dossiers.

    L'exclusion par défaut couvre les dossiers d'artefacts BioCybe
    (quarantine/, db/, logs/) pour éviter une boucle de re-scan, et
    les dossiers fourre-tout (.git, __pycache__, node_modules, venv).
    """
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return

    if not recursive:
        for entry in path.iterdir():
            if entry.is_file():
                yield entry
        return

    # os.walk permet de couper les sous-dossiers AVANT d'y descendre.
    import os as _os

    for dirpath, dirnames, filenames in _os.walk(path):
        # Modifier dirnames en place pour éviter de descendre dans les
        # dossiers exclus (sémantique os.walk standard).
        dirnames[:] = [d for d in dirnames if d not in excluded_dirs]
        for name in filenames:
            yield Path(dirpath) / name


def scan_path(
    target: str | Path,
    *,
    recursive: bool = True,
    quarantine: bool = False,
    dry_run: bool = False,
    cell: BCell | None = None,
    sync_rules: bool = True,
    network_scan: bool = False,
    sentinel: NetworkSentinel | None = None,
    db_path: str | Path = "db/signatures",
) -> list[FileVerdict]:
    """Scanne un fichier ou un dossier, retourne la liste des verdicts.

    Args:
        target: fichier ou dossier à analyser.
        recursive: si `target` est un dossier, descendre récursivement.
        quarantine: si True, met en quarantaine les fichiers malveillants.
        dry_run: si True, n'effectue aucune action destructive (pas de
            quarantaine, pas de modification disque) — mais le verdict
            indique ce qui aurait été fait. **Obligatoire en évaluation
            SOC** : permet de valider le taux de détection et de faux
            positifs avant d'activer les actions.
        cell: BCell à réutiliser (utile pour tests). Sinon en crée une.
        sync_rules: copier `rules/yara/` -> `db/signatures/yara/` avant le scan.
        network_scan: Phase 3.e — active la NetworkSentinel qui cherche
            des IOCs réseau (URLs/IPs/hosts/hashes) dans le contenu des
            fichiers, depuis les feeds URLhaus + ThreatFox.
        sentinel: NetworkSentinel à réutiliser. Sinon, en crée une depuis
            `db_path`. Si le lookup est vide (feeds jamais importés), la
            sentinelle ne fait rien — c'est OK.
        db_path: racine des index IOC (`db/signatures/` par défaut).
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Cible introuvable : {target_path}")

    if sync_rules:
        sync_yara_rules()

    if cell is None:
        cell = BCell("cli_scanner")

    if network_scan and sentinel is None:
        sentinel = NetworkSentinel.from_db(db_path)
        if sentinel.lookup.total == 0:
            logger.warning(
                "Network scan demandé mais aucun IOC chargé. "
                "Lance d'abord : biocybe intel update"
            )

    verdicts: list[FileVerdict] = []
    for file_path in _iter_files(target_path, recursive=recursive):
        try:
            result = cell.scan_file_sync(str(file_path))
        except Exception as exc:
            logger.error("Échec du scan de %s : %s", file_path, exc)
            continue

        verdict = FileVerdict(path=file_path, result=result)

        # Scan réseau (IOCs URLs/IPs/hosts/hashes référencés)
        if sentinel is not None:
            try:
                verdict.network = sentinel.scan_file(file_path)
            except Exception as exc:
                logger.error("Échec network scan pour %s : %s", file_path, exc)

        if verdict.is_malicious and quarantine:
            if dry_run:
                verdict.quarantine_dry_run = True
                logger.info("[DRY-RUN] aurait mis en quarantaine : %s", file_path)
            else:
                reason_parts = [
                    f"yara:{m.get('rule')}" for m in result.matched_rules if m.get("rule")
                ]
                reason_parts += [
                    f"hash:{s.get('value', 'unknown')}"
                    for s in result.matched_signatures
                    if s.get("type") == "hash"
                ]
                if verdict.network and verdict.network.is_malicious:
                    reason_parts += [
                        f"ioc:{h.ioc_type}:{h.value[:60]}"
                        for h in verdict.network.iocs_found[:3]
                    ]
                reason = ", ".join(reason_parts) or "malicious"
                try:
                    verdict.quarantine = quarantine_file(
                        file_path,
                        reason=reason,
                        detected_by=cell.name,
                        extra={
                            "family": result.malware_family,
                            "severity": result.severity,
                            "network_iocs": (
                                [h.to_dict() for h in verdict.network.iocs_found]
                                if verdict.network
                                else []
                            ),
                        },
                    )
                except Exception as exc:
                    logger.error("Échec quarantaine pour %s : %s", file_path, exc)

        verdicts.append(verdict)

    return verdicts


def format_report(verdicts: list[FileVerdict]) -> str:
    """Rend un rapport texte lisible pour la CLI."""
    total = len(verdicts)
    malicious = [v for v in verdicts if v.is_malicious]

    lines = []
    lines.append("=" * 70)
    lines.append("BioCybe — rapport de scan")
    lines.append("=" * 70)
    lines.append(f"Fichiers analysés : {total}")
    lines.append(f"Menaces détectées : {len(malicious)}")
    lines.append("")

    if not malicious:
        lines.append("Aucune menace détectée.")
    else:
        lines.append("Détails des menaces :")
        lines.append("-" * 70)
        for v in malicious:
            r = v.result
            lines.append(f"  Fichier  : {v.path}")
            lines.append(f"  Famille  : {r.malware_family or 'inconnue'}")
            lines.append(f"  Sévérité : {r.severity}")
            lines.append(f"  Confiance: {r.confidence:.2f}")
            for rule in r.matched_rules:
                lines.append(f"    - règle YARA : {rule.get('rule')}")
            for sig in r.matched_signatures:
                lines.append(f"    - signature  : {sig.get('type')} = {sig.get('value', 'N/A')}")
            if v.network and v.network.is_malicious:
                for hit in v.network.iocs_found:
                    lines.append(
                        f"    - IOC réseau : {hit.ioc_type} = {hit.value} "
                        f"({hit.source}, malware={hit.malware}, conf={hit.confidence})"
                    )
            if v.quarantine:
                lines.append(f"  Quarantaine : {v.quarantine.stored_filename}")
            elif v.quarantine_dry_run:
                lines.append("  Quarantaine : [DRY-RUN — aurait été déplacé]")
            lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)
