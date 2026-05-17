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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

from .isolation import QuarantineEntry, quarantine_file
from .lymphocytes_b import BCell, ScanResult

logger = logging.getLogger("biocybe.scanner")

DEFAULT_RULES_SRC = Path("rules/yara")
DEFAULT_RULES_DST = Path("db/signatures/yara")


@dataclass
class FileVerdict:
    """Verdict pour un fichier scanné."""
    path: Path
    result: ScanResult
    quarantine: Optional[QuarantineEntry] = None

    @property
    def is_malicious(self) -> bool:
        return self.result.is_malicious


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


def _iter_files(path: Path, recursive: bool = True) -> Iterator[Path]:
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return
    iterator = path.rglob("*") if recursive else path.iterdir()
    for entry in iterator:
        if entry.is_file():
            yield entry


def scan_path(
    target: str | Path,
    *,
    recursive: bool = True,
    quarantine: bool = False,
    cell: Optional[BCell] = None,
    sync_rules: bool = True,
) -> List[FileVerdict]:
    """Scanne un fichier ou un dossier, retourne la liste des verdicts.

    Args:
        target: fichier ou dossier à analyser.
        recursive: si `target` est un dossier, descendre récursivement.
        quarantine: si True, met en quarantaine les fichiers malveillants.
        cell: BCell à réutiliser (utile pour tests). Sinon en crée une.
        sync_rules: copier `rules/yara/` -> `db/signatures/yara/` avant le scan.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Cible introuvable : {target_path}")

    if sync_rules:
        sync_yara_rules()

    if cell is None:
        cell = BCell("cli_scanner")

    verdicts: List[FileVerdict] = []
    for file_path in _iter_files(target_path, recursive=recursive):
        try:
            result = cell.scan_file_sync(str(file_path))
        except Exception as exc:
            logger.error("Échec du scan de %s : %s", file_path, exc)
            continue

        verdict = FileVerdict(path=file_path, result=result)

        if result.is_malicious and quarantine:
            reason_parts = [
                f"yara:{m.get('rule')}" for m in result.matched_rules if m.get("rule")
            ]
            reason_parts += [
                f"hash:{s.get('value', 'unknown')}"
                for s in result.matched_signatures
                if s.get("type") == "hash"
            ]
            reason = ", ".join(reason_parts) or "malicious"
            try:
                verdict.quarantine = quarantine_file(
                    file_path,
                    reason=reason,
                    detected_by=cell.name,
                    extra={"family": result.malware_family, "severity": result.severity},
                )
            except Exception as exc:
                logger.error("Échec quarantaine pour %s : %s", file_path, exc)

        verdicts.append(verdict)

    return verdicts


def format_report(verdicts: List[FileVerdict]) -> str:
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
            if v.quarantine:
                lines.append(f"  Quarantaine : {v.quarantine.stored_filename}")
            lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)
