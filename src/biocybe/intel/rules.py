"""Import opt-in de règles YARA communautaires pour BioCybe.

Permet d'ajouter des milliers de règles YARA maintenues par la
communauté sécurité (Florian Roth / Neo23x0, YARA-Rules project, …)
sans les bundler dans la distribution BioCybe (questions de licence
+ taille + responsabilité éditoriale).

Architecture :
  - `KNOWN_SOURCES` recense les feeds (URL zipball, sous-dossier
    où les .yar vivent, licence, description).
  - `download_source(name)` télécharge le zipball GitHub et extrait
    uniquement les .yar/.yara matchant le `include_glob`.
  - `verify_source(name)` essaie de compiler chaque règle
    individuellement et retourne (ok, broken) — utile parce que
    beaucoup de règles communautaires dépendent de modules YARA
    optionnels (cuckoo, dotnet, magic) ou de fichiers `include`
    qui ne s'appliquent pas hors contexte.

Les règles téléchargées atterrissent dans `rules/yara/community/<source>/`
et sont automatiquement embarquées par `BCell` au prochain démarrage
(via `sync_yara_rules` + walk récursif).

Sécurité :
  - Téléchargements en HTTPS uniquement.
  - Limite de taille zip (50 Mo) pour éviter un zip-bomb.
  - Extraction limitée aux .yar/.yara avec path sanitization
    (anti zip-slip).
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

logger = logging.getLogger("biocybe.intel.rules")

DEFAULT_TIMEOUT_S = 120
MAX_ZIP_SIZE_BYTES = 50 * 1024 * 1024  # 50 Mo
MAX_RULE_SIZE_BYTES = 5 * 1024 * 1024  # 5 Mo par règle (très défensif)
RULE_EXTENSIONS = (".yar", ".yara")
USER_AGENT = "BioCybe/0.2 (+https://github.com/servais1983/biocybe)"


@dataclass(frozen=True)
class YaraRuleSource:
    """Une source de règles YARA externes."""

    name: str
    description: str
    zipball_url: str
    license: str
    # Chemin (préfixe) à l'intérieur du zip où chercher les règles.
    # Le préfixe initial `<repo>-<ref>/` est automatiquement ignoré.
    # `""` = racine du repo (utiliser tout le repo).
    include_subpath: str = ""
    # Glob optionnel pour limiter encore (ex. exclure les exemples).
    exclude_patterns: tuple[str, ...] = ()


# Sources curées. Ajout futur : MISP, ESET-Research, AlienVault OTX, etc.
# Toutes les sources sont OPT-IN — rien n'est téléchargé sans
# action explicite de l'utilisateur.
KNOWN_SOURCES: dict[str, YaraRuleSource] = {
    "signature-base": YaraRuleSource(
        name="signature-base",
        description=(
            "Florian Roth (Neo23x0) — ~3000 règles YARA de haute qualité, "
            "axées APT, ransomware et webshells. Très utilisé en SOC."
        ),
        # Branche par défaut "master"
        zipball_url="https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        license="CC-BY-NC-4.0 (usage non commercial OK, vérifier en cas de revente SaaS)",
        include_subpath="yara/",
        # Florian publie aussi des règles "broken" pour démonstration ;
        # on exclut les fichiers évidemment problématiques.
        exclude_patterns=("gen_powershell.yar",),  # contient parfois des chaines test
    ),
    "yara-rules": YaraRuleSource(
        name="yara-rules",
        description=(
            "YARA-Rules project — ~5000 règles communautaires triées par "
            "catégorie (malware, exploit_kits, packers, …). Qualité variable."
        ),
        zipball_url="https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
        license="GPL-2.0 (compatible avec une distribution MIT en linking dynamique)",
        include_subpath="",  # tout le repo
    ),
}


@dataclass
class DownloadResult:
    """Résultat d'un téléchargement de source."""

    source: str
    files_extracted: int
    bytes_written: int
    skipped_files: int
    output_dir: Path


@dataclass
class VerifyResult:
    """Résultat d'une vérification de compilation."""

    source: str
    rules_ok: int
    rules_broken: int
    sample_errors: list[tuple[str, str]]  # (filename, première ligne d'erreur)

    @property
    def total(self) -> int:
        return self.rules_ok + self.rules_broken


# --------------------------------------------------------------------- #
# Téléchargement & extraction
# --------------------------------------------------------------------- #

# Validation de chemin pour anti zip-slip : on n'autorise pas
# `../` ni chemin absolu dans les entrées du zip.
_UNSAFE_PATH_RE = re.compile(r"(^|/)(\.\.)(/|$)")


def _is_safe_member(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name:
        return False
    return not _UNSAFE_PATH_RE.search(name)


def _strip_repo_prefix(member_name: str) -> str:
    """`signature-base-master/yara/foo.yar` -> `yara/foo.yar`."""
    if "/" not in member_name:
        return member_name
    return member_name.split("/", 1)[1]


def _matches_include(rel_path: str, include_subpath: str) -> bool:
    if not include_subpath:
        return True
    return rel_path.startswith(include_subpath)


def _matches_exclude(filename: str, exclude_patterns: tuple[str, ...]) -> bool:
    return any(pat in filename for pat in exclude_patterns)


def download_source(
    source_name: str,
    dest_dir: Path | str = "rules/yara/community",
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    session: requests.Session | None = None,
) -> DownloadResult:
    """Télécharge une source YARA communautaire et extrait les règles.

    Args:
        source_name: clé dans `KNOWN_SOURCES`.
        dest_dir: racine où placer les règles ; un sous-dossier
            `<source_name>/` est créé dessous.
        timeout: timeout HTTP en secondes.
        session: `requests.Session` à réutiliser (optionnel).

    Returns:
        `DownloadResult` avec compteurs et chemin de sortie.

    Raises:
        KeyError: source inconnue.
        requests.HTTPError: erreur HTTP.
        zipfile.BadZipFile: archive corrompue.
        ValueError: zip trop volumineux (> MAX_ZIP_SIZE_BYTES).
    """
    if source_name not in KNOWN_SOURCES:
        raise KeyError(
            f"Source inconnue '{source_name}'. Sources disponibles : {sorted(KNOWN_SOURCES)}"
        )
    source = KNOWN_SOURCES[source_name]
    session = session or requests.Session()

    logger.info("Téléchargement de %s depuis %s", source_name, source.zipball_url)
    resp = session.get(
        source.zipball_url,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        allow_redirects=True,
    )
    resp.raise_for_status()

    content = resp.content
    if len(content) > MAX_ZIP_SIZE_BYTES:
        raise ValueError(
            f"Archive trop volumineuse ({len(content)} octets > "
            f"{MAX_ZIP_SIZE_BYTES} max). Anti zip-bomb."
        )

    output_dir = Path(dest_dir) / source_name
    output_dir.mkdir(parents=True, exist_ok=True)

    extracted = bytes_written = skipped = 0
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not _is_safe_member(info.filename):
                logger.warning("Chemin suspect ignoré : %r", info.filename)
                skipped += 1
                continue
            rel = _strip_repo_prefix(info.filename)
            if not _matches_include(rel, source.include_subpath):
                continue
            if not rel.lower().endswith(RULE_EXTENSIONS):
                continue
            if _matches_exclude(Path(rel).name, source.exclude_patterns):
                skipped += 1
                continue
            if info.file_size > MAX_RULE_SIZE_BYTES:
                logger.warning(
                    "Règle ignorée (trop grosse : %d octets) : %s",
                    info.file_size,
                    rel,
                )
                skipped += 1
                continue

            # On aplatit dans output_dir/<basename> pour éviter les conflits
            # de subdirs avec d'autres sources et faciliter le walk YARA.
            # Si plusieurs règles ont le même nom, on préfixe par leur path.
            base = Path(rel).name
            target = output_dir / base
            if target.exists():
                # Conflit de nom : préfixer par le path relatif pour
                # garder les deux versions.
                disambig = str(Path(rel).parent).replace("/", "_").replace("\\", "_") or "root"
                target = output_dir / f"{disambig}__{base}"

            data = zf.read(info)
            target.write_bytes(data)
            extracted += 1
            bytes_written += len(data)

    logger.info(
        "Source %s : %d règles extraites (%d octets), %d ignorées vers %s",
        source_name,
        extracted,
        bytes_written,
        skipped,
        output_dir,
    )

    return DownloadResult(
        source=source_name,
        files_extracted=extracted,
        bytes_written=bytes_written,
        skipped_files=skipped,
        output_dir=output_dir,
    )


# --------------------------------------------------------------------- #
# Vérification (compile chaque .yar individuellement)
# --------------------------------------------------------------------- #


def verify_source(
    source_name: str,
    dest_dir: Path | str = "rules/yara/community",
    *,
    sample_errors_limit: int = 10,
) -> VerifyResult:
    """Compile chaque règle d'une source individuellement, compte ok/cassées.

    Beaucoup de règles communautaires dépendent de modules YARA non
    standard (cuckoo, dotnet, magic) ou de fichiers `include` propres
    à leur repo d'origine ; elles ne compileront pas hors contexte.
    `BCell` les ignorera automatiquement grâce au mode tolérant
    (Phase 1) — cette fonction le confirme et donne un rapport.
    """
    # Import paresseux : yara peut ne pas être installé en mode dev minimal.
    import yara

    source_dir = Path(dest_dir) / source_name
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source non téléchargée : {source_dir}")

    ok = broken = 0
    samples: list[tuple[str, str]] = []
    for rule_file in sorted(source_dir.glob("*.yar*")):
        try:
            yara.compile(filepath=str(rule_file))
            ok += 1
        except yara.SyntaxError as exc:
            broken += 1
            if len(samples) < sample_errors_limit:
                # Garder seulement la 1re ligne de l'erreur pour rester lisible
                samples.append((rule_file.name, str(exc).splitlines()[0]))

    logger.info(
        "Source %s : %d règles OK, %d cassées (compilation tolérante).",
        source_name,
        ok,
        broken,
    )
    return VerifyResult(source=source_name, rules_ok=ok, rules_broken=broken, sample_errors=samples)


def list_sources() -> list[YaraRuleSource]:
    """Retourne la liste des sources connues."""
    return list(KNOWN_SOURCES.values())
