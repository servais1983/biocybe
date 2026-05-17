"""Test d'intégration end-to-end : règles YARA -> scan -> quarantaine.

On utilise la chaîne EICAR (chaîne de test standard de l'industrie AV,
inoffensive) pour valider que :
  1. les règles livrées dans `rules/yara/` sont bien chargées,
  2. la BCell détecte la chaîne,
  3. la quarantaine déplace le fichier et met à jour le manifeste.

Pas besoin d'un vrai malware : EICAR est conçu pour ces tests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Chaîne EICAR reconstruite par fragments pour éviter qu'un éditeur,
# un AV de poste ou un linter ne flagge ce fichier source comme infecté.
EICAR_PARTS = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
]
EICAR_STRING = "".join(EICAR_PARTS)


@pytest.fixture
def working_dir(tmp_path, monkeypatch):
    """Crée un dossier isolé avec une copie des règles, isole CWD."""
    # On copie le dossier de règles dans tmp_path pour ne pas polluer le repo.
    rules_src = ROOT / "rules" / "yara"
    rules_dst = tmp_path / "rules" / "yara"
    rules_dst.mkdir(parents=True)
    for rule in rules_src.glob("*.yar"):
        (rules_dst / rule.name).write_bytes(rule.read_bytes())

    # On bascule CWD pour que les chemins relatifs (db/, quarantine/) tombent dans tmp_path.
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_eicar_detected_and_quarantined(working_dir):
    from src.scanner import scan_path

    # Crée un fichier EICAR dans un sous-dossier scanné
    sample_dir = working_dir / "samples"
    sample_dir.mkdir()
    sample = sample_dir / "eicar.com"
    sample.write_text(EICAR_STRING, encoding="ascii")
    assert sample.exists()

    verdicts = scan_path(str(sample_dir), recursive=True, quarantine=True)

    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.is_malicious, "EICAR aurait dû être détecté"
    assert v.result.malware_family == "EICAR"
    rule_names = [m.get("rule") for m in v.result.matched_rules]
    assert "EICAR_Test_File" in rule_names

    # Le fichier d'origine a disparu (déplacé)
    assert not sample.exists()
    assert v.quarantine is not None

    # Le fichier est dans quarantine/ et le manifeste est à jour
    qdir = working_dir / "quarantine"
    assert (qdir / v.quarantine.stored_filename).exists()
    manifest = json.loads((qdir / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest) == 1
    assert manifest[0]["original_path"].endswith("eicar.com")
    assert "EICAR_Test_File" in manifest[0]["reason"]


def test_clean_file_not_flagged(working_dir):
    from src.scanner import scan_path

    clean = working_dir / "samples" / "hello.txt"
    clean.parent.mkdir(parents=True)
    clean.write_text("Hello, world! This file is benign.\n", encoding="utf-8")

    verdicts = scan_path(str(clean), quarantine=True)

    assert len(verdicts) == 1
    assert not verdicts[0].is_malicious
    assert verdicts[0].quarantine is None
    # Le fichier propre ne doit PAS avoir bougé
    assert clean.exists()


def test_sync_yara_rules_copies_files(working_dir):
    from src.scanner import sync_yara_rules

    copied = sync_yara_rules()
    assert copied >= 1  # au moins eicar.yar
    dst = working_dir / "db" / "signatures" / "yara"
    yar_files = list(dst.glob("*.yar"))
    assert any(f.name == "eicar.yar" for f in yar_files)

    # Deuxième passe : rien à copier (fichiers déjà à jour)
    copied_again = sync_yara_rules()
    assert copied_again == 0
