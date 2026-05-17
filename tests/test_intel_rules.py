"""Tests Phase 2.2.c : import de règles YARA communautaires.

Mocking complet de l'HTTP — on construit un faux zipball en mémoire
pour tester download_source sans appel réseau.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# Une règle YARA minimale, qui doit compiler partout.
GOOD_RULE = b"""
rule TestRuleGood {
    strings:
        $a = "hello"
    condition:
        $a
}
"""

# Une règle qui dépend d'un module inexistant — doit échouer la compile.
BROKEN_RULE = b"""
import "cuckoo"
rule TestRuleBroken {
    condition:
        cuckoo.network.dns_lookup(/evil\\.com/)
}
"""


def _make_fake_zipball(
    files: dict[str, bytes], root_prefix: str = "signature-base-master"
) -> bytes:
    """Construit un zipball GitHub-like en mémoire.

    GitHub préfixe toutes les entrées par `<repo>-<ref>/`.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(f"{root_prefix}/{path}", content)
    return buf.getvalue()


def _fake_get(zip_bytes: bytes):
    resp = MagicMock()
    resp.status_code = 200
    resp.content = zip_bytes
    resp.raise_for_status.return_value = None
    return resp


# --------------------------------------------------------------------- #
# list_sources / KNOWN_SOURCES
# --------------------------------------------------------------------- #


def test_known_sources_have_required_fields():
    from biocybe.intel.rules import KNOWN_SOURCES, list_sources

    assert "signature-base" in KNOWN_SOURCES
    assert "yara-rules" in KNOWN_SOURCES

    for src in list_sources():
        assert src.name
        assert src.zipball_url.startswith("https://")
        assert src.license
        assert src.description


# --------------------------------------------------------------------- #
# download_source
# --------------------------------------------------------------------- #


def test_download_source_extracts_yar_files(tmp_path):
    from biocybe.intel.rules import download_source

    zip_bytes = _make_fake_zipball(
        {
            "yara/rule_a.yar": GOOD_RULE,
            "yara/rule_b.yara": GOOD_RULE,
            "yara/sub/rule_c.yar": GOOD_RULE,
            "yara/readme.md": b"this is markdown, not yara",  # doit être ignoré
            "other/foo.yar": GOOD_RULE,  # hors include_subpath ('yara/')
        }
    )

    session = MagicMock()
    session.get.return_value = _fake_get(zip_bytes)

    result = download_source(
        "signature-base", dest_dir=tmp_path / "rules" / "community", session=session
    )

    # 3 fichiers .yar/.yara matchant `yara/` — pas le .md, pas `other/foo.yar`.
    assert result.files_extracted == 3
    assert result.source == "signature-base"
    assert result.output_dir == tmp_path / "rules" / "community" / "signature-base"

    extracted = sorted(p.name for p in result.output_dir.iterdir())
    assert "rule_a.yar" in extracted
    assert "rule_b.yara" in extracted
    # rule_c.yar venant de yara/sub/ → existe (avec ou sans disambig)
    assert any(name.endswith("rule_c.yar") for name in extracted)


def test_download_source_handles_name_collisions(tmp_path):
    from biocybe.intel.rules import download_source

    # Deux règles avec le même nom dans des sous-dossiers différents
    zip_bytes = _make_fake_zipball(
        {
            "yara/cat1/rule.yar": GOOD_RULE,
            "yara/cat2/rule.yar": GOOD_RULE,
        }
    )
    session = MagicMock()
    session.get.return_value = _fake_get(zip_bytes)

    result = download_source("signature-base", dest_dir=tmp_path, session=session)

    # 2 fichiers extraits avec disambiguïsation
    assert result.files_extracted == 2
    names = sorted(p.name for p in result.output_dir.iterdir())
    # Premier garde son nom, le second est préfixé par son path
    assert "rule.yar" in names
    assert any("cat" in n and n.endswith("rule.yar") and n != "rule.yar" for n in names)


def test_download_source_rejects_zip_slip(tmp_path):
    """Anti zip-slip : un membre avec `../` doit être ignoré."""
    from biocybe.intel.rules import download_source

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("signature-base-master/yara/legit.yar", GOOD_RULE)
        zf.writestr("signature-base-master/yara/../../evil.yar", GOOD_RULE)
        zf.writestr("/absolute/path.yar", GOOD_RULE)
    zip_bytes = buf.getvalue()

    session = MagicMock()
    session.get.return_value = _fake_get(zip_bytes)

    result = download_source("signature-base", dest_dir=tmp_path, session=session)

    # Seul le légitime est extrait
    assert result.files_extracted == 1
    files = list(result.output_dir.rglob("*"))
    assert all(f.name == "legit.yar" for f in files if f.is_file())
    # Pas de fichier en dehors de output_dir
    parent = result.output_dir.parent
    leaked = [p for p in parent.rglob("evil.yar")] + [p for p in parent.rglob("path.yar")]
    assert leaked == []


def test_download_source_unknown_raises(tmp_path):
    from biocybe.intel.rules import download_source

    with pytest.raises(KeyError, match="Source inconnue"):
        download_source("nope-this-source-does-not-exist", dest_dir=tmp_path)


def test_download_source_size_limit(tmp_path, monkeypatch):
    """Anti zip-bomb : un zip trop gros (compressé) est refusé avant extraction."""
    import os as _os

    from biocybe.intel import rules as rules_mod

    monkeypatch.setattr(rules_mod, "MAX_ZIP_SIZE_BYTES", 1024)  # 1 Ko

    # Bytes incompressibles (random) pour dépasser réellement 1 Ko après gzip
    big = _make_fake_zipball({"yara/big.yar": _os.urandom(8000)})
    assert len(big) > 1024, "le zip de test doit dépasser la limite"
    session = MagicMock()
    session.get.return_value = _fake_get(big)

    with pytest.raises(ValueError, match="zip-bomb"):
        rules_mod.download_source("signature-base", dest_dir=tmp_path, session=session)


# --------------------------------------------------------------------- #
# verify_source
# --------------------------------------------------------------------- #


def test_verify_source_counts_ok_and_broken(tmp_path):
    from biocybe.intel.rules import verify_source

    src_dir = tmp_path / "signature-base"
    src_dir.mkdir()
    (src_dir / "good1.yar").write_bytes(GOOD_RULE)
    (src_dir / "good2.yar").write_bytes(GOOD_RULE)
    (src_dir / "broken.yar").write_bytes(BROKEN_RULE)

    v = verify_source("signature-base", dest_dir=tmp_path)

    assert v.source == "signature-base"
    assert v.rules_ok == 2
    assert v.rules_broken == 1
    assert v.total == 3
    assert len(v.sample_errors) == 1
    assert v.sample_errors[0][0] == "broken.yar"


def test_verify_source_not_downloaded_raises(tmp_path):
    from biocybe.intel.rules import verify_source

    with pytest.raises(FileNotFoundError):
        verify_source("signature-base", dest_dir=tmp_path)


# --------------------------------------------------------------------- #
# Intégration avec BCell : règles communautaires picked up par sync
# --------------------------------------------------------------------- #


def test_community_rules_picked_up_by_scanner(tmp_path, monkeypatch):
    """Une règle YARA communautaire valide doit être chargée par BCell
    via le walk récursif de sync_yara_rules."""
    from biocybe.scanner import sync_yara_rules

    # Setup : rules/yara/community/test-source/my_rule.yar
    rules_root = tmp_path / "rules" / "yara"
    (rules_root / "community" / "test-source").mkdir(parents=True)
    (rules_root / "community" / "test-source" / "my_community_rule.yar").write_bytes(
        b'rule Community_Test {\n  strings: $a = "MARKERSTRING"\n  condition: $a\n}\n'
    )

    monkeypatch.chdir(tmp_path)
    copied = sync_yara_rules()
    assert copied >= 1

    # Vérifier qu'elle a bien été synchronisée
    runtime = tmp_path / "db" / "signatures" / "yara"
    assert (runtime / "my_community_rule.yar").exists()


# --------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------- #


def test_cli_intel_rules_list(capsys):
    from biocybe.cli import main

    exit_code = main(["intel", "rules", "list"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "signature-base" in out
    assert "yara-rules" in out


def test_cli_intel_rules_update_requires_yes(capsys, monkeypatch, tmp_path):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    # Sans --yes : retour 1 et message
    exit_code = main(["intel", "rules", "update", "--source", "signature-base"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "--yes" in out
