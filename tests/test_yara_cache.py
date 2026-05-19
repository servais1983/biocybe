"""Tests Phase 3.a : cache de compilation YARA.

Vérifie :
  - 1er chargement : compile + crée le cache disque
  - 2e chargement : recharge depuis cache (mesure perf)
  - cache invalidé si on modifie un fichier source (mtime)
  - cache invalidé si on ajoute un fichier source
  - cache invalidé si on supprime un fichier source
  - cache invalidé si compiled.yarc corrompu
  - le scan fonctionne PARFAITEMENT avec un cache (mêmes matches qu'avec compile)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


GOOD_RULE_A = """
rule TestRuleA {
    strings:
        $a = "MARKER_AAA"
    condition:
        $a
}
"""

GOOD_RULE_B = """
rule TestRuleB {
    strings:
        $b = "MARKER_BBB"
    condition:
        $b
}
"""


@pytest.fixture
def rules_dir(tmp_path):
    """Dossier signatures avec 2 règles de test."""
    sig_dir = tmp_path / "db" / "signatures"
    yara_dir = sig_dir / "yara"
    yara_dir.mkdir(parents=True)
    (yara_dir / "rule_a.yar").write_text(GOOD_RULE_A, encoding="utf-8")
    (yara_dir / "rule_b.yar").write_text(GOOD_RULE_B, encoding="utf-8")
    return sig_dir


def test_first_load_creates_cache(rules_dir):
    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    db = SignatureDatabase(str(rules_dir))
    assert db.rules is not None
    cache_bin = rules_dir / "yara" / "compiled.yarc"
    cache_fp = rules_dir / "yara" / "compiled.fingerprint.json"
    assert cache_bin.exists()
    assert cache_fp.exists()


def test_second_load_uses_cache(rules_dir, caplog):
    import logging

    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    SignatureDatabase(str(rules_dir))  # cold

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="biocybe.b_cell"):
        SignatureDatabase(str(rules_dir))  # warm
    msgs = " ".join(r.message for r in caplog.records)
    assert "Cache YARA chargé" in msgs, msgs


def test_warm_load_faster_than_cold(rules_dir):
    """Avec 2 règles le delta est petit mais le cache doit gagner."""
    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    # cold (compile + save)
    t0 = time.time()
    SignatureDatabase(str(rules_dir))
    cold = time.time() - t0

    # warm (load)
    t0 = time.time()
    SignatureDatabase(str(rules_dir))
    warm = time.time() - t0

    # warm doit être au pire 50% du cold sur ces 2 règles ;
    # en pratique on observe ~10% (cache = file open + load binaire)
    assert warm < cold, f"warm ({warm:.3f}s) doit être < cold ({cold:.3f}s)"


def test_cache_invalidated_when_source_modified(rules_dir, caplog):
    import logging

    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    SignatureDatabase(str(rules_dir))  # crée le cache

    # On modifie le contenu d'une règle et on force un mtime > cache
    rule_a = rules_dir / "yara" / "rule_a.yar"
    new_content = GOOD_RULE_A.replace("MARKER_AAA", "MARKER_AAA_v2")
    rule_a.write_text(new_content, encoding="utf-8")
    # Forcer un mtime visiblement plus récent
    import os

    os.utime(rule_a, (time.time() + 5, time.time() + 5))

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="biocybe.b_cell"):
        SignatureDatabase(str(rules_dir))
    msgs = " ".join(r.message for r in caplog.records)
    assert "obsolète" in msgs.lower() or "compilation" in msgs.lower(), msgs


def test_cache_invalidated_when_file_added(rules_dir):
    """Ajouter une règle après création du cache → invalidation."""
    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    SignatureDatabase(str(rules_dir))  # cache créé pour 2 fichiers

    (rules_dir / "yara" / "rule_c.yar").write_text(
        'rule TestRuleC { strings: $c = "MARKER_CCC" condition: $c }',
        encoding="utf-8",
    )

    # Au prochain load, le fingerprint change, recompilation
    db = SignatureDatabase(str(rules_dir))
    # Tester la détection de la nouvelle règle
    import tempfile

    target = Path(tempfile.gettempdir()) / "yara_test_target_added.txt"
    target.write_text("MARKER_CCC inside", encoding="utf-8")
    try:
        is_mal, matches = db.check_file_yara(str(target))
        assert is_mal, "Nouvelle règle devrait matcher après invalidation cache"
        rule_names = [m["rule"] for m in matches]
        assert "TestRuleC" in rule_names
    finally:
        target.unlink(missing_ok=True)


def test_cache_invalidated_when_file_removed(rules_dir, caplog):
    import logging

    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    SignatureDatabase(str(rules_dir))  # cache 2 fichiers

    (rules_dir / "yara" / "rule_b.yar").unlink()

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="biocybe.b_cell"):
        SignatureDatabase(str(rules_dir))
    msgs = " ".join(r.message for r in caplog.records)
    assert "obsolète" in msgs.lower() or "Compilation" in msgs, msgs


def test_corrupted_cache_falls_back_to_compile(rules_dir, caplog):
    import logging

    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    SignatureDatabase(str(rules_dir))

    # Corrompre le binaire .yarc
    (rules_dir / "yara" / "compiled.yarc").write_bytes(b"NOT_A_VALID_YARA_BINARY")

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="biocybe.b_cell"):
        db = SignatureDatabase(str(rules_dir))
    msgs = " ".join(r.message for r in caplog.records)
    assert "illisible" in msgs.lower() or "recompilation" in msgs.lower(), msgs
    # Mais la base doit quand même fonctionner (recompilation)
    assert db.rules is not None


def test_cache_detection_equivalent_to_fresh_compile(rules_dir, tmp_path):
    """Un fichier qui match avec compile direct doit match avec cache aussi."""
    from biocybe.lymphocytes_b.b_cell import SignatureDatabase

    target = tmp_path / "target.txt"
    target.write_text("Some text with MARKER_AAA in the middle", encoding="utf-8")

    # cold
    db_cold = SignatureDatabase(str(rules_dir))
    is_mal_cold, matches_cold = db_cold.check_file_yara(str(target))

    # warm (load cache)
    db_warm = SignatureDatabase(str(rules_dir))
    is_mal_warm, matches_warm = db_warm.check_file_yara(str(target))

    assert is_mal_cold == is_mal_warm
    assert {m["rule"] for m in matches_cold} == {m["rule"] for m in matches_warm}
    assert is_mal_cold is True
    assert "TestRuleA" in [m["rule"] for m in matches_cold]
