"""Tests mémoire immunitaire persistante (apprentissage cross-session).

Couvre :
  - remember : création + mise à jour (times_seen, last_seen, conf MAX)
  - recall par type ou auto
  - dispositions analyste (FP / confirmé)
  - adjust_confidence (réponse secondaire : 0 si FP, 100 si confirmé,
    renforcement progressif si récurrent)
  - persistance cross-session (réouverture de la même DB)
  - stats / top_families / recent / most_seen
  - intégration scanner : suppression FP + apprentissage
  - CLI memory {stats,recall,recent,mark,forget}
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

SHA = "a" * 64


# ----------------------------------------------------------------------
# Module ImmuneMemory
# ----------------------------------------------------------------------


def test_remember_creates_record(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    rec = mem.remember(
        SHA,
        indicator_type="sha256",
        verdict=VERDICT_MALICIOUS,
        confidence=80,
        family="Emotet",
        source="scanner",
    )
    assert rec.times_seen == 1
    assert rec.verdict == VERDICT_MALICIOUS
    assert rec.family == "Emotet"
    assert rec.confidence == 80
    mem.close()


def test_remember_updates_existing(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=50)
    rec = mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=90)
    assert rec.times_seen == 2  # incrémenté
    assert rec.confidence == 90  # MAX(50, 90)
    # Une 3e fois avec confiance plus faible ne dégrade pas
    rec = mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=10)
    assert rec.times_seen == 3
    assert rec.confidence == 90
    mem.close()


def test_recall_by_type_and_auto(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember("1.2.3.4", indicator_type="ip", verdict=VERDICT_MALICIOUS)
    assert mem.recall("1.2.3.4", "ip") is not None
    assert mem.recall("1.2.3.4") is not None  # auto
    assert mem.recall("9.9.9.9") is None
    mem.close()


def test_disposition_false_positive(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95)
    assert mem.is_known_benign(SHA, "sha256") is False
    mem.set_disposition(SHA, "sha256", "confirmed_benign", notes="legit tool")
    assert mem.is_known_benign(SHA, "sha256") is True
    rec = mem.recall(SHA, "sha256")
    assert rec.notes == "legit tool"
    mem.close()


def test_adjust_confidence_secondary_response(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")

    # Inconnu → confiance inchangée
    assert mem.adjust_confidence(SHA, 60, "sha256") == 60

    # Vu une fois malveillant → léger renforcement (60 + min(1,10) = 61)
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=60)
    assert mem.adjust_confidence(SHA, 60, "sha256") == 61

    # Vu 12 fois → +10 plafonné (réponse secondaire forte)
    for _ in range(11):
        mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=60)
    assert mem.adjust_confidence(SHA, 60, "sha256") == 70  # 60 + min(12,10)

    # Confirmé malveillant → 100 immédiat
    mem.set_disposition(SHA, "sha256", "confirmed_malicious")
    assert mem.adjust_confidence(SHA, 10, "sha256") == 100

    # Confirmé FP → 0 (supprimé)
    mem.set_disposition(SHA, "sha256", "confirmed_benign")
    assert mem.adjust_confidence(SHA, 99, "sha256") == 0
    mem.close()


def test_persistence_across_sessions(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    db = tmp_path / "persist.db"
    mem = ImmuneMemory(db)
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=88)
    mem.set_disposition(SHA, "sha256", "confirmed_benign")
    mem.close()

    # Réouverture : la mémoire doit avoir survécu
    mem2 = ImmuneMemory(db)
    rec = mem2.recall(SHA, "sha256")
    assert rec is not None
    assert rec.is_confirmed_benign
    assert mem2.is_known_benign(SHA, "sha256")
    mem2.close()


def test_forget(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS)
    assert mem.forget(SHA, "sha256") is True
    assert mem.recall(SHA, "sha256") is None
    assert mem.forget(SHA, "sha256") is False  # déjà absent
    mem.close()


def test_stats_and_queries(tmp_path):
    from biocybe.memory import VERDICT_BENIGN, VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(
        "h1" + "0" * 62, indicator_type="sha256", verdict=VERDICT_MALICIOUS, family="Emotet"
    )
    mem.remember(
        "h2" + "0" * 62, indicator_type="sha256", verdict=VERDICT_MALICIOUS, family="Emotet"
    )
    mem.remember("h3" + "0" * 62, indicator_type="sha256", verdict=VERDICT_BENIGN)
    # h2 vu plusieurs fois
    for _ in range(5):
        mem.remember("h2" + "0" * 62, indicator_type="sha256", verdict=VERDICT_MALICIOUS)

    stats = mem.stats()
    assert stats["total"] == 3
    assert stats["by_verdict"]["malicious"] == 2
    fams = mem.top_families(5)
    assert fams[0] == ("Emotet", 2)
    most = mem.most_seen(1)
    assert most[0].indicator.startswith("h2")
    assert len(mem.recent(10)) == 3
    mem.close()


def test_verdict_does_not_regress_to_benign(tmp_path):
    """Un indicateur déjà malveillant ne redevient pas benign via remember."""
    from biocybe.memory import VERDICT_BENIGN, VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=90)
    rec = mem.remember(SHA, indicator_type="sha256", verdict=VERDICT_BENIGN, confidence=10)
    assert rec.verdict == VERDICT_MALICIOUS  # reste malveillant
    mem.close()


# ----------------------------------------------------------------------
# Intégration scanner
# ----------------------------------------------------------------------


def test_scanner_suppresses_confirmed_fp(tmp_path, monkeypatch):
    """Un fichier flaggé mais marqué FP en mémoire est supprimé."""
    import hashlib

    from biocybe.lymphocytes_b import ScanResult
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory
    from biocybe.scanner import FileVerdict, _apply_immune_memory

    f = tmp_path / "legit.exe"
    f.write_bytes(b"this is a legit tool flagged by an over-eager rule")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(sha, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=80)
    mem.set_disposition(sha, "sha256", "confirmed_benign")

    result = ScanResult()
    result.is_malicious = True
    result.confidence = 0.8
    result.malware_family = "FalseAlarm"
    verdict = FileVerdict(path=f, result=result)

    _apply_immune_memory(verdict, mem)
    assert verdict.is_malicious is False
    assert verdict.suppressed_by_memory is True
    mem.close()


def test_scanner_learns_new_detection(tmp_path):
    import hashlib

    from biocybe.lymphocytes_b import ScanResult
    from biocybe.memory import ImmuneMemory
    from biocybe.scanner import FileVerdict, _apply_immune_memory

    f = tmp_path / "malware.bin"
    f.write_bytes(b"malicious payload bytes")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()

    mem = ImmuneMemory(tmp_path / "m.db")
    result = ScanResult()
    result.is_malicious = True
    result.confidence = 0.9
    result.malware_family = "TestFam"
    result.severity = "high"
    verdict = FileVerdict(path=f, result=result)

    _apply_immune_memory(verdict, mem)
    # La détection a été mémorisée
    rec = mem.recall(sha, "sha256")
    assert rec is not None
    assert rec.family == "TestFam"
    assert rec.confidence == 90
    assert verdict.is_malicious is True  # pas supprimé
    mem.close()


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_memory_stats_empty(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    db = tmp_path / "m.db"
    exit_code = main(["memory", "stats", "--db-path", str(db)])
    assert exit_code == 0
    assert "Total indicateurs : 0" in capsys.readouterr().out


def test_cli_memory_mark_and_recall(tmp_path, capsys):
    from biocybe.cli import main

    db = str(tmp_path / "m.db")
    # Marque un hash comme FP (crée l'entrée)
    rc = main(["memory", "mark", SHA, "--type", "sha256", "--as", "benign", "--db-path", db])
    assert rc == 0
    assert "supprimees" in capsys.readouterr().out

    # Recall : doit être confirmed_benign
    rc = main(["memory", "recall", SHA, "--type", "sha256", "--db-path", db, "--json"])
    assert rc == 0
    import json

    rec = json.loads(capsys.readouterr().out)
    assert rec["disposition"] == "confirmed_benign"


def test_cli_memory_recall_unknown(tmp_path, capsys):
    from biocybe.cli import main

    rc = main(["memory", "recall", "9.9.9.9", "--db-path", str(tmp_path / "m.db")])
    assert rc == 1
    assert "Inconnu" in capsys.readouterr().out


def test_cli_memory_forget(tmp_path, capsys):
    from biocybe.cli import main

    db = str(tmp_path / "m.db")
    main(["memory", "mark", SHA, "--type", "sha256", "--as", "malicious", "--db-path", db])
    capsys.readouterr()
    rc = main(["memory", "forget", SHA, "--type", "sha256", "--db-path", db])
    assert rc == 0
    assert "Oublie" in capsys.readouterr().out


def test_cli_memory_recent(tmp_path, capsys):
    from biocybe.cli import main

    db = str(tmp_path / "m.db")
    main(["memory", "mark", SHA, "--type", "sha256", "--as", "malicious", "--db-path", db])
    capsys.readouterr()
    rc = main(["memory", "recent", "--db-path", db, "--json"])
    assert rc == 0
    import json

    recs = json.loads(capsys.readouterr().out)
    assert len(recs) == 1
