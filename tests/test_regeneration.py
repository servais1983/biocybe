"""Tests auto-régénération (self-healing) — scénario anti-ransomware.

Couvre les 3 phases (baseline → drift → heal) + les garde-fous
(dry-run par défaut, vérification d'intégrité, atomicité, caps),
et le scénario ransomware end-to-end (chiffrement → restauration).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _healer(tmp_path):
    from biocybe.regeneration import SelfHealer

    return SelfHealer(
        vault_dir=tmp_path / "vault",
        manifest_path=tmp_path / "baseline.json",
    )


# ----------------------------------------------------------------------
# Baseline
# ----------------------------------------------------------------------


def test_baseline_captures_files(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "a.txt").write_text("contenu A sain", encoding="utf-8")
    (protected / "b.conf").write_text("config = ok", encoding="utf-8")

    h = _healer(tmp_path)
    stats = h.baseline([protected])
    assert stats.captured == 2
    assert stats.total_bytes > 0
    # Le coffre contient le contenu
    assert h.stats()["baseline_total"] == 2


def test_baseline_skips_too_big(tmp_path):
    from biocybe.regeneration import SelfHealer

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 2048)
    h = SelfHealer(
        vault_dir=tmp_path / "v",
        manifest_path=tmp_path / "b.json",
        max_file_bytes=1024,
    )
    stats = h.baseline([big])
    assert stats.captured == 0
    assert str(big) in stats.skipped_too_big or len(stats.skipped_too_big) == 1


def test_baseline_persists_across_instances(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data", encoding="utf-8")
    h1 = _healer(tmp_path)
    h1.baseline([f])
    # Nouvelle instance lit le manifeste sur disque
    h2 = _healer(tmp_path)
    assert h2.stats()["baseline_total"] == 1


# ----------------------------------------------------------------------
# Drift
# ----------------------------------------------------------------------


def test_detect_drift_intact(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("inchangé", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    assert h.detect_drift() == []


def test_detect_drift_modified(tmp_path):
    from biocybe.regeneration import DriftStatus

    f = tmp_path / "x.txt"
    f.write_text("original", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    f.write_text("ALTERE PAR ATTAQUANT", encoding="utf-8")
    drift = h.detect_drift()
    assert len(drift) == 1
    assert drift[0].status == DriftStatus.MODIFIED


def test_detect_drift_deleted(tmp_path):
    from biocybe.regeneration import DriftStatus

    f = tmp_path / "x.txt"
    f.write_text("original", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    f.unlink()
    drift = h.detect_drift()
    assert len(drift) == 1
    assert drift[0].status == DriftStatus.DELETED


# ----------------------------------------------------------------------
# Heal — garde-fous + restauration
# ----------------------------------------------------------------------


def test_heal_dry_run_does_not_touch_files(tmp_path):
    from biocybe.regeneration import HealAction

    f = tmp_path / "x.txt"
    f.write_text("original", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    f.write_text("altere", encoding="utf-8")

    results = h.heal(dry_run=True)
    assert len(results) == 1
    assert results[0].action == HealAction.WOULD_RESTORE
    # Le fichier n'a PAS été touché en dry-run
    assert f.read_text(encoding="utf-8") == "altere"


def test_heal_restores_modified_file(tmp_path):
    from biocybe.regeneration import HealAction

    f = tmp_path / "x.txt"
    f.write_text("CONTENU SAIN", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    f.write_text("corrompu", encoding="utf-8")

    results = h.heal(dry_run=False)
    assert results[0].action == HealAction.RESTORED
    # Le contenu sain est restauré
    assert f.read_text(encoding="utf-8") == "CONTENU SAIN"


def test_heal_restores_deleted_file(tmp_path):
    from biocybe.regeneration import HealAction

    f = tmp_path / "x.txt"
    f.write_text("a recreer", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])
    f.unlink()
    assert not f.exists()

    results = h.heal(dry_run=False)
    assert results[0].action == HealAction.RESTORED
    assert f.exists()
    assert f.read_text(encoding="utf-8") == "a recreer"


def test_heal_only_paths_filter(tmp_path):
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("A", encoding="utf-8")
    f2.write_text("B", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f1, f2])
    f1.write_text("A-altere", encoding="utf-8")
    f2.write_text("B-altere", encoding="utf-8")

    results = h.heal(dry_run=False, only_paths=[str(f1)])
    assert len(results) == 1
    assert f1.read_text(encoding="utf-8") == "A"
    assert f2.read_text(encoding="utf-8") == "B-altere"  # non touché


def test_heal_max_per_run_cap(tmp_path):
    from biocybe.regeneration import SelfHealer

    files = []
    for i in range(5):
        f = tmp_path / f"f{i}.txt"
        f.write_text(f"orig{i}", encoding="utf-8")
        files.append(f)
    h = SelfHealer(
        vault_dir=tmp_path / "v",
        manifest_path=tmp_path / "b.json",
        max_heal_per_run=2,
    )
    h.baseline(files)
    for f in files:
        f.write_text("altere", encoding="utf-8")

    results = h.heal(dry_run=False)
    # Cap à 2 restaurations par run
    assert len(results) == 2


def test_heal_integrity_check_blocks_corrupt_vault(tmp_path):
    """Si le coffre est corrompu, la restauration échoue (intégrité KO)."""
    from biocybe.regeneration import HealAction

    f = tmp_path / "x.txt"
    f.write_text("SAIN", encoding="utf-8")
    h = _healer(tmp_path)
    h.baseline([f])

    # Corrompt le contenu dans le coffre
    entry = next(iter(h._entries.values()))
    vault_file = h._vault_path(entry.sha256)
    vault_file.write_bytes(b"VAULT CORROMPU")

    f.write_text("altere", encoding="utf-8")
    results = h.heal(dry_run=False)
    assert results[0].action == HealAction.FAILED
    assert "corrompu" in (results[0].error or "").lower()
    # Le fichier altéré n'a PAS été remplacé par du contenu corrompu
    assert f.read_text(encoding="utf-8") == "altere"


# ----------------------------------------------------------------------
# Scénario ransomware end-to-end
# ----------------------------------------------------------------------


def test_ransomware_scenario_end_to_end(tmp_path):
    """Simule un ransomware chiffrant des fichiers → régénération complète."""
    from biocybe.regeneration import HealAction

    docs = tmp_path / "documents"
    docs.mkdir()
    originals = {}
    for name in ("rapport.docx", "contrat.pdf", "photo.jpg"):
        content = f"contenu original de {name}" * 10
        (docs / name).write_text(content, encoding="utf-8")
        originals[name] = content

    h = _healer(tmp_path)
    h.baseline([docs])

    # "Ransomware" : chiffre tous les fichiers (remplace par du bruit)
    for name in originals:
        (docs / name).write_text("ENCRYPTED_BY_RANSOMWARE_" + "Z" * 50, encoding="utf-8")

    # Détection : tout est en drift "modified"
    summary = h.drift_summary()
    assert summary["modified"] == 3

    # Régénération
    results = h.heal(dry_run=False)
    assert all(r.action == HealAction.RESTORED for r in results)
    # Tous les fichiers sont restaurés à l'identique
    for name, content in originals.items():
        assert (docs / name).read_text(encoding="utf-8") == content
    # Plus aucun drift après heal
    assert h.detect_drift() == []


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_regen_full_cycle(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    f = tmp_path / "critical.conf"
    f.write_text("safe config", encoding="utf-8")
    vault = str(tmp_path / "vault")
    manifest = str(tmp_path / "baseline.json")

    # baseline
    rc = main(["regen", "baseline", str(f), "--vault", vault, "--manifest", manifest])
    assert rc == 0
    capsys.readouterr()

    # drift : rien encore
    rc = main(["regen", "drift", "--vault", vault, "--manifest", manifest])
    assert rc == 0  # pas de drift

    # altération
    f.write_text("tampered", encoding="utf-8")
    rc = main(["regen", "drift", "--vault", vault, "--manifest", manifest])
    assert rc == 1  # drift détecté
    capsys.readouterr()

    # heal dry-run (défaut) : ne touche pas
    rc = main(["regen", "heal", "--vault", vault, "--manifest", manifest])
    assert rc == 0
    assert f.read_text(encoding="utf-8") == "tampered"
    assert "DRY-RUN" in capsys.readouterr().out

    # heal --execute : restaure
    rc = main(["regen", "heal", "--execute", "--vault", vault, "--manifest", manifest])
    assert rc == 0
    assert f.read_text(encoding="utf-8") == "safe config"


def test_cli_regen_status_empty(tmp_path, capsys):
    from biocybe.cli import main

    rc = main([
        "regen", "status",
        "--vault", str(tmp_path / "v"),
        "--manifest", str(tmp_path / "b.json"),
    ])
    assert rc == 0
    assert "Aucune baseline" in capsys.readouterr().out
