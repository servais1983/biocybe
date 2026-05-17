"""Tests Phase 2.2.e : mode --dry-run et restauration de quarantaine.

Garantit que :
  - --dry-run détecte mais n'écrit rien sur disque (exigence SOC pour
    l'évaluation en prod sans risque) ;
  - restore_file rétablit le fichier à son emplacement original ;
  - restore_file refuse de restaurer un fichier corrompu (vérification
    SHA-256), sauf si --no-verify est explicitement passé ;
  - la commande CLI `biocybe quarantine list/restore` fonctionne.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


EICAR_PARTS = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
]
EICAR_STRING = "".join(EICAR_PARTS)


@pytest.fixture
def working_dir(tmp_path, monkeypatch):
    """Dossier isolé avec règles YARA et CWD basculé."""
    rules_src = ROOT / "rules" / "yara"
    rules_dst = tmp_path / "rules" / "yara"
    rules_dst.mkdir(parents=True)
    for rule in rules_src.glob("*.yar"):
        (rules_dst / rule.name).write_bytes(rule.read_bytes())
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _make_eicar(directory: Path, name: str = "eicar.com") -> Path:
    f = directory / name
    f.write_text(EICAR_STRING, encoding="ascii")
    return f


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


def test_dry_run_detects_but_does_not_quarantine(working_dir):
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    assert sample.exists()

    verdicts = scan_path(str(sample), quarantine=True, dry_run=True)

    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.is_malicious
    assert v.quarantine is None, "dry-run ne doit JAMAIS écrire en quarantaine"
    assert v.quarantine_dry_run is True
    # Le fichier d'origine est resté en place
    assert sample.exists()
    # Pas de dossier quarantine créé
    assert not (working_dir / "quarantine" / "manifest.json").exists()


def test_dry_run_without_quarantine_flag_is_noop(working_dir):
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    verdicts = scan_path(str(sample), quarantine=False, dry_run=True)
    assert verdicts[0].is_malicious
    assert verdicts[0].quarantine is None
    assert verdicts[0].quarantine_dry_run is False  # rien à signaler, quarantine=False


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_after_quarantine(working_dir):
    from biocybe.isolation import list_quarantine, restore_file
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    original_path = str(sample.resolve())

    verdicts = scan_path(str(sample), quarantine=True)
    assert verdicts[0].quarantine is not None
    qid = verdicts[0].quarantine.quarantine_id

    # Le fichier d'origine a disparu, l'entrée est au manifeste
    assert not sample.exists()
    assert len(list_quarantine()) == 1

    # Restauration
    dest = restore_file(qid)
    assert str(dest.resolve()) == original_path
    assert dest.exists()
    assert dest.read_text(encoding="ascii") == EICAR_STRING

    # Manifeste vide
    assert list_quarantine() == []


def test_restore_to_custom_destination(working_dir):
    from biocybe.isolation import restore_file
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    verdicts = scan_path(str(sample), quarantine=True)
    qid = verdicts[0].quarantine.quarantine_id

    custom = working_dir / "investigation" / "sample_for_review.bin"
    dest = restore_file(qid, destination=str(custom))
    assert dest == custom
    assert custom.exists()


def test_restore_refuses_corrupted_file(working_dir):
    from biocybe.isolation import QuarantineIntegrityError, restore_file
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    verdicts = scan_path(str(sample), quarantine=True)
    qid = verdicts[0].quarantine.quarantine_id
    stored = working_dir / "quarantine" / verdicts[0].quarantine.stored_filename

    # Quelqu'un altère le fichier en quarantaine (corruption ou tampering)
    stored.write_text("MODIFIED CONTENT", encoding="utf-8")

    with pytest.raises(QuarantineIntegrityError):
        restore_file(qid)

    # Avec --no-verify, ça passe (cas forensique exceptionnel)
    dest = restore_file(qid, verify_hash=False)
    assert dest.exists()


def test_restore_keep_manifest_for_audit(working_dir):
    from biocybe.isolation import list_quarantine, restore_file
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    verdicts = scan_path(str(sample), quarantine=True)
    qid = verdicts[0].quarantine.quarantine_id

    restore_file(qid, remove_from_manifest=False)

    # L'entrée reste dans le manifeste pour audit trail
    remaining = list_quarantine()
    assert len(remaining) == 1
    assert remaining[0]["quarantine_id"] == qid


def test_restore_unknown_id_raises(working_dir):
    from biocybe.isolation import restore_file

    with pytest.raises(KeyError):
        restore_file("inexistant_id_12345")


def test_restore_refuses_if_destination_exists(working_dir):
    from biocybe.isolation import restore_file
    from biocybe.scanner import scan_path

    sample = _make_eicar(working_dir)
    original_path = sample.resolve()
    verdicts = scan_path(str(sample), quarantine=True)
    qid = verdicts[0].quarantine.quarantine_id

    # Un autre fichier vient prendre la place de l'original
    original_path.write_text("squatter", encoding="utf-8")

    with pytest.raises(FileExistsError):
        restore_file(qid)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_scan_dry_run_json(working_dir, capsys):
    from biocybe.cli import main

    _make_eicar(working_dir)
    exit_code = main(["scan", str(working_dir), "--quarantine", "--dry-run", "--json"])

    assert exit_code == 1  # menace détectée
    out = capsys.readouterr().out
    payload = json.loads(out)
    # Le scan parcourt working_dir (eicar + règles YARA + log) ; seul EICAR doit matcher.
    malicious = [v for v in payload if v["result"]["is_malicious"]]
    assert len(malicious) == 1, f"Une seule menace attendue, vu : {[v['path'] for v in malicious]}"
    assert malicious[0]["quarantine"] == {"dry_run": True}
    # Pas de manifeste écrit
    assert not (working_dir / "quarantine" / "manifest.json").exists()


def test_cli_quarantine_list_and_restore(working_dir, capsys):
    from biocybe.cli import main

    _make_eicar(working_dir)
    main(["scan", str(working_dir), "--quarantine"])
    capsys.readouterr()  # vider le buffer

    # list
    exit_code = main(["quarantine", "list", "--json"])
    assert exit_code == 0
    entries = json.loads(capsys.readouterr().out)
    assert len(entries) == 1
    qid = entries[0]["quarantine_id"]

    # restore
    exit_code = main(["quarantine", "restore", qid])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "restauré" in out.lower()
