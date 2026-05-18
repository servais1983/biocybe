"""Tests Phase 2.4.a : audit log immuable.

Tests réels :
  - append écrit vraiment sur disque, lignes JSON parseables
  - chaîne de hash : verify() détecte une ligne modifiée, supprimée, insérée
  - séquence monotone : verify() détecte un trou
  - reprise après restart : le seq et le hash continuent depuis le fichier
  - audit() est tolérant aux exceptions (jamais fatal)
  - intégration quarantine_file → audit entry réellement écrite
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "audit.jsonl"


# --------------------------------------------------------------------- #
# AuditLog : write / read / verify
# --------------------------------------------------------------------- #


def test_append_writes_line_to_disk(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    entry = log.append("test_action", actor="unit_test", details={"k": "v"})
    assert entry.seq == 1
    assert entry.actor == "unit_test"
    assert entry.action == "test_action"
    assert entry.outcome == "success"
    assert entry.prev_hash == "0" * 64

    # Le fichier existe, contient 1 ligne JSON valide
    raw = log_path.read_text(encoding="utf-8").strip()
    assert raw
    d = json.loads(raw)
    assert d["seq"] == 1
    assert d["details"]["k"] == "v"
    assert d["self_hash"] == entry.self_hash


def test_seq_is_monotonic(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    e1 = log.append("a")
    e2 = log.append("b")
    e3 = log.append("c")
    assert (e1.seq, e2.seq, e3.seq) == (1, 2, 3)
    assert e2.prev_hash == e1.self_hash
    assert e3.prev_hash == e2.self_hash


def test_verify_passes_on_intact_log(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    for i in range(5):
        log.append(f"action_{i}", details={"i": i})

    ok, errors = log.verify()
    assert ok is True, f"verify a échoué : {errors}"
    assert errors == []


def test_verify_detects_modified_line(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    for i in range(3):
        log.append(f"action_{i}")

    # Tamper : modifie le 2e champ details
    lines = log_path.read_text(encoding="utf-8").splitlines()
    d = json.loads(lines[1])
    d["details"] = {"tampered": True}
    lines[1] = json.dumps(d, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Nouvelle instance pour relire l'état depuis disque
    log2 = AuditLog(log_path)
    ok, errors = log2.verify()
    assert ok is False
    # Le self_hash de la ligne modifiée est invalide
    assert any("self_hash invalide" in e for e in errors)


def test_verify_detects_deleted_line(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    for i in range(4):
        log.append(f"action_{i}")

    # Supprime la 3e ligne (seq=3)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log2 = AuditLog(log_path)
    ok, errors = log2.verify()
    assert ok is False
    # Devrait détecter un trou de seq ET un prev_hash incorrect
    joined = " | ".join(errors)
    assert "seq=" in joined


def test_verify_detects_swapped_lines(log_path):
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    for i in range(4):
        log.append(f"action_{i}")

    # Échange lignes 2 et 3
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log2 = AuditLog(log_path)
    ok, _errors = log2.verify()
    assert ok is False


def test_state_resumes_after_restart(log_path):
    from biocybe.audit import AuditLog

    log1 = AuditLog(log_path)
    log1.append("first")
    e2 = log1.append("second")

    # Nouvelle instance : doit reprendre seq=3 et prev_hash=e2.self_hash
    log2 = AuditLog(log_path)
    e3 = log2.append("third")
    assert e3.seq == 3
    assert e3.prev_hash == e2.self_hash

    ok, errors = log2.verify()
    assert ok, errors


def test_concurrent_append_no_interleave(log_path):
    """Plusieurs threads écrivent simultanément ; les seq doivent être
    uniques et la chaîne de hash valide après-coup."""
    from biocybe.audit import AuditLog

    log = AuditLog(log_path)
    N_THREADS = 8
    N_PER_THREAD = 20

    def worker(idx):
        for i in range(N_PER_THREAD):
            log.append(f"thread_{idx}_action_{i}", details={"i": i})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = log.read_all()
    assert len(entries) == N_THREADS * N_PER_THREAD
    # Tous les seq sont uniques et contigus
    seqs = sorted(e.seq for e in entries)
    assert seqs == list(range(1, len(entries) + 1))

    ok, errors = log.verify()
    assert ok, f"verify a échoué : {errors[:5]}"


# --------------------------------------------------------------------- #
# audit() wrapper + default singleton
# --------------------------------------------------------------------- #


def test_audit_is_noop_without_default():
    from biocybe import audit as _audit

    # Reset le singleton (au cas où un test précédent l'ait set)
    _audit.set_default(None)

    # Ne lève pas d'exception
    _audit.audit("nothing_set", details={"k": "v"})


def test_audit_uses_default_when_set(log_path):
    from biocybe import audit as _audit

    log = _audit.AuditLog(log_path)
    _audit.set_default(log)
    try:
        _audit.audit("via_default", actor="test", details={"x": 1})
        entries = log.read_all()
        assert len(entries) == 1
        assert entries[0].action == "via_default"
        assert entries[0].details == {"x": 1}
    finally:
        _audit.set_default(None)


def test_audit_tolerates_broken_log(monkeypatch, log_path):
    """Si append lève, audit() ne doit PAS propager l'exception."""
    from biocybe import audit as _audit

    log = _audit.AuditLog(log_path)
    _audit.set_default(log)
    try:
        monkeypatch.setattr(
            log, "append", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full"))
        )
        # Ne raise pas
        _audit.audit("ok_no_crash")
    finally:
        _audit.set_default(None)


# --------------------------------------------------------------------- #
# Intégration : quarantine_file -> audit entry
# --------------------------------------------------------------------- #


def test_quarantine_file_writes_audit_entry(tmp_path, monkeypatch):
    from biocybe import audit as _audit
    from biocybe.isolation import quarantine_file

    audit_path = tmp_path / "audit.jsonl"
    log = _audit.AuditLog(audit_path)
    _audit.set_default(log)
    try:
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "evil.bin"
        src.write_text("garbage", encoding="ascii")
        entry = quarantine_file(src, reason="unit_test", detected_by="pytest")

        audit_entries = log.read_all()
        assert any(e.action == "quarantine_created" for e in audit_entries)
        qa = next(e for e in audit_entries if e.action == "quarantine_created")
        assert qa.actor == "pytest"
        assert qa.details["quarantine_id"] == entry.quarantine_id
        assert qa.details["sha256"]
    finally:
        _audit.set_default(None)
