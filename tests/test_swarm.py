"""Tests immunité collective (swarm) — export/import de renseignement."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _mem(tmp_path, name="m.db"):
    from biocybe.memory import ImmuneMemory

    return ImmuneMemory(tmp_path / name)


def _seed_malicious(mem, n=3, *, confirmed=False):
    from biocybe.memory import VERDICT_MALICIOUS

    for i in range(n):
        ind = f"{i:064x}"
        mem.remember(
            ind, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95, family="Emotet"
        )
        if confirmed:
            mem.set_disposition(ind, "sha256", "confirmed_malicious")


# ----------------------------------------------------------------------
# Export : ce qui est partageable
# ----------------------------------------------------------------------


def test_export_shares_high_confidence(tmp_path):
    from biocybe.swarm import SwarmSync

    mem = _mem(tmp_path)
    _seed_malicious(mem, 3)
    sync = SwarmSync(mem, node_id="node-a")
    bundle = sync.export_bundle(min_confidence=80)
    assert bundle["count"] == 3
    assert bundle["node_id"] == "node-a"
    mem.close()


def test_export_never_shares_false_positives(tmp_path):
    """Un FP confirmé localement ne doit JAMAIS être partagé."""
    from biocybe.memory import VERDICT_MALICIOUS
    from biocybe.swarm import SwarmSync

    mem = _mem(tmp_path)
    mem.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95)
    mem.set_disposition("a" * 64, "sha256", "confirmed_benign")  # FP local
    sync = SwarmSync(mem, node_id="node-a")
    bundle = sync.export_bundle()
    assert bundle["count"] == 0  # le FP n'est pas exporté
    mem.close()


def test_export_excludes_low_confidence(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS
    from biocybe.swarm import SwarmSync

    mem = _mem(tmp_path)
    mem.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=40)
    sync = SwarmSync(mem, node_id="node-a")
    bundle = sync.export_bundle(min_confidence=80)
    assert bundle["count"] == 0
    mem.close()


# ----------------------------------------------------------------------
# Immunité collective : export node A → import node B
# ----------------------------------------------------------------------


def test_collective_immunity_transfer(tmp_path):
    """Node A connaît une menace, node B l'apprend sans l'avoir vue."""
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 3)
    bundle = SwarmSync(mem_a, node_id="node-a").export_bundle()

    # Node B n'a rien
    mem_b = _mem(tmp_path, "b.db")
    assert mem_b.stats()["total"] == 0

    sync_b = SwarmSync(mem_b, node_id="node-b")
    stats = sync_b.import_bundle(bundle)
    assert stats.imported == 3
    # Node B a maintenant l'immunité : il connaît les indicateurs de A
    assert mem_b.recall("0" * 64, "sha256") is not None
    rec = mem_b.recall("0" * 64, "sha256")
    assert rec.source == "swarm:node-a"
    mem_a.close()
    mem_b.close()


def test_import_respects_local_fp(tmp_path):
    """Un pair signale une menace, mais c'est un FP confirmé localement → ignoré."""
    from biocybe.memory import VERDICT_MALICIOUS
    from biocybe.swarm import SwarmSync

    # Node A partage l'indicateur X comme malveillant
    mem_a = _mem(tmp_path, "a.db")
    mem_a.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95)
    bundle = SwarmSync(mem_a, node_id="node-a").export_bundle()

    # Node B a confirmé localement que X est un FP
    mem_b = _mem(tmp_path, "b.db")
    mem_b.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=50)
    mem_b.set_disposition("a" * 64, "sha256", "confirmed_benign")

    stats = SwarmSync(mem_b, node_id="node-b").import_bundle(bundle)
    assert stats.skipped_local_fp == 1
    assert stats.imported == 0
    # B garde sa décision : X reste un FP
    assert mem_b.is_known_benign("a" * 64, "sha256")
    mem_a.close()
    mem_b.close()


def test_import_skips_own_bundle(tmp_path):
    from biocybe.swarm import SwarmSync

    mem = _mem(tmp_path)
    _seed_malicious(mem, 2)
    sync = SwarmSync(mem, node_id="node-a")
    bundle = sync.export_bundle()
    stats = sync.import_bundle(bundle)  # ré-import de notre propre bundle
    assert stats.skipped_own == 2
    assert stats.imported == 0
    mem.close()


def test_confirmed_malicious_propagates(tmp_path):
    """Une confirmation malveillante d'un pair renforce l'immunité locale."""
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 1, confirmed=True)  # A a CONFIRMÉ la menace
    bundle = SwarmSync(mem_a, node_id="node-a").export_bundle()

    mem_b = _mem(tmp_path, "b.db")
    SwarmSync(mem_b, node_id="node-b").import_bundle(bundle)
    rec = mem_b.recall("0" * 64, "sha256")
    assert rec.disposition == "confirmed_malicious"  # confirmation propagée
    mem_b.close()
    mem_a.close()


# ----------------------------------------------------------------------
# Signature HMAC
# ----------------------------------------------------------------------


def test_signed_bundle_verified(tmp_path):
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 2)
    bundle = SwarmSync(mem_a, node_id="node-a", swarm_key="shared-secret").export_bundle()
    assert bundle["hmac"] is not None

    mem_b = _mem(tmp_path, "b.db")
    stats = SwarmSync(mem_b, node_id="node-b", swarm_key="shared-secret").import_bundle(bundle)
    assert stats.imported == 2
    assert stats.signature_failed is False
    mem_a.close()
    mem_b.close()


def test_tampered_bundle_rejected(tmp_path):
    """Un bundle modifié après signature est rejeté."""
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 1)
    bundle = SwarmSync(mem_a, node_id="node-a", swarm_key="key").export_bundle()
    # Falsification : on injecte un indicateur sans recalculer le HMAC
    bundle["indicators"].append(
        {
            "indicator": "f" * 64,
            "indicator_type": "sha256",
            "verdict": "malicious",
            "confidence": 100,
            "family": "Injecté",
        }
    )

    mem_b = _mem(tmp_path, "b.db")
    stats = SwarmSync(mem_b, node_id="node-b", swarm_key="key").import_bundle(bundle)
    assert stats.signature_failed is True
    assert stats.imported == 0
    assert mem_b.recall("f" * 64, "sha256") is None  # l'injection a échoué
    mem_a.close()
    mem_b.close()


def test_wrong_key_rejected(tmp_path):
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 1)
    bundle = SwarmSync(mem_a, node_id="node-a", swarm_key="key-A").export_bundle()

    mem_b = _mem(tmp_path, "b.db")
    stats = SwarmSync(mem_b, node_id="node-b", swarm_key="key-B").import_bundle(bundle)
    assert stats.signature_failed is True
    mem_a.close()
    mem_b.close()


def test_unsigned_rejected_when_key_required(tmp_path):
    from biocybe.swarm import SwarmSync

    mem_a = _mem(tmp_path, "a.db")
    _seed_malicious(mem_a, 1)
    bundle = SwarmSync(mem_a, node_id="node-a").export_bundle()  # pas de clé → non signé

    mem_b = _mem(tmp_path, "b.db")
    stats = SwarmSync(mem_b, node_id="node-b", swarm_key="key").import_bundle(bundle)
    assert stats.signature_failed is True  # B exige une signature
    mem_a.close()
    mem_b.close()


# ----------------------------------------------------------------------
# import_dir + CLI
# ----------------------------------------------------------------------


def test_import_dir_aggregates(tmp_path):
    from biocybe.swarm import SwarmSync

    shared = tmp_path / "shared"
    shared.mkdir()
    for node in ("a", "b"):
        m = _mem(tmp_path, f"{node}.db")
        from biocybe.memory import VERDICT_MALICIOUS

        m.remember(
            f"{node}" * 32, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95
        )
        SwarmSync(m, node_id=f"node-{node}").write_bundle(shared / f"{node}.json")
        m.close()

    mem_c = _mem(tmp_path, "c.db")
    stats = SwarmSync(mem_c, node_id="node-c").import_dir(shared)
    assert stats.imported == 2
    mem_c.close()


def test_cli_swarm_full_cycle(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")
    bundle = str(tmp_path / "bundle.json")

    # Seed node A
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    ma = ImmuneMemory(db_a)
    ma.remember(
        "a" * 64,
        indicator_type="sha256",
        verdict=VERDICT_MALICIOUS,
        confidence=95,
        family="LockBit",
    )
    ma.close()

    # export
    rc = main(["swarm", "export", bundle, "--db-path", db_a, "--node-id", "node-a"])
    assert rc == 0
    assert json.loads(Path(bundle).read_text(encoding="utf-8"))["count"] == 1
    capsys.readouterr()

    # import sur node B
    rc = main(["swarm", "import", bundle, "--db-path", db_b, "--node-id", "node-b", "--json"])
    assert rc == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["imported"] == 1

    # B connaît maintenant LockBit
    mb = ImmuneMemory(db_b)
    assert mb.recall("a" * 64, "sha256").family == "LockBit"
    mb.close()


def test_cli_swarm_status(tmp_path, capsys):
    from biocybe.cli import main
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    db = str(tmp_path / "m.db")
    m = ImmuneMemory(db)
    m.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=95)
    m.close()
    rc = main(["swarm", "status", "--db-path", db, "--json"])
    assert rc == 0
    info = json.loads(capsys.readouterr().out)
    assert info["shareable_count"] == 1
    assert info["signed"] is False
