"""Apprentissage depuis les incidents qualifiés (tolérance / mémoire)."""

from __future__ import annotations

import json

import pytest

from biocybe.inflammation import (
    DangerSignal,
    FeedbackStore,
    IncidentStore,
    InflammationEngine,
    ToleranceModel,
    feedback_path_for,
    signal_signature,
)


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t


def _backup_agent_incident(store_path, clock, exe="/opt/backup/agent"):
    """Outil de sauvegarde légitime qui ressemble à un ransomware."""
    eng = InflammationEngine(host="h", clock=clock, store=IncidentStore(store_path))
    inc = eng.ingest(
        DangerSignal("process:shadow_copy_deletion", "procmon", 90, entities=(f"file:{exe}",))
    )
    assert inc is not None
    return inc.incident_id


# --------------------------------------------------------------------------- #
# Signature
# --------------------------------------------------------------------------- #


def test_signature_excludes_pids_and_host():
    assert signal_signature("k", ["pid:5", "file:/a", "host:x"]) == "k|file:/a"
    assert signal_signature("k", ["pid:5"]) == ""
    assert signal_signature("k", ["file:/b", "file:/a"]) == "k|file:/a|file:/b"


# --------------------------------------------------------------------------- #
# Modèle
# --------------------------------------------------------------------------- #


def test_false_positive_learned_and_bounded(tmp_path):
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    fb = FeedbackStore(feedback_path_for(store))
    for _ in range(5):
        inc_id = _backup_agent_incident(store, clock)
        fb.mark(inc_id, "false_positive", analyst="alice")
        clock.t += 10_000
    model = ToleranceModel.from_paths(store)
    f = model.factor("process:shadow_copy_deletion", ["file:/opt/backup/agent", "pid:42"])
    assert f == pytest.approx(0.1)  # 0.5**5 = 0.03 -> plancher 0.1 : jamais 0


def test_tolerance_is_targeted_not_global(tmp_path):
    """Tolérer l'agent de sauvegarde ne tolère PAS le même comportement
    depuis /tmp, ni un autre type de signal, ni les anomalies hôte."""
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    FeedbackStore(feedback_path_for(store)).mark(
        _backup_agent_incident(store, clock), "false_positive"
    )
    model = ToleranceModel.from_paths(store)
    assert model.factor("process:shadow_copy_deletion", ["file:/opt/backup/agent"]) == 0.5
    assert model.factor("process:shadow_copy_deletion", ["file:/tmp/agent"]) == 1.0
    assert model.factor("network_ioc", ["file:/opt/backup/agent"]) == 1.0
    assert model.factor("behavior_anomaly", []) == 1.0


def test_true_positive_overrides_false_positive(tmp_path):
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    fb = FeedbackStore(feedback_path_for(store))
    fb.mark(_backup_agent_incident(store, clock), "false_positive")
    clock.t += 10_000
    fb.mark(_backup_agent_incident(store, clock), "true_positive")
    model = ToleranceModel.from_paths(store)
    assert model.factor("process:shadow_copy_deletion", ["file:/opt/backup/agent"]) == 1.25


def test_latest_verdict_for_an_incident_wins(tmp_path):
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    fb = FeedbackStore(feedback_path_for(store))
    inc_id = _backup_agent_incident(store, clock)
    fb.mark(inc_id, "false_positive")
    fb.mark(inc_id, "true_positive")  # l'analyste se ravise
    model = ToleranceModel.from_paths(store)
    assert model.fp_counts == {} and sum(model.tp_counts.values()) == 1


def test_invalid_verdict_and_corrupt_lines(tmp_path):
    fb = FeedbackStore(tmp_path / "d.jsonl")
    with pytest.raises(ValueError):
        fb.mark("INC-x", "maybe")
    (tmp_path / "d.jsonl").write_text('garbage\n{"verdict":"x"}\n', encoding="utf-8")
    assert fb.load() == {}


# --------------------------------------------------------------------------- #
# Effet sur le moteur
# --------------------------------------------------------------------------- #


def test_learned_fp_no_longer_opens_incident_but_attack_elsewhere_does(tmp_path):
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    FeedbackStore(feedback_path_for(store)).mark(
        _backup_agent_incident(store, clock), "false_positive"
    )
    clock.t += 10_000
    eng = InflammationEngine(host="h", clock=clock, tolerance=ToleranceModel.from_paths(store))
    # Même outil, même chemin : 90 x 0.5 = 45 < seuil local 50 -> pas d'incident
    assert (
        eng.ingest(
            DangerSignal(
                "process:shadow_copy_deletion", "procmon", 90, entities=("file:/opt/backup/agent",)
            )
        )
        is None
    )
    assert eng.stats["signals_tolerated"] == 1
    # Même comportement depuis /tmp : pleine réponse
    inc = eng.ingest(
        DangerSignal("process:shadow_copy_deletion", "procmon", 90, entities=("file:/tmp/agent",))
    )
    assert inc is not None and inc.signals[-1].tolerance == 1.0


def test_tolerated_signal_still_counts_when_corroborated(tmp_path):
    """La tolérance réduit, elle n'aveugle pas : l'outil toléré qui parle
    ensuite à un C2 déclenche quand même un incident."""
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    FeedbackStore(feedback_path_for(store)).mark(
        _backup_agent_incident(store, clock), "false_positive"
    )
    eng = InflammationEngine(host="h", clock=clock, tolerance=ToleranceModel.from_paths(store))
    ent = ("file:/opt/backup/agent",)
    eng.ingest(DangerSignal("process:shadow_copy_deletion", "procmon", 90, entities=ent))
    inc = eng.ingest(DangerSignal("network_ioc", "netmon", 80, entities=ent))
    assert inc is not None and inc.severity == "systemic"
    text = inc.explain()
    assert "tolérance (FP appris)" in text


def test_true_positive_memory_speeds_up_response(tmp_path):
    store = tmp_path / "incidents.jsonl"
    clock = Clock()
    FeedbackStore(feedback_path_for(store)).mark(
        _backup_agent_incident(store, clock, exe="/tmp/dropper"), "true_positive"
    )
    eng = InflammationEngine(host="h", clock=clock, tolerance=ToleranceModel.from_paths(store))
    # Même signature qu'un incident confirmé malveillant : réponse renforcée
    # (90 x 1.25 = 112.5), l'incident monte plus vite.
    inc = eng.ingest(
        DangerSignal("process:shadow_copy_deletion", "procmon", 90, entities=("file:/tmp/dropper",))
    )
    assert inc.signals[-1].tolerance == 1.25 and inc.current_level == pytest.approx(112.5)
    assert "mémoire (TP appris)" in inc.explain()


def test_broken_tolerance_model_does_not_blind_engine():
    class Broken:
        def factor(self, kind, entities):
            raise RuntimeError("boom")

    eng = InflammationEngine(host="h", tolerance=Broken())
    assert eng.ingest(DangerSignal("x", "t", 80, entities=("file:/a",))) is not None


# --------------------------------------------------------------------------- #
# CLI + daemon
# --------------------------------------------------------------------------- #


def test_cli_mark_tolerance_and_list(tmp_path, capsys, monkeypatch):
    from biocybe import cli

    audited = []
    monkeypatch.setattr("biocybe.audit.audit", lambda action, **kw: audited.append((action, kw)))
    store = tmp_path / "incidents.jsonl"
    inc_id = _backup_agent_incident(store, Clock())

    rc = cli.main(
        [
            "incidents",
            "mark",
            inc_id[-6:],
            "--as",
            "false_positive",
            "--notes",
            "agent de sauvegarde Veeam",
            "--analyst",
            "alice",
            "--store",
            str(store),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0 and "faux positif" in out and "x0.5" in out
    assert audited[0][0] == "incident_marked" and audited[0][1]["actor"] == "alice"

    assert cli.main(["incidents", "tolerance", "--store", str(store), "--json"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert entries[0]["false_positives"] == 1 and entries[0]["factor"] == 0.5

    cli.main(["incidents", "list", "--all", "--store", str(store)])
    assert "[false_positive]" in capsys.readouterr().out
    assert cli.main(["incidents", "mark", "nope", "--as", "true_positive", "--store", str(store)])


def test_daemon_hot_reloads_tolerance(tmp_path):
    from biocybe import cli

    store = tmp_path / "incidents.jsonl"
    eng = cli._build_inflammation_from_config(
        {"inflammation": {"store_path": str(store)}}, notify_mgr=None
    )
    ent = ("file:/opt/backup/agent",)
    inc = eng.ingest(DangerSignal("process:shadow_copy_deletion", "procmon", 90, entities=ent))
    assert inc is not None
    assert cli._maybe_reload_tolerance(eng) is False  # rien de nouveau

    FeedbackStore(feedback_path_for(store)).mark(inc.incident_id, "false_positive")
    import os
    import time

    future = time.time() + 5
    os.utime(feedback_path_for(store), (future, future))  # mtime garanti différent
    assert cli._maybe_reload_tolerance(eng) is True
    assert eng._tolerance.factor("process:shadow_copy_deletion", ent) == 0.5
