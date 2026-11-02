"""Tests du système inflammatoire (corrélation multi-cellules).

Horloge injectée : tous les scénarios sont déterministes, sans sleep.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from biocybe.inflammation import (
    LEVEL_LOCAL,
    LEVEL_SYSTEMIC,
    STATUS_MERGED,
    STATUS_OPEN,
    STATUS_RESOLVED,
    TRANSITION_ESCALATED,
    TRANSITION_OPENED,
    TRANSITION_RESOLVED,
    DangerSignal,
    IncidentStore,
    InflammationConfig,
    InflammationEngine,
    file_entity,
    from_cell_message,
    from_connection_record,
    from_regen_event,
    from_watch_event,
)


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def engine(clock):
    eng = InflammationEngine(InflammationConfig(), host="testhost", clock=clock)
    eng.events = []
    eng.subscribe(lambda inc, tr: eng.events.append((inc.incident_id, tr, inc.severity)))
    return eng


def _watch_event(path: str, severity: str = "high", family: str | None = "Emotet"):
    result = SimpleNamespace(
        is_malicious=True,
        severity=severity,
        malware_family=family,
        matched_rules=[{"rule": "Test_Rule"}],
    )
    return SimpleNamespace(is_malicious=True, result=result, path=Path(path), quarantine=None)


def _conn_record(exe: str, pid: int = 4242, confidence: int = 80, ip: str = "192.0.2.10"):
    hit = SimpleNamespace(
        confidence=confidence, ioc_type="ip", value=ip, source="threatfox", malware="CobaltStrike"
    )
    return SimpleNamespace(
        hit=hit, process_exe=exe, pid=pid, process_name="evil.exe", raddr=f"{ip}:443"
    )


# --------------------------------------------------------------------------- #
# Seuils, décroissance, résolution
# --------------------------------------------------------------------------- #


def test_weak_signal_stays_subthreshold(engine):
    inc = engine.ingest(DangerSignal("file_malware", "watcher", 25, entities=("file:/a",)))
    assert inc is None
    assert engine.events == []
    assert engine.stats["signals_subthreshold"] == 1


def test_strong_signal_opens_local_incident(engine):
    inc = engine.ingest(DangerSignal("file_malware", "watcher", 65, entities=("file:/a",)))
    assert inc is not None
    assert inc.severity == LEVEL_LOCAL
    assert inc.status == STATUS_OPEN
    assert engine.events == [(inc.incident_id, TRANSITION_OPENED, LEVEL_LOCAL)]


def test_exponential_decay_half_life(engine, clock):
    engine.ingest(DangerSignal("x", "t", 80, entities=("file:/a",)))
    assert engine.level_of("file:/a") == pytest.approx(80)
    clock.advance(engine.config.half_life_seconds)
    assert engine.level_of("file:/a") == pytest.approx(40)


def test_incident_resolves_after_calm(engine, clock):
    inc = engine.ingest(DangerSignal("x", "t", 80, entities=("file:/a",)))
    clock.advance(60)
    assert engine.tick() == []  # encore enflammé
    # 80 -> < 10 il faut > 3 demi-vies
    clock.advance(engine.config.half_life_seconds * 3.1)
    resolved = engine.tick()
    assert [i.incident_id for i in resolved] == [inc.incident_id]
    assert inc.status == STATUS_RESOLVED
    assert engine.open_incidents() == []
    assert engine.events[-1][1] == TRANSITION_RESOLVED


def test_new_signal_after_resolution_opens_new_incident(engine, clock):
    first = engine.ingest(DangerSignal("x", "t", 80, entities=("file:/a",)))
    clock.advance(engine.config.half_life_seconds * 4)
    engine.tick()
    second = engine.ingest(DangerSignal("x", "t", 80, entities=("file:/a",)))
    assert second.incident_id != first.incident_id


# --------------------------------------------------------------------------- #
# Co-stimulation, corrélation, kill chain
# --------------------------------------------------------------------------- #


def test_kill_chain_file_then_c2_escalates_systemic(engine, clock, tmp_path):
    """Fichier malveillant déposé PUIS cet exe contacte un C2 : un seul
    incident, escaladé SYSTÉMIQUE grâce à la co-stimulation."""
    exe = str(tmp_path / "dropper.exe")
    inc = engine.ingest(from_watch_event(_watch_event(exe)))
    assert inc.severity == LEVEL_LOCAL

    clock.advance(30)
    inc2 = engine.ingest(from_connection_record(_conn_record(exe)))
    assert inc2 is inc, "le C2 depuis l'exe détecté doit rejoindre le même incident"
    assert inc.severity == LEVEL_SYSTEMIC
    assert inc.kinds == ["file_malware", "network_ioc"]
    assert set(inc.mitre) >= {"T1105", "T1071"}
    assert inc.pids == [4242]
    c2 = inc.signals[-1]
    assert c2.costim_factor == pytest.approx(1.5)
    assert engine.events[-1] == (inc.incident_id, TRANSITION_ESCALATED, LEVEL_SYSTEMIC)
    text = inc.explain()
    assert "SYSTÉMIQUE" in text and "co-stim" in text and "T1071" in text


def test_same_kind_does_not_costimulate(engine):
    engine.ingest(DangerSignal("network_ioc", "netmon", 60, entities=("pid:1",)))
    inc = engine.ingest(DangerSignal("network_ioc", "netmon", 60, entities=("pid:1",)))
    assert inc.signals[-1].costim_factor == 1.0


def test_unrelated_entities_make_separate_incidents(engine):
    a = engine.ingest(DangerSignal("x", "t", 70, entities=("file:/a",)))
    b = engine.ingest(DangerSignal("x", "t", 70, entities=("file:/b",)))
    assert a.incident_id != b.incident_id
    assert len(engine.open_incidents()) == 2


def test_bridging_signal_merges_incidents(engine):
    a = engine.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/a",)))
    b = engine.ingest(DangerSignal("network_ioc", "n", 70, entities=("pid:9",)))
    assert a.incident_id != b.incident_id
    # Ce signal relie le fichier et le pid (ex. exe=/a, pid=9)
    m = engine.ingest(DangerSignal("network_ioc", "n", 60, entities=("file:/a", "pid:9")))
    assert m is a
    assert b.status == STATUS_MERGED and b.merged_into == a.incident_id
    assert {"file:/a", "pid:9"} <= a.entities
    assert len(engine.open_incidents()) == 1
    assert engine.stats["incidents_merged"] == 1


def test_precursor_signals_pulled_into_incident(engine):
    # Signal faible (sous le seuil) puis signal fort sur la même entité :
    # le précurseur fait partie de la chronologie de l'incident.
    engine.ingest(DangerSignal("integrity_drift", "regen", 20, entities=("dir:/docs",)))
    inc = engine.ingest(DangerSignal("ransomware_burst", "regen", 90, entities=("dir:/docs",)))
    corrs = [s.correlation for s in inc.signals]
    assert corrs[0] == "precursor" and corrs[-1] == "entity"
    assert inc.signals_total == 2


def test_host_only_signal_temporal_correlation(engine):
    inc = engine.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/a",)))
    got = engine.ingest(DangerSignal("behavior_anomaly", "t_cell", 30, host_factor=1.0))
    assert got is inc
    assert inc.signals[-1].correlation == "temporal"


def test_host_only_signal_without_incident_is_subthreshold(engine):
    assert engine.ingest(DangerSignal("behavior_anomaly", "t_cell", 30, host_factor=1.0)) is None


def test_host_fever_opens_host_incident(engine):
    # Plusieurs signaux modérés sur des entités distinctes : aucun tissu
    # au-dessus du seuil local, mais l'hôte entre en fièvre.
    opened = None
    for i in range(12):
        opened = (
            engine.ingest(
                DangerSignal(f"k{i}", "t", 40, entities=(f"file:/f{i}",), host_factor=1.0)
            )
            or opened
        )
    assert opened is not None
    assert opened.severity == LEVEL_SYSTEMIC
    assert engine.host in opened.entities


def test_habituation_bounds_chatty_source(engine, clock):
    """Une anomalie répétée toutes les minutes pendant 2 h ne doit pas
    faire monter l'hôte en fièvre à elle seule (accoutumance)."""
    for _ in range(120):
        engine.ingest(DangerSignal("behavior_anomaly", "t_cell", 30, host_factor=1.0))
        clock.advance(60)
    assert engine.host_level < engine.config.systemic_threshold
    assert engine.open_incidents() == []


def test_habituation_can_be_disabled(clock):
    eng = InflammationEngine(InflammationConfig(habituation=False), host="h", clock=clock)
    for _ in range(120):
        eng.ingest(DangerSignal("behavior_anomaly", "t_cell", 30, host_factor=1.0))
        clock.advance(60)
    assert eng.host_level > eng.config.systemic_threshold


# --------------------------------------------------------------------------- #
# Robustesse
# --------------------------------------------------------------------------- #


def test_callback_exception_does_not_break_engine(clock):
    eng = InflammationEngine(host="h", clock=clock)

    def boom(inc, tr):
        raise RuntimeError("boom")

    eng.subscribe(boom)
    inc = eng.ingest(DangerSignal("x", "t", 80, entities=("file:/a",)))
    assert inc is not None
    assert eng.stats["callback_errors"] == 1


def test_signal_weight_clamped_and_entities_deduped():
    s = DangerSignal("x", "t", 500, entities=("file:/a", "file:/a", "", "host:zz"))
    assert s.weight == 100
    assert s.entities == ("file:/a",)


def test_max_signals_per_incident_bounded(clock):
    eng = InflammationEngine(InflammationConfig(max_signals_per_incident=20), host="h", clock=clock)
    inc = None
    for _ in range(100):
        inc = eng.ingest(DangerSignal("x", "t", 80, entities=("file:/a",))) or inc
    assert len(inc.signals) == 20
    assert inc.signals_total == 100


def test_calm_entities_pruned(engine, clock):
    for i in range(50):
        engine.ingest(DangerSignal("x", "t", 5, entities=(f"file:/{i}",)))
    assert engine.snapshot()["tracked_entities"] >= 50
    clock.advance(engine.config.half_life_seconds * 10)
    engine.tick()
    assert engine.snapshot()["tracked_entities"] <= 1  # seul l'hôte reste


def test_config_validation():
    with pytest.raises(ValueError):
        InflammationConfig.from_dict({"local_threshold": 200, "systemic_threshold": 100})
    with pytest.raises(ValueError):
        InflammationConfig.from_dict({"half_life_seconds": 0})
    cfg = InflammationConfig.from_dict({"local_threshold": "40", "unknown_key": 1})
    assert cfg.local_threshold == 40.0


def test_file_entity_shared_namespace(tmp_path):
    p = tmp_path / "x.exe"
    assert file_entity(p) == file_entity(str(p))
    assert file_entity(p).startswith("file:")


# --------------------------------------------------------------------------- #
# Adaptateurs
# --------------------------------------------------------------------------- #


def test_from_watch_event_ignores_benign():
    ev = SimpleNamespace(is_malicious=False, result=None, path=Path("/x"))
    assert from_watch_event(ev) is None


def test_from_watch_event_ransomware_family_maps_t1486():
    sig = from_watch_event(_watch_event("/tmp/r.bin", family="LockBit-Ransomware"))
    assert "T1486" in sig.mitre
    assert sig.weight == 65


def test_from_connection_record_without_hit():
    assert from_connection_record(SimpleNamespace(hit=None)) is None


def test_from_regen_burst_entities_are_dirs(tmp_path):
    sig = from_regen_event(
        "burst",
        {"window_count": 3, "paths": [str(tmp_path / "a.doc"), str(tmp_path / "b.doc")]},
    )
    assert sig.kind == "ransomware_burst"
    assert len(sig.entities) == 1 and sig.entities[0].startswith("dir:")
    assert sig.host_factor == 1.0
    assert from_regen_event("unknown", {}) is None


def test_from_cell_message_tcell_and_macrophage():
    tsig = from_cell_message(
        "alert_anomaly",
        {
            "type": "behavioral_outlier",
            "explanation": {"anomaly_score": -0.3, "top_features": [{"name": "cpu"}]},
            "detected_by": "t_cell_main",
        },
        "t_cell_main",
    )
    assert len(tsig) == 1 and tsig[0].kind == "behavior_anomaly" and tsig[0].entities == ()

    msigs = from_cell_message(
        "alert_anomaly",
        {
            "type": "suspicious_network_connection",
            "severity": "high",
            "anomalies": [
                {"type": "suspicious_network_connection", "severity": "high", "details": {"pid": 7}}
            ],
        },
        "macrophage_network",
    )
    assert msigs[0].entities == ("pid:7",) and msigs[0].mitre == ("T1571",)
    assert from_cell_message("system_health", {}, "x") == []


# --------------------------------------------------------------------------- #
# Persistance + CLI
# --------------------------------------------------------------------------- #


def test_store_roundtrip_and_corruption_tolerance(tmp_path, clock):
    store = IncidentStore(tmp_path / "inc.jsonl")
    eng = InflammationEngine(host="h", clock=clock, store=store)
    inc = eng.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/a",)))
    eng.ingest(DangerSignal("network_ioc", "n", 80, entities=("file:/a",)))
    with (tmp_path / "inc.jsonl").open("a", encoding="utf-8") as f:
        f.write("{corrupted line\n")
    latest = store.load_latest()
    assert list(latest) == [inc.incident_id]
    assert latest[inc.incident_id]["severity"] == LEVEL_SYSTEMIC
    assert latest[inc.incident_id]["last_transition"] == TRANSITION_ESCALATED


def test_cli_incidents_list_and_show(tmp_path, clock, capsys):
    from biocybe.cli import main

    store_path = tmp_path / "inc.jsonl"
    eng = InflammationEngine(host="h", clock=clock, store=IncidentStore(store_path))
    exe = str(tmp_path / "dropper.exe")
    inc = eng.ingest(from_watch_event(_watch_event(exe)))
    eng.ingest(from_connection_record(_conn_record(exe)))

    rc = main(["incidents", "list", "--store", str(store_path)])
    out = capsys.readouterr().out
    assert rc == 2  # systémique ouvert
    assert inc.incident_id in out and "SYST" in out

    rc = main(["incidents", "show", inc.incident_id[-6:], "--store", str(store_path)])
    out = capsys.readouterr().out
    assert rc == 0 and "Chronologie" in out and "network_ioc" in out

    rc = main(["incidents", "list", "--store", str(store_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["kinds"] == ["file_malware", "network_ioc"]

    assert main(["incidents", "show", "nope", "--store", str(store_path)]) == 1


def test_cli_incidents_list_empty_store(tmp_path):
    from biocybe.cli import main

    assert main(["incidents", "list", "--store", str(tmp_path / "none.jsonl")]) == 0


def test_daemon_builder_wires_audit_and_notify(tmp_path, monkeypatch):
    """Le builder du daemon : audit + notify sur chaque transition."""
    from biocybe import cli

    audited = []
    monkeypatch.setattr("biocybe.audit.audit", lambda action, **kw: audited.append(action))
    notified = []
    mgr = SimpleNamespace(notify=lambda ev: notified.append(ev))
    eng = cli._build_inflammation_from_config(
        {"inflammation": {"store_path": str(tmp_path / "i.jsonl")}}, mgr
    )
    assert eng is not None
    eng.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/a",)))
    eng.ingest(DangerSignal("network_ioc", "n", 80, entities=("file:/a",)))
    assert audited == ["incident_opened", "incident_escalated"]
    assert [e.severity.value for e in notified] == ["warning", "critical"]
    assert notified[-1].kind.value == "incident"


def test_daemon_builder_can_be_disabled():
    from biocybe import cli

    assert cli._build_inflammation_from_config({"inflammation": {"enabled": False}}, None) is None


def test_nk_only_on_correlated_systemic(tmp_path, monkeypatch):
    """La NK n'est sollicitée que pour un incident SYSTÉMIQUE corroboré
    par >= 2 types de signaux, une seule fois par incident."""
    from biocybe import cli

    calls = []

    class FakeNK:
        def evaluate(self, **kw):
            calls.append(kw)
            return kw

        def respond(self, decision):
            return None

    monkeypatch.setattr(cli, "_build_nk_cell_from_config", lambda cfg: FakeNK())
    eng = cli._build_inflammation_from_config(
        {"inflammation": {"store_path": str(tmp_path / "i.jsonl"), "nk_on_systemic": True}}, None
    )
    # Systémique par un seul type de signal : pas d'action
    eng.ingest(DangerSignal("network_ioc", "n", 100, entities=("pid:1",)))
    eng.ingest(DangerSignal("network_ioc", "n", 100, entities=("pid:1",)))
    assert calls == []
    # Kill chain corrélée : action sur le pid
    eng.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/b", "pid:2")))
    eng.ingest(DangerSignal("network_ioc", "n", 90, entities=("file:/b", "pid:2")))
    assert [c["pid"] for c in calls] == [2]
    eng.ingest(DangerSignal("network_ioc", "n", 90, entities=("pid:2",)))
    assert len(calls) == 1


def test_bus_cell_routes_anomalies_and_ignores_rest(clock):
    from biocybe.biocybe_core import CellMessage
    from biocybe.inflammation import InflammationCell

    eng = InflammationEngine(host="h", clock=clock)
    eng.ingest(DangerSignal("file_malware", "w", 70, entities=("file:/a",)))
    cell = InflammationCell(eng)
    assert cell.handle_message(CellMessage("system_health", "macro", payload={})) is False
    ok = cell.handle_message(
        CellMessage(
            "alert_anomaly",
            "t_cell_main",
            payload={"type": "behavioral_outlier", "explanation": {}, "detected_by": "t_cell_main"},
        )
    )
    assert ok is True
    inc = eng.open_incidents()[0]
    assert inc.signals[-1].kind == "behavior_anomaly"
    assert inc.signals[-1].correlation == "temporal"


def test_habituation_floor_resists_pre_flooding(engine, clock):
    """Anti-contournement : un attaquant inonde d'abord une entité de
    signaux réseau faibles, puis le vrai IOC fort du même type doit garder
    au moins la moitié de son poids et ouvrir un incident."""
    for _ in range(200):
        engine.ingest(DangerSignal("network_ioc", "netmon", 5, entities=("pid:66",)))
        clock.advance(1)
    inc = engine.ingest(DangerSignal("network_ioc", "netmon", 95, entities=("pid:66",)))
    assert inc is not None, "le vrai C2 ne doit pas être rendu invisible par le bruit"
    assert inc.signals[-1].habituation == pytest.approx(0.5)
    assert inc.signals[-1].contribution >= 95 * 0.5 - 1e-6


def test_habituation_weak_signal_floor(engine, clock):
    for _ in range(500):
        engine.ingest(DangerSignal("x", "t", 20, entities=("file:/z",)))
    last = engine._tissues["file:/z"]
    assert last.repeats["x"][0] > 100
    sig = DangerSignal("x", "t", 20, entities=("file:/z",))
    _, contrib, habit = engine._inflame("file:/z", sig, 1.0, clock())
    assert habit == pytest.approx(0.1) and contrib == pytest.approx(2.0)


def test_habituation_floor_config_validation():
    with pytest.raises(ValueError):
        InflammationConfig.from_dict({"habituation_floor": 0.8, "strong_habituation_floor": 0.5})
