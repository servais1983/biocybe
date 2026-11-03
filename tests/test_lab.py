"""Scorecard de validation en labo (plan d'exécution vs incidents réels)."""

from __future__ import annotations

import json

import pytest

from biocybe.inflammation import DangerSignal, IncidentStore, InflammationEngine
from biocybe.lab import load_plan, score

T0 = 1_700_000_000.0


def _lab_incidents(tmp_path):
    """Ce qu'aurait produit BioCybe pendant la session de labo."""
    clock = [T0]
    store = IncidentStore(tmp_path / "incidents.jsonl")
    eng = InflammationEngine(host="lab", clock=lambda: clock[0], store=store)
    # T1490 joué à T0 -> détecté 4 s plus tard (systémique : signal critique)
    clock[0] = T0 + 4
    eng.ingest(
        DangerSignal(
            "process:shadow_copy_deletion",
            "procmon",
            90,
            entities=("file:/w/vss",),
            mitre=("T1490",),
        )
    )
    # T1003.001 joué à T0+600 -> détecté 2 s plus tard
    clock[0] = T0 + 602
    eng.ingest(
        DangerSignal(
            "process:lsass_memory_dump",
            "procmon",
            90,
            entities=("file:/w/r",),
            mitre=("T1003.001",),
        )
    )
    # Bruit sans rapport avec le plan (FP probable)
    clock[0] = T0 + 900
    eng.ingest(DangerSignal("x", "t", 70, entities=("file:/w/backup",), mitre=("T1105",)))
    return store


def _plan(tmp_path, rows):
    p = tmp_path / "plan.csv"
    p.write_text("technique,executed_at,test_name,host\n" + "\n".join(rows) + "\n", "utf-8")
    return p


def test_scorecard_detection_latency_missed_and_unexplained(tmp_path):
    store = _lab_incidents(tmp_path)
    plan = _plan(
        tmp_path,
        [
            f"T1490,{T0},Atomic T1490-1,lab-win01",
            f"t1003,{T0 + 600},Atomic T1003.001-2,lab-win01",  # technique parente, casse libre
            f"T1053.005,{T0 + 1200},Atomic T1053.005-1,lab-win01",  # rien produit -> raté
        ],
    )
    card = score(load_plan(plan), store.load_latest())
    by = {r["technique"]: r for r in card["results"]}
    assert by["T1490"]["result"] == "systemic" and by["T1490"]["latency_seconds"] == 4.0
    assert by["T1003"]["result"] == "systemic" and by["T1003"]["latency_seconds"] == 2.0
    assert by["T1053.005"]["result"] == "missed" and by["T1053.005"]["incidents"] == []
    assert card["detected"] == 2 and card["missed"] == 1
    assert card["detection_rate"] == pytest.approx(0.667, abs=1e-3)
    assert [u["mitre"] for u in card["unexplained_incidents"]] == [["T1105"]]


def test_detection_outside_window_does_not_count(tmp_path):
    store = _lab_incidents(tmp_path)
    plan = _plan(tmp_path, [f"T1490,{T0 - 5000},trop tôt,lab"])
    card = score(load_plan(plan), store.load_latest(), window_seconds=600)
    assert card["results"][0]["result"] == "missed"


def test_iso_dates_and_invalid_plans(tmp_path):
    from datetime import datetime

    iso = datetime.fromtimestamp(T0).isoformat()
    runs = load_plan(_plan(tmp_path, [f"T1490,{iso},,"]))
    assert runs[0].executed_at == pytest.approx(T0)

    bad = tmp_path / "bad.csv"
    bad.write_text("technique,when\nT1490,x\n", "utf-8")
    with pytest.raises(ValueError, match="executed_at"):
        load_plan(bad)
    bad.write_text("technique,executed_at\nT1490,pas-une-date\n", "utf-8")
    with pytest.raises(ValueError, match="ligne 2"):
        load_plan(bad)


def test_cli_lab_score(tmp_path, capsys):
    from biocybe import cli

    store = _lab_incidents(tmp_path)
    plan = _plan(tmp_path, [f"T1490,{T0},Atomic T1490-1,lab-win01"])
    rc = cli.main(["lab", "score", "--plan", str(plan), "--store", str(store.path)])
    out = capsys.readouterr().out
    assert rc == 0 and "Détectées : 1/1" in out and "non expliqués" in out
    plan2 = _plan(tmp_path, [f"T1055,{T0},injection,lab"])
    assert cli.main(["lab", "score", "--plan", str(plan2), "--store", str(store.path)]) == 1
    capsys.readouterr()
    cli.main(["lab", "score", "--plan", str(plan2), "--store", str(store.path), "--json"])
    assert json.loads(capsys.readouterr().out)["missed"] == 1
    bad = tmp_path / "x.csv"
    bad.write_text("foo\n", "utf-8")
    assert cli.main(["lab", "score", "--plan", str(bad), "--store", str(store.path)]) == 2
