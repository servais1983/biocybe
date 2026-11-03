"""Couverture MITRE : suite de non-régression de détection (rejeu)."""

from __future__ import annotations

import json

from biocybe.coverage import CORPUS, navigator_layer, run_coverage


def test_no_detection_regression():
    """Chaque cas du corpus donne exactement le résultat attendu.

    Si ce test casse : soit une règle/le moteur a régressé, soit la
    couverture a progressé et le corpus doit être mis à jour (expected).
    """
    report = run_coverage()
    bad = [(r["technique"], r["result"], r["expected"]) for r in report["regressions"]]
    assert bad == []


def test_corpus_includes_known_gaps_honestly():
    results = {c.technique: c.expected for c in CORPUS}
    # T1055 observable via injmon (traces mémoire) ; le hollowing propre reste aveugle
    assert results["T1055"] == "local"
    assert results["T1055.012"] == "not_observable"
    # T1071.004 devenu observable avec le capteur DNS (dnsmon)
    assert results["T1071.004"] == "local"
    assert sum(1 for c in CORPUS if c.expected == "not_observable") >= 1
    assert sum(1 for c in CORPUS if c.tactic == "chain") >= 2


def test_report_aggregates():
    report = run_coverage()
    c = report["counts"]
    assert sum(c.values()) == report["total"] == len(CORPUS)
    assert 0 < report["incident_rate"] <= report["visibility_rate"] <= 1
    assert report["by_tactic"]["impact"]["systemic"] >= 2


def test_rule_removal_is_caught_as_regression():
    """Désactiver une règle doit faire échouer la mesure (garde-fou réel)."""
    from biocybe.process_monitor import load_rules

    rules = load_rules()
    for r in rules:
        if r.rule_id == "shadow_copy_deletion":
            r.enabled = False
    report = run_coverage(rules=rules)
    assert any(r["technique"] == "T1490" for r in report["regressions"])


def test_navigator_layer_format():
    layer = navigator_layer(run_coverage())
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1490"]["score"] == 100
    assert by_id["T1055.012"]["score"] == 0
    assert all("+" not in t for t in by_id)  # chaînes exclues de la couche
    json.dumps(layer)


def test_cli_coverage(tmp_path, capsys):
    from biocybe import cli

    nav = tmp_path / "layer.json"
    assert cli.main(["coverage", "--navigator", str(nav)]) == 0
    out = capsys.readouterr().out
    assert "Couverture MITRE ATT&CK" in out and "Trous identifiés" in out
    assert json.loads(nav.read_text("utf-8"))["techniques"]
