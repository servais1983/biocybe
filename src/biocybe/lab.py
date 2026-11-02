"""Scorecard de validation en labo — mesurer contre de vraies techniques.

``biocybe coverage`` mesure la logique de détection sur de la télémétrie
synthétique. Ici, on mesure **ce qui s'est vraiment passé** dans un labo
isolé : l'équipe exécute des tests publiés (Atomic Red Team, Caldera...)
et consigne chaque exécution dans un plan CSV ; ce module confronte ce plan
aux incidents réellement produits par BioCybe.

Plan CSV (en-tête obligatoire) ::

    technique,executed_at,test_name,host
    T1490,2026-11-03T10:15:00,Atomic T1490-1,lab-win01

``executed_at`` : ISO 8601 (heure locale ou avec fuseau) ou epoch.
Une exécution est **détectée** si un incident dont les techniques MITRE
contiennent la technique jouée (ou une sous-technique / technique parente)
a été ouvert ou mis à jour dans la fenêtre ``[executed_at - skew,
executed_at + window]``. La latence = premier signal correspondant -
exécution.

Les incidents qui ne correspondent à AUCUNE exécution du plan sont
rapportés comme **non expliqués** : soit de vrais faux positifs, soit du
bruit d'outillage — à qualifier (``biocybe incidents mark``).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class PlannedRun:
    technique: str
    executed_at: float
    test_name: str = ""
    host: str = ""


def _parse_time(value: str) -> float:
    value = (value or "").strip()
    try:
        return float(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise ValueError(f"executed_at illisible : {value!r}") from exc


def load_plan(path: str | Path) -> list[PlannedRun]:
    runs = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = {"technique", "executed_at"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"colonnes manquantes dans le plan : {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            tech = (row.get("technique") or "").strip().upper()
            if not tech:
                continue
            try:
                ts = _parse_time(row.get("executed_at", ""))
            except ValueError as exc:
                raise ValueError(f"ligne {i} : {exc}") from exc
            runs.append(
                PlannedRun(
                    technique=tech,
                    executed_at=ts,
                    test_name=(row.get("test_name") or "").strip(),
                    host=(row.get("host") or "").strip(),
                )
            )
    return runs


def _technique_matches(planned: str, seen: str) -> bool:
    """T1003 joué ↔ T1003.001 vu (et inversement) comptent comme correspondance."""
    return seen == planned or seen.startswith(planned + ".") or planned.startswith(seen + ".")


def _signal_times(incident: dict[str, Any], technique: str) -> list[float]:
    times = [
        float(s.get("timestamp") or 0)
        for s in incident.get("signals") or []
        if any(_technique_matches(technique, m) for m in s.get("mitre") or [])
    ]
    return sorted(t for t in times if t)


def score(
    runs: list[PlannedRun],
    incidents: dict[str, dict[str, Any]],
    *,
    window_seconds: float = 600.0,
    skew_seconds: float = 60.0,
) -> dict[str, Any]:
    results = []
    explained: set[str] = set()
    for run in runs:
        lo, hi = run.executed_at - skew_seconds, run.executed_at + window_seconds
        matched = []
        first_signal = None
        for inc_id, inc in incidents.items():
            if not any(_technique_matches(run.technique, m) for m in inc.get("mitre") or []):
                continue
            times = [t for t in _signal_times(inc, run.technique) if lo <= t <= hi]
            if not times:
                continue
            matched.append(inc)
            explained.add(inc_id)
            first_signal = min(times) if first_signal is None else min(first_signal, min(times))
        if not matched:
            result = "missed"
        elif any(i.get("severity") == "systemic" for i in matched):
            result = "systemic"
        else:
            result = "local"
        results.append(
            {
                "technique": run.technique,
                "test_name": run.test_name,
                "host": run.host,
                "executed_at": run.executed_at,
                "result": result,
                "latency_seconds": (
                    round(max(0.0, first_signal - run.executed_at), 1)
                    if first_signal is not None
                    else None
                ),
                "incidents": [i.get("incident_id") for i in matched],
            }
        )
    unexplained = [
        {
            "incident_id": i.get("incident_id"),
            "severity": i.get("severity"),
            "kinds": i.get("kinds"),
            "mitre": i.get("mitre"),
            "disposition": i.get("disposition"),
        }
        for inc_id, i in incidents.items()
        if inc_id not in explained
    ]
    detected = [r for r in results if r["result"] != "missed"]
    latencies = sorted(r["latency_seconds"] for r in detected if r["latency_seconds"] is not None)
    return {
        "executions": len(results),
        "detected": len(detected),
        "systemic": sum(1 for r in results if r["result"] == "systemic"),
        "missed": sum(1 for r in results if r["result"] == "missed"),
        "detection_rate": round(len(detected) / len(results), 3) if results else 0.0,
        "latency_median_seconds": latencies[len(latencies) // 2] if latencies else None,
        "latency_max_seconds": latencies[-1] if latencies else None,
        "unexplained_incidents": unexplained,
        "results": results,
    }


def format_scorecard(card: dict[str, Any]) -> str:
    lines = [
        f"Validation labo — {card['executions']} exécution(s) du plan",
        f"  Détectées : {card['detected']}/{card['executions']} "
        f"({card['detection_rate']:.0%}) dont systémiques {card['systemic']} — "
        f"manquées {card['missed']}",
        f"  Latence : médiane {card['latency_median_seconds']}s, "
        f"max {card['latency_max_seconds']}s",
        f"  Incidents non expliqués par le plan (FP probables) : "
        f"{len(card['unexplained_incidents'])}",
        "",
    ]
    tag = {"systemic": "SYST", "local": "LOC ", "missed": "RATÉ"}
    for r in card["results"]:
        when = datetime.fromtimestamp(r["executed_at"]).strftime("%Y-%m-%d %H:%M:%S")
        lat = f"{r['latency_seconds']}s" if r["latency_seconds"] is not None else "-"
        lines.append(
            f"  [{tag[r['result']]}] {r['technique']:<11} {when} {r['host'][:14]:<14} "
            f"latence={lat:<7} {r['test_name'][:40]}"
        )
    if card["unexplained_incidents"]:
        lines += ["", "Incidents non expliqués (à qualifier : biocybe incidents mark) :"]
        lines += [
            f"  - {u['incident_id']} [{u['severity']}] {','.join(u['kinds'] or [])}"
            f"{' (' + u['disposition'] + ')' if u.get('disposition') else ''}"
            for u in card["unexplained_incidents"]
        ]
    return "\n".join(lines)
