"""Adaptateurs : traduisent la sortie de chaque cellule en `DangerSignal`.

Un seul endroit où l'on décide du poids et du mapping MITRE de chaque
détection. Les adaptateurs ne lèvent jamais : une entrée inattendue donne
``None`` (le signal est ignoré, la cellule émettrice n'est pas perturbée).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .engine import DangerSignal, dir_entity, file_entity

logger = logging.getLogger("biocybe.inflammation.signals")

# Poids d'une détection fichier selon la sévérité annoncée par la B-cell.
FILE_SEVERITY_WEIGHT = {"low": 25.0, "medium": 45.0, "high": 65.0, "critical": 85.0}

# MITRE ATT&CK — volontairement prudent : on ne mappe que ce que le signal
# établit réellement (pas de technique « devinée »).
MITRE_INGRESS_TOOL = "T1105"  # Ingress Tool Transfer (fichier malveillant déposé)
MITRE_APP_LAYER_C2 = "T1071"  # Application Layer Protocol (C2)
MITRE_ENCRYPT_IMPACT = "T1486"  # Data Encrypted for Impact
MITRE_STORED_DATA_MANIP = "T1565.001"  # Stored Data Manipulation
MITRE_NON_STANDARD_PORT = "T1571"  # Non-Standard Port


def from_watch_event(ev: Any, *, source: str = "watcher") -> DangerSignal | None:
    """WatchEvent malveillant (watcher temps réel) → signal ``file_malware``."""
    try:
        if not getattr(ev, "is_malicious", False):
            return None
        res = ev.result
        severity = str(getattr(res, "severity", "medium") or "medium").lower()
        weight = FILE_SEVERITY_WEIGHT.get(severity, 45.0)
        family = getattr(res, "malware_family", None)
        rules = [m.get("rule") for m in (getattr(res, "matched_rules", None) or []) if m]
        rules = [r for r in rules if r]
        mitre = [MITRE_INGRESS_TOOL]
        if family and "ransom" in str(family).lower():
            mitre.append(MITRE_ENCRYPT_IMPACT)
        path = Path(ev.path)
        return DangerSignal(
            kind="file_malware",
            source=source,
            weight=weight,
            entities=(file_entity(path),),
            summary=f"{path.name} : YARA={','.join(rules) or '?'} famille={family or '?'}",
            mitre=tuple(mitre),
            details={
                "path": str(path),
                "severity": severity,
                "family": family,
                "rules": rules,
                "quarantined": getattr(ev, "quarantine", None) is not None,
            },
        )
    except Exception as exc:
        logger.debug("from_watch_event: entrée ignorée (%s)", exc)
        return None


def from_connection_record(record: Any, *, source: str = "netmon") -> DangerSignal | None:
    """ConnectionRecord avec IOC (netmon) → signal ``network_ioc``."""
    try:
        hit = getattr(record, "hit", None)
        if hit is None:
            return None
        conf = getattr(hit, "confidence", None)
        weight = float(conf) if conf is not None else 60.0
        entities = []
        exe = getattr(record, "process_exe", None)
        if exe:
            entities.append(file_entity(exe))
        pid = getattr(record, "pid", None)
        if pid is not None:
            entities.append(f"pid:{pid}")
        ioc_type = getattr(hit, "ioc_type", None) or "ioc"
        ioc_value = getattr(hit, "value", None)
        if ioc_value:
            entities.append(f"ioc:{ioc_type}:{str(ioc_value).lower()}")
        name = getattr(record, "process_name", None) or "?"
        raddr = getattr(record, "raddr", None)
        return DangerSignal(
            kind="network_ioc",
            source=source,
            weight=weight,
            entities=tuple(entities),
            summary=f"{name} (pid {pid}) → {raddr} [{getattr(hit, 'source', '?')}"
            f"/{getattr(hit, 'malware', None) or '?'}]",
            mitre=(MITRE_APP_LAYER_C2,),
            details={
                "pid": pid,
                "process_name": name,
                "process_exe": exe,
                "remote": raddr,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "feed": getattr(hit, "source", None),
                "malware": getattr(hit, "malware", None),
                "confidence": conf,
            },
        )
    except Exception as exc:
        logger.debug("from_connection_record: entrée ignorée (%s)", exc)
        return None


def from_regen_event(kind: str, payload: dict[str, Any]) -> DangerSignal | None:
    """Événement d'auto-régénération (watcher) → ``integrity_drift`` ou
    ``ransomware_burst``."""
    try:
        if kind == "drift":
            path = Path(payload["path"])
            return DangerSignal(
                kind="integrity_drift",
                source="regeneration",
                weight=12.0,
                entities=(dir_entity(path.parent),),
                summary=f"drift sur fichier protégé {path.name}",
                mitre=(MITRE_STORED_DATA_MANIP,),
                details={"path": str(path)},
                host_factor=0.5,
            )
        if kind == "burst":
            paths = [Path(p) for p in payload.get("paths") or []]
            dirs = list(dict.fromkeys(dir_entity(p.parent) for p in paths))[:10]
            count = int(payload.get("window_count") or len(paths))
            return DangerSignal(
                kind="ransomware_burst",
                source="regeneration",
                weight=90.0,
                entities=tuple(dirs),
                summary=f"rafale : {count} fichiers protégés modifiés "
                f"({'auto-heal' if payload.get('auto_heal') else 'alerte'})",
                mitre=(MITRE_ENCRYPT_IMPACT, MITRE_STORED_DATA_MANIP),
                details={
                    "window_count": count,
                    "paths": [str(p) for p in paths[:50]],
                    "auto_heal": bool(payload.get("auto_heal")),
                },
                # Une rafale ransomware est un danger pour tout l'hôte.
                host_factor=1.0,
            )
    except Exception as exc:
        logger.debug("from_regen_event: entrée ignorée (%s)", exc)
    return None


def from_cell_message(msg_type: str, payload: Any, source: str) -> list[DangerSignal]:
    """Messages du bus (lymphocyte T, macrophage) → signaux.

    - ``alert_anomaly`` / ``behavioral_outlier`` (T-cell) : anomalie hôte,
      sans entité reliante → corrélation temporelle uniquement.
    - ``alert_anomaly`` (macrophage) : une entrée par anomalie ; les
      connexions/processus suspects portent un PID → entité reliante.
    """
    if msg_type != "alert_anomaly" or not isinstance(payload, dict):
        return []
    out: list[DangerSignal] = []
    try:
        if payload.get("type") == "behavioral_outlier":
            expl = payload.get("explanation") or {}
            score = expl.get("anomaly_score")
            top = (expl.get("top_features") or [{}])[0]
            out.append(
                DangerSignal(
                    kind="behavior_anomaly",
                    source=payload.get("detected_by") or source,
                    weight=30.0,
                    summary=f"anomalie comportementale (score={score}, "
                    f"top={top.get('name')} z={top.get('z_score')})",
                    details={"anomaly_score": score, "top_feature": top},
                    host_factor=1.0,
                )
            )
            return out

        # CPU/mémoire haute = signaux faibles (fréquents sur un hôte chargé) ;
        # process/connexion suspects (avec PID) = signaux forts.
        sev_weight = {"low": 5.0, "medium": 10.0, "high": 35.0}
        for anomaly in payload.get("anomalies") or []:
            a_type = anomaly.get("type") or payload.get("type") or "anomaly"
            details = anomaly.get("details") or {}
            weight = sev_weight.get(str(anomaly.get("severity", "medium")), 10.0)
            entities = []
            pid = details.get("pid") if isinstance(details, dict) else None
            if pid is not None:
                entities.append(f"pid:{pid}")
            mitre = (MITRE_NON_STANDARD_PORT,) if a_type == "suspicious_network_connection" else ()
            out.append(
                DangerSignal(
                    kind=f"macrophage_{a_type}",
                    source=payload.get("detected_by") or source,
                    weight=weight,
                    entities=tuple(entities),
                    summary=f"{a_type}" + (f" (pid {pid})" if pid is not None else ""),
                    mitre=mitre,
                    details=details if isinstance(details, dict) else {"raw": str(details)},
                    host_factor=0.5,
                )
            )
    except Exception as exc:
        logger.debug("from_cell_message: entrée ignorée (%s)", exc)
    return out
