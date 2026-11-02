"""Moteur inflammatoire — corrélation des signaux de danger entre cellules.

Métaphore biologique (Danger Theory, P. Matzinger, 1994)
--------------------------------------------------------
Le système immunitaire ne réagit pas à « tout ce qui est étranger », mais
aux **signaux de danger** émis par les tissus agressés. Un signal isolé
reste local et s'éteint ; plusieurs signaux *différents* convergeant sur le
même tissu (co-stimulation) déclenchent une réponse inflammatoire, puis
systémique (fièvre) si le danger persiste. Quand l'agression cesse, la
réponse se **résout** d'elle-même (homéostasie).

Traduction cyber
----------------
Jusqu'ici chaque cellule BioCybe alertait seule : le watcher sur un fichier,
le netmon sur une connexion C2, la régénération sur une rafale de drift, le
lymphocyte T sur une anomalie. Un SOC voit 4 alertes sans lien. Ce moteur :

  - reçoit des `DangerSignal` de toutes les cellules ;
  - maintient un **niveau de danger par entité** (fichier, PID, IOC,
    dossier, hôte) qui **décroît exponentiellement** (demi-vie) ;
  - applique une **co-stimulation** : un signal d'un type *nouveau* pour
    l'entité pèse plus lourd (fichier malveillant PUIS connexion C2 depuis
    ce même exécutable = kill chain, pas deux bruits indépendants) ;
  - **corrèle** les signaux en `Incident` via les entités partagées
    (le chemin d'un fichier détecté == l'exe d'un process qui parle à un
    C2) et fusionne les incidents qu'un signal relie ;
  - escalade LOCAL → SYSTÉMIQUE, puis **résout** l'incident quand le
    niveau retombe (hystérésis : seuil de résolution << seuil d'ouverture).

Garanties
---------
  - Déterministe et testable : horloge injectable, aucune I/O dans le cœur.
  - Mémoire bornée : cap d'entités, de signaux par incident, d'incidents
    clos conservés.
  - Thread-safe ; les callbacks sont appelés HORS verrou et ne peuvent pas
    casser le moteur.
  - Explicable : chaque incident porte sa chronologie, la contribution de
    chaque signal, le facteur de co-stimulation et les techniques MITRE.
  - Ne décide rien de destructif : il émet des transitions ; la réponse
    (notification, NK) reste décidée par l'appelant et ses garde-fous.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.inflammation")

# --------------------------------------------------------------------------- #
# Vocabulaire
# --------------------------------------------------------------------------- #

LEVEL_CALM = "calm"
LEVEL_LOCAL = "local"  # inflammation locale : incident ouvert
LEVEL_SYSTEMIC = "systemic"  # réponse systémique : danger corrélé/élevé

_LEVEL_RANK = {LEVEL_CALM: 0, LEVEL_LOCAL: 1, LEVEL_SYSTEMIC: 2}

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"
STATUS_MERGED = "merged"

TRANSITION_OPENED = "opened"
TRANSITION_ESCALATED = "escalated"
TRANSITION_RESOLVED = "resolved"

# Préfixe des entités d'agrégation (ne servent PAS à relier des incidents,
# sinon tout signal de l'hôte fusionnerait tout en un seul incident).
HOST_PREFIX = "host:"


def file_entity(path: str | os.PathLike) -> str:
    """Entité canonique d'un fichier / exécutable.

    Le MÊME espace de noms sert pour un fichier détecté par le watcher et
    pour l'exe d'un process vu par le netmon : c'est ce qui permet de relier
    « fichier déposé » et « ce fichier parle à un C2 ».
    """
    return "file:" + os.path.normcase(os.path.abspath(os.fspath(path)))


def dir_entity(path: str | os.PathLike) -> str:
    return "dir:" + os.path.normcase(os.path.abspath(os.fspath(path)))


def host_entity(name: str | None = None) -> str:
    return HOST_PREFIX + (name or socket.gethostname() or "localhost")


# --------------------------------------------------------------------------- #
# Modèle
# --------------------------------------------------------------------------- #


@dataclass
class DangerSignal:
    """Un signal de danger émis par une cellule.

    Attributes:
        kind: famille du signal (``file_malware``, ``network_ioc``,
            ``ransomware_burst``, ``integrity_drift``, ``behavior_anomaly``...).
            La co-stimulation compte les *kinds* distincts.
        source: cellule émettrice (``watcher``, ``netmon``, ``t_cell_main``...).
        weight: intensité 0-100 (sévérité x confiance de la cellule).
        entities: entités *reliantes* touchées (fichier, pid, ioc, dossier).
        summary: phrase courte lisible par un analyste.
        mitre: techniques ATT&CK associées (ex. ``("T1071",)``).
        details: contexte brut (sérialisable JSON).
        host_factor: part du poids propagée au niveau hôte (fièvre globale).
    """

    kind: str
    source: str
    weight: float
    entities: tuple[str, ...] = ()
    summary: str = ""
    mitre: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    host_factor: float | None = None
    timestamp: float | None = None
    signal_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        self.weight = max(0.0, min(100.0, float(self.weight)))
        # Dédoublonne en gardant l'ordre ; ignore les entités vides et
        # l'agrégat hôte (géré à part).
        seen: dict[str, None] = {}
        for e in self.entities:
            if e and not e.startswith(HOST_PREFIX):
                seen.setdefault(e, None)
        self.entities = tuple(seen)
        self.mitre = tuple(dict.fromkeys(m for m in self.mitre if m))


@dataclass
class SignalContribution:
    """Trace explicable de l'effet d'un signal sur un incident."""

    signal_id: str
    timestamp: float
    kind: str
    source: str
    summary: str
    weight: float
    costim_factor: float
    contribution: float
    entities: tuple[str, ...]
    mitre: tuple[str, ...]
    details: dict[str, Any]
    correlation: str  # "entity" | "temporal" | "precursor"
    habituation: float = 1.0
    tolerance: float = 1.0  # appris des incidents qualifiés (<1 FP, >1 TP)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "source": self.source,
            "summary": self.summary,
            "weight": round(self.weight, 2),
            "costim_factor": round(self.costim_factor, 2),
            "habituation": round(self.habituation, 3),
            "tolerance": round(self.tolerance, 3),
            "contribution": round(self.contribution, 2),
            "entities": list(self.entities),
            "mitre": list(self.mitre),
            "details": self.details,
            "correlation": self.correlation,
        }


@dataclass
class Incident:
    """Ensemble de signaux corrélés = un incident à traiter par le SOC."""

    incident_id: str
    opened_at: float
    host: str
    severity: str = LEVEL_LOCAL
    status: str = STATUS_OPEN
    entities: set[str] = field(default_factory=set)
    signals: list[SignalContribution] = field(default_factory=list)
    signals_total: int = 0
    peak_level: float = 0.0
    current_level: float = 0.0
    updated_at: float = 0.0
    escalated_at: float | None = None
    resolved_at: float | None = None
    merged_into: str | None = None
    merged_from: list[str] = field(default_factory=list)

    # ---- dérivés -------------------------------------------------------

    @property
    def kinds(self) -> list[str]:
        return sorted({s.kind for s in self.signals})

    @property
    def mitre(self) -> list[str]:
        return sorted({m for s in self.signals for m in s.mitre})

    @property
    def sources(self) -> list[str]:
        return sorted({s.source for s in self.signals})

    @property
    def pids(self) -> list[int]:
        out = []
        for e in self.entities:
            if e.startswith("pid:"):
                try:
                    out.append(int(e[4:]))
                except ValueError:
                    pass
        return sorted(out)

    def explain(self) -> str:
        """Résumé lisible (français) : pourquoi cet incident existe."""
        label = "SYSTÉMIQUE" if self.severity == LEVEL_SYSTEMIC else "LOCAL"
        lines = [
            f"Incident {self.incident_id} [{label}] — statut {self.status}, "
            f"niveau {self.current_level:.0f} (pic {self.peak_level:.0f}), "
            f"{self.signals_total} signal(aux) de {len(self.kinds)} type(s) : "
            f"{', '.join(self.kinds) or '-'}",
        ]
        if self.mitre:
            lines.append(f"  MITRE ATT&CK : {', '.join(self.mitre)}")
        linking = sorted(e for e in self.entities if not e.startswith(HOST_PREFIX))
        if linking:
            shown = ", ".join(linking[:6]) + (" …" if len(linking) > 6 else "")
            lines.append(f"  Entités : {shown}")
        lines.append("  Chronologie :")
        t0 = self.signals[0].timestamp if self.signals else self.opened_at
        for s in self.signals[-15:]:
            costim = f" x{s.costim_factor:.2f} co-stim" if s.costim_factor > 1.0 else ""
            if s.habituation < 0.99:
                costim += f" x{s.habituation:.2f} accoutumance"
            if s.tolerance < 0.99:
                costim += f" x{s.tolerance:.2f} tolérance (FP appris)"
            elif s.tolerance > 1.01:
                costim += f" x{s.tolerance:.2f} mémoire (TP appris)"
            corr = {"temporal": " [corr. temporelle hôte]", "precursor": " [précurseur]"}.get(
                s.correlation, ""
            )
            lines.append(
                f"    +{s.timestamp - t0:6.1f}s  {s.kind:<18} {s.source:<14} "
                f"poids {s.weight:.0f}{costim} → +{s.contribution:.0f}{corr}  {s.summary}"
            )
        if self.signals_total > len(self.signals):
            lines.append(f"    … {self.signals_total - len(self.signals)} signal(aux) plus anciens")
        return "\n".join(lines)

    def to_dict(self, *, max_signals: int | None = None) -> dict[str, Any]:
        sigs = self.signals if max_signals is None else self.signals[-max_signals:]
        return {
            "incident_id": self.incident_id,
            "host": self.host,
            "severity": self.severity,
            "status": self.status,
            "opened_at": self.opened_at,
            "updated_at": self.updated_at,
            "escalated_at": self.escalated_at,
            "resolved_at": self.resolved_at,
            "peak_level": round(self.peak_level, 2),
            "current_level": round(self.current_level, 2),
            "entities": sorted(self.entities),
            "kinds": self.kinds,
            "sources": self.sources,
            "mitre": self.mitre,
            "pids": self.pids,
            "signals_total": self.signals_total,
            "signals": [s.to_dict() for s in sigs],
            "merged_into": self.merged_into,
            "merged_from": list(self.merged_from),
            "explanation": self.explain(),
        }


@dataclass
class _Tissue:
    """État inflammatoire d'une entité."""

    level: float = 0.0
    last_ts: float = 0.0
    kinds: dict[str, float] = field(default_factory=dict)  # kind -> dernier ts
    # kind -> [compteur décroissant, ts] : base de l'accoutumance
    repeats: dict[str, list[float]] = field(default_factory=dict)
    recent: deque = field(default_factory=lambda: deque(maxlen=20))  # précurseurs


@dataclass
class InflammationConfig:
    """Paramètres du moteur (tous surchargeables via config.inflammation)."""

    local_threshold: float = 50.0
    systemic_threshold: float = 120.0
    resolve_threshold: float = 10.0
    half_life_seconds: float = 900.0  # 15 min
    costim_bonus: float = 0.5  # +50 % par type de signal distinct déjà présent
    costim_max_factor: float = 3.0
    # Accoutumance : le n-ième signal du même type sur la même entité pèse
    # weight / (1 + n_récents). Empêche une source bavarde (anomalie CPU
    # durable, beacon C2 toutes les 5 s) de faire exploser le niveau seule.
    habituation: bool = True
    # Plancher d'accoutumance (anti-contournement) : sans plancher, un
    # attaquant peut d'abord inonder une entité de signaux anodins d'un type
    # pour « désensibiliser » le moteur, puis faire passer le vrai signal du
    # même type à poids quasi nul. Un signal ne descend jamais sous
    # `habituation_floor` de son poids, et un signal FORT (>= strong_signal_weight,
    # ex. IOC haute confiance) jamais sous `strong_habituation_floor`.
    habituation_floor: float = 0.1
    strong_signal_weight: float = 60.0
    strong_habituation_floor: float = 0.5
    default_host_factor: float = 0.35
    temporal_correlation: bool = True  # signaux sans entité → incident ouvert le + récent
    max_entities: int = 10_000
    max_signals_per_incident: int = 500
    max_closed_incidents: int = 200

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> InflammationConfig:
        cfg = cls()
        for key, value in (data or {}).items():
            if hasattr(cfg, key) and value is not None:
                current = getattr(cfg, key)
                try:
                    setattr(cfg, key, type(current)(value))
                except (TypeError, ValueError):
                    logger.warning("inflammation: valeur invalide pour %s=%r ignorée", key, value)
        if not (0 < cfg.resolve_threshold < cfg.local_threshold <= cfg.systemic_threshold):
            raise ValueError(
                "inflammation: il faut 0 < resolve_threshold < local_threshold "
                "<= systemic_threshold"
            )
        if not (0.0 <= cfg.habituation_floor <= cfg.strong_habituation_floor <= 1.0):
            raise ValueError(
                "inflammation: il faut 0 <= habituation_floor <= strong_habituation_floor <= 1"
            )
        if cfg.half_life_seconds <= 0:
            raise ValueError("inflammation: half_life_seconds doit être > 0")
        return cfg


IncidentCallback = Callable[[Incident, str], None]


# --------------------------------------------------------------------------- #
# Moteur
# --------------------------------------------------------------------------- #


class InflammationEngine:
    """Corrèle les signaux de danger de toutes les cellules en incidents."""

    def __init__(
        self,
        config: InflammationConfig | None = None,
        *,
        host: str | None = None,
        clock: Callable[[], float] = time.time,
        store: IncidentStore | None = None,
        tolerance: Any = None,
    ):
        self.config = config or InflammationConfig()
        # Modèle appris (feedback analyste) : objet exposant
        # ``factor(kind, entities) -> float``. None = pas d'apprentissage.
        self._tolerance = tolerance
        self.host = host_entity(host)
        self._clock = clock
        self._store = store
        self._lock = threading.RLock()
        self._tissues: dict[str, _Tissue] = {}
        self._open: dict[str, Incident] = {}
        self._closed: deque[Incident] = deque(maxlen=self.config.max_closed_incidents)
        self._entity_index: dict[str, str] = {}  # entité reliante -> incident ouvert
        self._callbacks: list[IncidentCallback] = []
        self.stats = {
            "signals_received": 0,
            "signals_subthreshold": 0,
            "incidents_opened": 0,
            "incidents_escalated": 0,
            "incidents_resolved": 0,
            "incidents_merged": 0,
            "callback_errors": 0,
            "signals_tolerated": 0,
            "signals_reinforced": 0,
        }

    # ---- API publique ---------------------------------------------------

    def set_tolerance(self, tolerance: Any) -> None:
        """Remplace le modèle de tolérance appris (rechargement à chaud)."""
        with self._lock:
            self._tolerance = tolerance

    def subscribe(self, callback: IncidentCallback) -> None:
        """Enregistre un callback ``(incident, transition)``."""
        self._callbacks.append(callback)

    def ingest(self, signal: DangerSignal) -> Incident | None:
        """Intègre un signal. Retourne l'incident concerné (ou None si
        le signal reste sous le seuil)."""
        events: list[tuple[Incident, str]] = []
        with self._lock:
            incident = self._ingest_locked(signal, events)
        self._emit(events)
        return incident

    def tick(self) -> list[Incident]:
        """Décroissance + résolution des incidents calmés + élagage.

        À appeler périodiquement (le daemon le fait toutes les ~10 s).
        Retourne les incidents résolus pendant ce tick.
        """
        events: list[tuple[Incident, str]] = []
        now = self._clock()
        with self._lock:
            for incident in list(self._open.values()):
                level = self._incident_level(incident, now)
                incident.current_level = level
                if level < self.config.resolve_threshold:
                    incident.status = STATUS_RESOLVED
                    incident.resolved_at = now
                    incident.updated_at = now
                    self._close(incident)
                    self.stats["incidents_resolved"] += 1
                    events.append((incident, TRANSITION_RESOLVED))
            self._prune(now)
        self._emit(events)
        return [i for i, _ in events]

    def level_of(self, entity: str) -> float:
        with self._lock:
            return self._level(entity, self._clock())

    @property
    def host_level(self) -> float:
        return self.level_of(self.host)

    def open_incidents(self) -> list[Incident]:
        with self._lock:
            return sorted(self._open.values(), key=lambda i: i.opened_at)

    def closed_incidents(self) -> list[Incident]:
        with self._lock:
            return list(self._closed)

    def get(self, incident_id: str) -> Incident | None:
        with self._lock:
            if incident_id in self._open:
                return self._open[incident_id]
            return next((i for i in self._closed if i.incident_id == incident_id), None)

    def snapshot(self) -> dict[str, Any]:
        """État agrégé (dashboard / métriques)."""
        with self._lock:
            now = self._clock()
            open_inc = list(self._open.values())
            return {
                "host": self.host,
                "host_level": round(self._level(self.host, now), 2),
                "host_state": self._classify(self._level(self.host, now)),
                "open_incidents": len(open_inc),
                "open_systemic": sum(1 for i in open_inc if i.severity == LEVEL_SYSTEMIC),
                "tracked_entities": len(self._tissues),
                "thresholds": {
                    "local": self.config.local_threshold,
                    "systemic": self.config.systemic_threshold,
                    "resolve": self.config.resolve_threshold,
                    "half_life_seconds": self.config.half_life_seconds,
                },
                **self.stats,
            }

    # ---- cœur (sous verrou) ----------------------------------------------

    def _ingest_locked(
        self, signal: DangerSignal, events: list[tuple[Incident, str]]
    ) -> Incident | None:
        cfg = self.config
        now = signal.timestamp if signal.timestamp is not None else self._clock()
        signal.timestamp = now
        self.stats["signals_received"] += 1

        # 0) Tolérance / mémoire apprises des incidents qualifiés
        tol = 1.0
        if self._tolerance is not None:
            try:
                tol = float(self._tolerance.factor(signal.kind, signal.entities))
            except Exception as exc:  # un modèle cassé ne doit pas aveugler le moteur
                logger.error("inflammation: tolérance inutilisable (%s) — ignorée", exc)
                tol = 1.0
            if tol < 1.0:
                self.stats["signals_tolerated"] += 1
            elif tol > 1.0:
                self.stats["signals_reinforced"] += 1

        # 1) Inflammation des tissus touchés (avec co-stimulation par entité)
        contributions: dict[str, tuple[float, float, float]] = {}
        for ent in signal.entities:
            contributions[ent] = self._inflame(ent, signal, tol, now)
        host_factor = cfg.default_host_factor if signal.host_factor is None else signal.host_factor
        host_contrib = self._inflame(self.host, signal, host_factor * tol, now)

        # Contribution « affichée » = la plus forte sur une entité reliante,
        # sinon celle de l'hôte (signal sans entité).
        if contributions:
            best_ent = max(contributions, key=lambda e: contributions[e][1])
            costim, contrib, habit = contributions[best_ent]
        else:
            costim, contrib, habit = host_contrib

        # 2) Corrélation : incidents ouverts partageant une entité reliante
        linked_ids = []
        for ent in signal.entities:
            inc_id = self._entity_index.get(ent)
            if inc_id and inc_id in self._open and inc_id not in linked_ids:
                linked_ids.append(inc_id)

        correlation = "entity"
        incident: Incident | None = None
        if linked_ids:
            incident = self._merge([self._open[i] for i in linked_ids], now)
        elif not signal.entities and cfg.temporal_correlation and self._open:
            # Signal sans entité (anomalie hôte) : on le rattache à l'incident
            # actif le plus récent du même hôte — corrélation temporelle,
            # explicitement marquée comme telle dans la chronologie.
            incident = max(self._open.values(), key=lambda i: i.updated_at)
            correlation = "temporal"

        host_level = self._level(self.host, now)
        max_entity_level = max((self._level(e, now) for e in signal.entities), default=0.0)

        opened = False
        if incident is None:
            if max_entity_level >= cfg.local_threshold:
                incident = self._new_incident(now)
                opened = True
            elif host_level >= cfg.systemic_threshold:
                # Fièvre : beaucoup de petits signaux sur l'hôte, aucun
                # tissu isolé au-dessus du seuil -> incident « hôte ».
                incident = self._new_incident(now)
                incident.entities.add(self.host)
                opened = True
            else:
                self.stats["signals_subthreshold"] += 1
                self._remember_precursor(signal, costim, contrib, habit, tol)
                return None

        prev_severity = incident.severity

        # 3) Rattacher : précurseurs d'abord (contexte), puis le signal
        if opened:
            for ent in signal.entities:
                for pre in self._tissues.get(ent, _Tissue()).recent:
                    self._attach(incident, pre, "precursor")
        self._attach(
            incident,
            SignalContribution(
                signal_id=signal.signal_id,
                timestamp=now,
                kind=signal.kind,
                source=signal.source,
                summary=signal.summary,
                weight=signal.weight,
                costim_factor=costim,
                contribution=contrib,
                entities=signal.entities,
                mitre=signal.mitre,
                details=dict(signal.details),
                correlation=correlation,
                habituation=habit,
                tolerance=tol,
            ),
            correlation,
        )
        if correlation == "temporal":
            incident.entities.add(self.host)

        # 4) Niveau + sévérité
        level = self._incident_level(incident, now)
        incident.current_level = level
        incident.peak_level = max(incident.peak_level, level)
        incident.updated_at = now
        new_sev = LEVEL_SYSTEMIC if level >= cfg.systemic_threshold else LEVEL_LOCAL
        if host_level >= cfg.systemic_threshold:
            new_sev = LEVEL_SYSTEMIC
        if _LEVEL_RANK[new_sev] > _LEVEL_RANK[incident.severity]:
            incident.severity = new_sev

        if opened:
            self.stats["incidents_opened"] += 1
            if incident.severity == LEVEL_SYSTEMIC:
                incident.escalated_at = now
            events.append((incident, TRANSITION_OPENED))
        elif incident.severity != prev_severity:
            incident.escalated_at = now
            self.stats["incidents_escalated"] += 1
            events.append((incident, TRANSITION_ESCALATED))
        return incident

    def _inflame(
        self, entity: str, signal: DangerSignal, factor: float, now: float
    ) -> tuple[float, float, float]:
        """Ajoute la contribution du signal à une entité. Retourne
        (facteur de co-stimulation, contribution effective, accoutumance)."""
        cfg = self.config
        tissue = self._tissues.get(entity)
        if tissue is None:
            if len(self._tissues) >= cfg.max_entities:
                self._prune(now, force=True)
            tissue = _Tissue(last_ts=now)
            self._tissues[entity] = tissue
        self._decay(tissue, now)

        # Co-stimulation : nb de types DISTINCTS récents (autres que celui-ci).
        window = 3 * cfg.half_life_seconds
        others = sum(1 for k, ts in tissue.kinds.items() if k != signal.kind and now - ts <= window)
        costim = min(cfg.costim_max_factor, 1.0 + cfg.costim_bonus * others)

        habit = 1.0
        if cfg.habituation:
            count, last = tissue.repeats.get(signal.kind, (0.0, now))
            count *= 0.5 ** (max(0.0, now - last) / cfg.half_life_seconds)
            floor = (
                cfg.strong_habituation_floor
                if signal.weight >= cfg.strong_signal_weight
                else cfg.habituation_floor
            )
            habit = max(floor, 1.0 / (1.0 + count))
            tissue.repeats[signal.kind] = [count + 1.0, now]

        contribution = signal.weight * factor * costim * habit
        tissue.level += contribution
        tissue.kinds[signal.kind] = now
        return costim, contribution, habit

    def _remember_precursor(
        self,
        signal: DangerSignal,
        costim: float,
        contrib: float,
        habit: float,
        tol: float = 1.0,
    ) -> None:
        pre = SignalContribution(
            signal_id=signal.signal_id,
            timestamp=signal.timestamp or self._clock(),
            kind=signal.kind,
            source=signal.source,
            summary=signal.summary,
            weight=signal.weight,
            costim_factor=costim,
            contribution=contrib,
            entities=signal.entities,
            mitre=signal.mitre,
            details=dict(signal.details),
            correlation="precursor",
            habituation=habit,
            tolerance=tol,
        )
        for ent in signal.entities:
            tissue = self._tissues.get(ent)
            if tissue is not None:
                tissue.recent.append(pre)

    def _attach(self, incident: Incident, contrib: SignalContribution, correlation: str) -> None:
        if any(s.signal_id == contrib.signal_id for s in incident.signals[-50:]):
            return  # déjà attaché (précurseur partagé par plusieurs entités)
        if correlation == "precursor":
            contrib = SignalContribution(**{**contrib.__dict__, "correlation": "precursor"})
        incident.signals.append(contrib)
        incident.signals.sort(key=lambda s: s.timestamp)
        incident.signals_total += 1
        if len(incident.signals) > self.config.max_signals_per_incident:
            del incident.signals[: len(incident.signals) - self.config.max_signals_per_incident]
        for ent in contrib.entities:
            incident.entities.add(ent)
            self._entity_index[ent] = incident.incident_id

    def _merge(self, incidents: list[Incident], now: float) -> Incident:
        """Fusionne des incidents qu'un signal relie (garde le plus ancien)."""
        incidents = sorted(incidents, key=lambda i: i.opened_at)
        keep = incidents[0]
        for other in incidents[1:]:
            keep.entities |= other.entities
            keep.signals.extend(other.signals)
            keep.signals.sort(key=lambda s: s.timestamp)
            keep.signals_total += other.signals_total
            keep.peak_level = max(keep.peak_level, other.peak_level)
            if _LEVEL_RANK[other.severity] > _LEVEL_RANK[keep.severity]:
                keep.severity = other.severity
            keep.merged_from.append(other.incident_id)
            other.status = STATUS_MERGED
            other.merged_into = keep.incident_id
            other.updated_at = now
            self._close(other)
            self.stats["incidents_merged"] += 1
            for ent in keep.entities:
                if not ent.startswith(HOST_PREFIX):
                    self._entity_index[ent] = keep.incident_id
            self._persist(other, "merged")
        if len(keep.signals) > self.config.max_signals_per_incident:
            del keep.signals[: len(keep.signals) - self.config.max_signals_per_incident]
        return keep

    def _new_incident(self, now: float) -> Incident:
        inc_id = f"INC-{time.strftime('%Y%m%d', time.gmtime(now))}-{uuid.uuid4().hex[:6]}"
        incident = Incident(incident_id=inc_id, opened_at=now, host=self.host, updated_at=now)
        self._open[inc_id] = incident
        return incident

    def _close(self, incident: Incident) -> None:
        self._open.pop(incident.incident_id, None)
        for ent in list(incident.entities):
            if self._entity_index.get(ent) == incident.incident_id:
                del self._entity_index[ent]
        self._closed.append(incident)

    def _incident_level(self, incident: Incident, now: float) -> float:
        return max((self._level(e, now) for e in incident.entities), default=0.0)

    def _decay(self, tissue: _Tissue, now: float) -> None:
        dt = now - tissue.last_ts
        if dt > 0:
            tissue.level *= 0.5 ** (dt / self.config.half_life_seconds)
            tissue.last_ts = now

    def _level(self, entity: str, now: float) -> float:
        tissue = self._tissues.get(entity)
        if tissue is None:
            return 0.0
        dt = max(0.0, now - tissue.last_ts)
        return tissue.level * 0.5 ** (dt / self.config.half_life_seconds)

    def _classify(self, level: float) -> str:
        if level >= self.config.systemic_threshold:
            return LEVEL_SYSTEMIC
        if level >= self.config.local_threshold:
            return LEVEL_LOCAL
        return LEVEL_CALM

    def _prune(self, now: float, *, force: bool = False) -> None:
        """Oublie les tissus calmés (et non liés à un incident ouvert)."""
        floor = 0.5
        doomed = []
        for ent, tissue in self._tissues.items():
            if ent == self.host or ent in self._entity_index:
                continue
            self._decay(tissue, now)
            if tissue.level < floor:
                doomed.append(ent)
        for ent in doomed:
            del self._tissues[ent]
        if force and len(self._tissues) >= self.config.max_entities:
            # Toujours plein : on sacrifie les entités les plus calmes.
            candidates = sorted(
                (e for e in self._tissues if e != self.host and e not in self._entity_index),
                key=lambda e: self._tissues[e].level,
            )
            for ent in candidates[: max(1, len(candidates) // 10)]:
                del self._tissues[ent]

    # ---- émission -------------------------------------------------------

    def _persist(self, incident: Incident, transition: str) -> None:
        if self._store is None:
            return
        try:
            self._store.append(incident, transition)
        except Exception as exc:  # stockage = best effort, jamais bloquant
            logger.error("inflammation: persistance incident a échoué : %s", exc)

    def _emit(self, events: Iterable[tuple[Incident, str]]) -> None:
        for incident, transition in events:
            level = "warning" if transition != TRANSITION_RESOLVED else "info"
            getattr(logger, level)(
                "[INFLAMMATION] %s %s (%s, niveau %.0f, %d signaux, %s)",
                incident.incident_id,
                transition,
                incident.severity,
                incident.current_level,
                incident.signals_total,
                ",".join(incident.kinds),
            )
            self._persist(incident, transition)
            for cb in list(self._callbacks):
                try:
                    cb(incident, transition)
                except Exception as exc:
                    self.stats["callback_errors"] += 1
                    logger.error("inflammation: callback a levé %s", exc)


# --------------------------------------------------------------------------- #
# Persistance (lecture CLI / dashboard hors process daemon)
# --------------------------------------------------------------------------- #


class IncidentStore:
    """Journal JSONL append-only des transitions d'incidents.

    Chaque ligne = ``{"ts", "transition", "incident": {...}}``. Le dernier
    snapshot d'un ``incident_id`` fait foi. Lecture tolérante aux lignes
    corrompues (un crash en cours d'écriture ne rend pas le journal
    illisible).
    """

    def __init__(self, path: str | os.PathLike, *, max_signals: int = 50):
        self.path = Path(path)
        self.max_signals = max_signals
        self._lock = threading.Lock()

    def append(self, incident: Incident, transition: str) -> None:
        line = json.dumps(
            {
                "ts": time.time(),
                "transition": transition,
                "incident": incident.to_dict(max_signals=self.max_signals),
            },
            ensure_ascii=False,
            default=str,
        )
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def load_latest(self) -> dict[str, dict[str, Any]]:
        """Retourne ``{incident_id: dernier snapshot}`` (ordre d'ouverture)."""
        latest: dict[str, dict[str, Any]] = {}
        if not self.path.exists():
            return latest
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                    inc = rec["incident"]
                    inc["last_transition"] = rec.get("transition")
                    latest[inc["incident_id"]] = inc
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        try:
            from .feedback import FeedbackStore, feedback_path_for

            for inc_id, rec in FeedbackStore(feedback_path_for(self.path)).load().items():
                if inc_id in latest:
                    latest[inc_id]["disposition"] = rec["verdict"]
        except Exception as exc:
            logger.warning("inflammation: qualifications illisibles (%s)", exc)
        return dict(sorted(latest.items(), key=lambda kv: kv[1].get("opened_at") or 0))
