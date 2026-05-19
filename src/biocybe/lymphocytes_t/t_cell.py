"""Lymphocyte T — détection comportementale par IsolationForest.

Complète les Lymphocytes B (signatures) avec une détection d'anomalies
sans signature préalable, sur la base des métriques système collectées
par `psutil`. Pensée pour la prod SOC :

  - Cycle de vie clair : `learning` -> `armed`. Tant que la cellule
    n'est pas armée (entraînement insuffisant), elle ne génère pas
    d'alerte (évite le bruit en démarrage).
  - Persistance disque (joblib) : le modèle survit aux redémarrages
    et un nouveau process peut reprendre la détection sans ré-entraîner.
  - Explicabilité : chaque alerte porte la liste des features qui ont
    le plus dévié, en z-scores. Sans explication, un SOC ignorera
    les alertes ML (à juste titre).
  - Cooldown : pas d'alerte plus d'une fois toutes les N secondes
    pour le même type d'anomalie (anti-storm).
  - Intégration au bus : envoie des messages `alert_anomaly` que
    `BCell._handle_anomaly_alert` (déjà implémenté Phase 1) consomme
    pour déclencher des scans signature ciblés.

Les sklearn / numpy / joblib imports sont lazy : un user qui n'a pas
installé `[ml]` peut toujours utiliser le reste de BioCybe ; il aura
juste un `RuntimeError` clair s'il essaye d'instancier une TCell.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from ..biocybe_core import BiologicalCell, CellMessage

logger = logging.getLogger("biocybe.t_cell")

DEFAULT_MODEL_DIR = "models/t_cell"

# Liste ordonnée des features extraites de psutil. L'ordre est
# load-bearing : il définit le shape du vecteur passé à sklearn.
# Toute modification doit invalider les modèles entraînés (versionning).
METRIC_FEATURES: tuple[str, ...] = (
    "cpu_percent",
    "cpu_load_1m",  # 0 si indispo (Windows)
    "memory_percent",
    "swap_percent",
    "disk_io_read_bytes_rate",
    "disk_io_write_bytes_rate",
    "net_bytes_sent_rate",
    "net_bytes_recv_rate",
    "net_connections_count",
    "process_count",
    "process_count_running",
    "process_count_zombie",
    "thread_count_total",
)

MODEL_VERSION = 1  # bump si METRIC_FEATURES change


class MLDepsMissing(RuntimeError):
    """sklearn/numpy/joblib non installés (extra `[ml]`)."""


def _require_ml():
    """Lazy import : sklearn n'est pas une dép core."""
    try:
        import joblib  # noqa: F401
        import numpy as np  # noqa: F401
        from sklearn.ensemble import IsolationForest  # noqa: F401
        from sklearn.preprocessing import StandardScaler  # noqa: F401
    except ImportError as exc:
        raise MLDepsMissing(
            "Le module Lymphocyte T requiert `pip install biocybe[ml]` "
            "(numpy + scikit-learn + joblib). "
            f"Import manquant : {exc.name}"
        ) from exc


# --------------------------------------------------------------------- #
# Collecteur de métriques
# --------------------------------------------------------------------- #


@dataclass
class _IOBaseline:
    """État précédent des compteurs IO pour calculer un débit (bytes/s)."""

    read_bytes: int = 0
    write_bytes: int = 0
    sent_bytes: int = 0
    recv_bytes: int = 0
    timestamp: float = 0.0


# Process_iter (énumère tous les processus avec ACL Windows) coûte
# ~100-200ms sur un Windows typique. À 5s d'intervalle pour 2 TCells,
# on bouffe ~5% CPU constant. On cache donc le résultat et on ne
# rafraîchit qu'à cette périodicité (configurable).
_PROCESS_STATS_REFRESH_S = 30.0


class MetricsCollector:
    """Collecte un vecteur de métriques système courantes.

    Les compteurs cumulés (IO disque, IO réseau) sont convertis en
    débits (bytes/s) en mémorisant la dernière mesure.

    Les stats process (count, running, zombie, threads) sont **cachées
    pendant `_PROCESS_STATS_REFRESH_S` secondes** (défaut 30s) pour
    éviter le coût d'un `psutil.process_iter` à chaque sample —
    énumérer 300+ processus avec ACL Windows prend ~100-200ms.
    Les variations sub-30s sont capturées par les autres features
    rapides (CPU%, mem, IO rates).
    """

    def __init__(self) -> None:
        self._baseline = _IOBaseline(timestamp=time.time())
        # Cache des stats process (refresh tous les 30s)
        self._process_stats_cache: dict[str, float] | None = None
        self._process_stats_ts: float = 0.0
        # Premier appel à cpu_percent renvoie 0 — on l'amorce.
        psutil.cpu_percent(interval=None)

    def _refresh_process_stats(self) -> dict[str, float]:
        """Énumère tous les processus + connexions réseau (coûteux sur
        Windows). À ne pas appeler souvent — d'où le cache à 30s.
        """
        proc_count = proc_running = proc_zombie = thread_total = 0
        try:
            for proc in psutil.process_iter(["status", "num_threads"]):
                proc_count += 1
                info = proc.info
                if info["status"] == psutil.STATUS_RUNNING:
                    proc_running += 1
                elif info["status"] == psutil.STATUS_ZOMBIE:
                    proc_zombie += 1
                if info["num_threads"]:
                    thread_total += info["num_threads"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        try:
            net_conn = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, OSError):
            net_conn = 0

        return {
            "process_count": float(proc_count),
            "process_count_running": float(proc_running),
            "process_count_zombie": float(proc_zombie),
            "thread_count_total": float(thread_total),
            "net_connections_count": float(net_conn),
        }

    def sample(self) -> dict[str, float]:
        """Retourne un dict feature_name -> float pour CE moment."""
        now = time.time()
        dt = max(now - self._baseline.timestamp, 1e-3)

        try:
            disk = psutil.disk_io_counters()
            net = psutil.net_io_counters()
        except (psutil.AccessDenied, RuntimeError):
            disk = net = None

        d_read = (disk.read_bytes - self._baseline.read_bytes) / dt if disk else 0.0
        d_write = (disk.write_bytes - self._baseline.write_bytes) / dt if disk else 0.0
        n_sent = (net.bytes_sent - self._baseline.sent_bytes) / dt if net else 0.0
        n_recv = (net.bytes_recv - self._baseline.recv_bytes) / dt if net else 0.0

        if disk:
            self._baseline.read_bytes = disk.read_bytes
            self._baseline.write_bytes = disk.write_bytes
        if net:
            self._baseline.sent_bytes = net.bytes_sent
            self._baseline.recv_bytes = net.bytes_recv
        self._baseline.timestamp = now

        load_1m = 0.0
        if hasattr(os, "getloadavg"):
            try:
                load_1m = os.getloadavg()[0]
            except OSError:
                load_1m = 0.0

        # Cache des stats process (refresh tous les 30s) — voir docstring
        if (
            self._process_stats_cache is None
            or (now - self._process_stats_ts) > _PROCESS_STATS_REFRESH_S
        ):
            self._process_stats_cache = self._refresh_process_stats()
            self._process_stats_ts = now
        proc_stats = self._process_stats_cache

        return {
            "cpu_percent": float(psutil.cpu_percent(interval=None)),
            "cpu_load_1m": float(load_1m),
            "memory_percent": float(psutil.virtual_memory().percent),
            "swap_percent": float(psutil.swap_memory().percent),
            "disk_io_read_bytes_rate": float(max(d_read, 0.0)),
            "disk_io_write_bytes_rate": float(max(d_write, 0.0)),
            "net_bytes_sent_rate": float(max(n_sent, 0.0)),
            "net_bytes_recv_rate": float(max(n_recv, 0.0)),
            "net_connections_count": proc_stats["net_connections_count"],
            "process_count": proc_stats["process_count"],
            "process_count_running": proc_stats["process_count_running"],
            "process_count_zombie": proc_stats["process_count_zombie"],
            "thread_count_total": proc_stats["thread_count_total"],
        }

    def sample_vector(self) -> list[float]:
        """Sample puis ordonne selon METRIC_FEATURES (shape stable pour sklearn)."""
        s = self.sample()
        return [s[name] for name in METRIC_FEATURES]


# --------------------------------------------------------------------- #
# Modèle persisté
# --------------------------------------------------------------------- #


@dataclass
class TCellModel:
    """Modèle persistable : IsolationForest + StandardScaler + stats baseline."""

    model: Any  # sklearn.ensemble.IsolationForest
    scaler: Any  # sklearn.preprocessing.StandardScaler
    feature_means: list[float]  # moyennes par feature (pour z-scores d'explication)
    feature_stds: list[float]  # écarts-types par feature
    feature_names: list[str] = field(default_factory=lambda: list(METRIC_FEATURES))
    trained_at: str = field(default_factory=lambda: datetime.now().isoformat())
    n_samples: int = 0
    contamination: float = 0.01
    version: int = MODEL_VERSION

    def save(self, model_dir: str | Path) -> Path:
        import joblib

        path = Path(model_dir)
        path.mkdir(parents=True, exist_ok=True)
        # joblib gère mieux les gros modèles sklearn que pickle direct.
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "feature_means": self.feature_means,
                "feature_stds": self.feature_stds,
                "feature_names": self.feature_names,
                "trained_at": self.trained_at,
                "n_samples": self.n_samples,
                "contamination": self.contamination,
                "version": self.version,
            },
            path / "model.joblib",
            compress=3,
        )
        # Manifest texte lisible pour audit (sans le binaire sklearn).
        meta = {
            "trained_at": self.trained_at,
            "n_samples": self.n_samples,
            "contamination": self.contamination,
            "version": self.version,
            "feature_names": self.feature_names,
        }
        (path / "model_meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return path / "model.joblib"

    @classmethod
    def load(cls, model_dir: str | Path) -> TCellModel:
        import joblib

        path = Path(model_dir) / "model.joblib"
        if not path.exists():
            raise FileNotFoundError(f"Modèle TCell absent : {path}")
        blob = joblib.load(path)
        if blob.get("version") != MODEL_VERSION:
            raise ValueError(
                f"Version de modèle incompatible : {blob.get('version')} "
                f"!= {MODEL_VERSION}. Ré-entraîne avec `biocybe tcell train`."
            )
        return cls(**blob)


# --------------------------------------------------------------------- #
# Explication d'anomalie
# --------------------------------------------------------------------- #


@dataclass
class AnomalyExplanation:
    """Pourquoi la TCell a flaggé cet échantillon — lisible humain."""

    timestamp: str
    anomaly_score: float  # IsolationForest decision_function : <0 = anomalie
    score_threshold: float
    is_anomaly: bool
    top_features: list[dict[str, Any]]  # [{name, value, z_score, baseline_mean}]
    raw_sample: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "anomaly_score": self.anomaly_score,
            "score_threshold": self.score_threshold,
            "is_anomaly": self.is_anomaly,
            "top_features": self.top_features,
            "raw_sample": self.raw_sample,
        }

    def human_summary(self) -> str:
        if not self.is_anomaly:
            return f"Comportement normal (score={self.anomaly_score:.3f})"
        parts = [
            f"Anomalie comportementale (score={self.anomaly_score:.3f}<{self.score_threshold:.3f})"
        ]
        for feat in self.top_features[:3]:
            sign = "haute" if feat["z_score"] > 0 else "basse"
            parts.append(
                f"  - {feat['name']} = {feat['value']:.1f} "
                f"(z={feat['z_score']:+.1f}σ vs baseline μ={feat['baseline_mean']:.1f}) — anormalement {sign}"  # noqa: RUF001
            )
        return "\n".join(parts)


# --------------------------------------------------------------------- #
# La TCell elle-même
# --------------------------------------------------------------------- #


class TCell(BiologicalCell):
    """Lymphocyte T — détection comportementale par IsolationForest.

    Cycle de vie :
        learning  : collecte des échantillons, pas encore d'alerte.
        armed     : modèle chargé/entraîné, détecte et alerte.
        disarmed  : entraînement échoué ou modèle invalide.
    """

    def __init__(self, name: str = "t_cell_main", config: dict | None = None):
        _require_ml()
        super().__init__(name, "t_cell", config or {})

        cfg = self.config
        self.model_dir = Path(cfg.get("model_dir", DEFAULT_MODEL_DIR))
        self.scan_interval = float(cfg.get("scan_interval_seconds", 5.0))
        self.training_samples = int(cfg.get("training_samples", 600))
        self.contamination = float(cfg.get("contamination", 0.01))
        self.score_threshold = float(cfg.get("score_threshold", 0.0))
        self.cooldown_seconds = float(cfg.get("cooldown_seconds", 60.0))

        self.collector = MetricsCollector()
        self.tcell_model: TCellModel | None = None
        self.state: str = "learning"  # learning | armed | disarmed
        self._training_buffer: list[list[float]] = []
        self._buffer_lock = threading.Lock()
        self._last_alert_ts = 0.0
        self._stats_extra = {
            "anomalies_detected": 0,
            "samples_collected": 0,
            "samples_trained_on": 0,
            "model_version": MODEL_VERSION,
        }

        # Tente de charger un modèle persistant
        try:
            self.tcell_model = TCellModel.load(self.model_dir)
            self.state = "armed"
            self._stats_extra["samples_trained_on"] = self.tcell_model.n_samples
            self.logger.info(
                "TCell '%s' armée depuis modèle persistant (entraîné le %s sur %d échantillons)",
                self.name,
                self.tcell_model.trained_at,
                self.tcell_model.n_samples,
            )
        except FileNotFoundError:
            self.logger.info(
                "TCell '%s' : pas de modèle persistant. Mode 'learning' jusqu'à "
                "%d échantillons collectés (intervalle %.1fs).",
                self.name,
                self.training_samples,
                self.scan_interval,
            )
        except (ValueError, Exception) as exc:
            self.state = "disarmed"
            self.logger.error("TCell '%s' désarmée : %s", self.name, exc)

        self.register_message_handler("collect_metrics", self._handle_collect_request)

    # ---- API publique ----------------------------------------------------

    def collect_one(self) -> dict[str, float]:
        """Collecte un échantillon et le stocke dans le buffer si en learning."""
        sample = self.collector.sample()
        with self._buffer_lock:
            if self.state == "learning" and len(self._training_buffer) < self.training_samples:
                vec = [sample[name] for name in METRIC_FEATURES]
                self._training_buffer.append(vec)
                self._stats_extra["samples_collected"] = len(self._training_buffer)
        return sample

    def train_from_buffer(self) -> TCellModel:
        """Entraîne IsolationForest sur le buffer courant et persiste."""
        _require_ml()
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        with self._buffer_lock:
            if len(self._training_buffer) < 20:
                raise ValueError(
                    f"Buffer insuffisant : {len(self._training_buffer)} samples "
                    "(20 minimum, 600+ recommandé pour un baseline crédible)."
                )
            data = np.asarray(self._training_buffer, dtype=float)

        scaler = StandardScaler()
        scaled = scaler.fit_transform(data)
        model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(scaled)

        feature_means = data.mean(axis=0).tolist()
        # ddof=0 pour éviter NaN si une feature est constante
        feature_stds = data.std(axis=0, ddof=0).tolist()
        # Évite la division par zéro plus tard
        feature_stds = [s if s > 1e-9 else 1.0 for s in feature_stds]

        self.tcell_model = TCellModel(
            model=model,
            scaler=scaler,
            feature_means=feature_means,
            feature_stds=feature_stds,
            n_samples=len(data),
            contamination=self.contamination,
        )
        self.tcell_model.save(self.model_dir)
        self.state = "armed"
        self._stats_extra["samples_trained_on"] = len(data)
        self.logger.info(
            "TCell '%s' entraînée sur %d échantillons, modèle persisté dans %s",
            self.name,
            len(data),
            self.model_dir,
        )
        return self.tcell_model

    def evaluate(self, sample: dict[str, float] | None = None) -> AnomalyExplanation:
        """Score un échantillon et retourne une explication.

        Utilisable même hors `_process_cycle` (utile pour tests et CLI).
        """
        if self.state != "armed" or self.tcell_model is None:
            raise RuntimeError(
                f"TCell '{self.name}' non armée (état={self.state}). "
                "Entraîne d'abord : `biocybe tcell train`."
            )
        import numpy as np

        if sample is None:
            sample = self.collector.sample()

        vec = np.asarray([[sample[name] for name in METRIC_FEATURES]], dtype=float)
        scaled = self.tcell_model.scaler.transform(vec)
        # decision_function : >0 = normal, <0 = anomalie. Plus c'est négatif, plus c'est anormal.
        score = float(self.tcell_model.model.decision_function(scaled)[0])
        is_anomaly = score < self.score_threshold

        # Explication : top features qui s'écartent le plus de la baseline.
        means = self.tcell_model.feature_means
        stds = self.tcell_model.feature_stds
        z_scores = []
        for i, name in enumerate(METRIC_FEATURES):
            z = (sample[name] - means[i]) / stds[i]
            z_scores.append(
                {
                    "name": name,
                    "value": sample[name],
                    "z_score": z,
                    "baseline_mean": means[i],
                    "abs_z": abs(z),
                }
            )
        z_scores.sort(key=lambda x: x["abs_z"], reverse=True)
        top = [{k: v for k, v in fz.items() if k != "abs_z"} for fz in z_scores[:5]]

        return AnomalyExplanation(
            timestamp=datetime.now().isoformat(),
            anomaly_score=score,
            score_threshold=self.score_threshold,
            is_anomaly=is_anomaly,
            top_features=top,
            raw_sample=sample,
        )

    def get_status(self) -> dict:
        s = super().get_status()
        s["tcell"] = {
            "state": self.state,
            "model_dir": str(self.model_dir),
            **self._stats_extra,
        }
        if self.tcell_model is not None:
            s["tcell"]["trained_at"] = self.tcell_model.trained_at
        return s

    # ---- Cycle de vie cellulaire ----------------------------------------

    def _process_cycle(self) -> None:
        """Appelé en boucle par le worker thread (BiologicalCell._worker).

        Stratégie :
          - state=learning : collecte un échantillon, et si on a atteint
            training_samples, auto-entraîne et passe en armed.
          - state=armed : collecte, évalue, alerte si anomalie + cooldown OK.
          - state=disarmed : ne fait rien (laisse l'opérateur intervenir).

        Le pacing est fait via _stop_event.wait(scan_interval) pour réagir
        immédiatement à un stop.
        """
        try:
            if self.state == "disarmed":
                self._stop_event.wait(self.scan_interval)
                return

            sample = self.collect_one()

            if self.state == "learning":
                # Auto-train quand on a assez d'échantillons
                with self._buffer_lock:
                    have = len(self._training_buffer)
                if have >= self.training_samples:
                    try:
                        self.train_from_buffer()
                    except Exception as exc:
                        self.state = "disarmed"
                        self.logger.error("Auto-train TCell échoué : %s", exc)

            elif self.state == "armed":
                explanation = self.evaluate(sample)
                if explanation.is_anomaly:
                    self._maybe_alert(explanation)

        except Exception as exc:
            self.logger.error("Cycle TCell %s : %s", self.name, exc)
        finally:
            self._stop_event.wait(self.scan_interval)

    def _maybe_alert(self, explanation: AnomalyExplanation) -> None:
        """Envoie une alerte au bus, avec cooldown anti-storm."""
        now = time.time()
        if now - self._last_alert_ts < self.cooldown_seconds:
            return
        self._last_alert_ts = now
        self._stats_extra["anomalies_detected"] += 1

        self.logger.warning(
            "[T-CELL ANOMALY] %s\n%s",
            self.name,
            explanation.human_summary(),
        )

        # Envoyé au bus — les B-cells écoutent déjà `alert_anomaly`
        # (cf. b_cell._handle_anomaly_alert, Phase 1) et déclenchent
        # un scan signature ciblé sur les fichiers suspects récents.
        self.send_message(
            msg_type="alert_anomaly",
            target="broadcast",
            payload={
                "type": "behavioral_outlier",
                "explanation": explanation.to_dict(),
                "detected_by": self.name,
            },
            priority=4,
        )

        # Notification externe via le hook isolation (capté par le
        # NotifierManager si configuré).
        try:
            from ..isolation import _fire_notify

            top = explanation.top_features[0] if explanation.top_features else {}
            _fire_notify(
                kind="behavioral_anomaly",
                severity="warning",
                title=f"Anomalie comportementale ({self.name})",
                message=explanation.human_summary().split("\n")[0],
                payload={
                    "anomaly_score": explanation.anomaly_score,
                    "top_feature": top.get("name"),
                    "top_z_score": top.get("z_score"),
                    "detected_by": self.name,
                    "explanation": explanation.to_dict(),
                },
            )
        except Exception:
            pass  # ne jamais casser la détection sur un échec notif

    def _handle_collect_request(self, message: CellMessage) -> None:
        """Permet à un autre module de forcer une mesure ponctuelle."""
        sample = self.collect_one()
        self.send_message(
            msg_type="metrics_sample",
            target=message.source,
            payload={"sample": sample, "source": self.name},
        )


# --------------------------------------------------------------------- #
# Factory consommée par cli._init_core
# --------------------------------------------------------------------- #


def create_cells(config: dict) -> list[BiologicalCell]:
    """Crée les instances de TCell selon `config['cells']['t_cell']`."""
    cells: list[BiologicalCell] = []
    t_cfg = (config.get("cells") or {}).get("t_cell") or {}
    instances = t_cfg.get("instances") or [{"name": "t_cell_main"}]
    for inst in instances:
        cells.append(TCell(inst.get("name", f"t_cell_{len(cells)}"), inst.get("config", {})))
    return cells
