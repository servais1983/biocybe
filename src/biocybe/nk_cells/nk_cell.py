"""Cellule NK (Natural Killer) — réponse active sur processus malveillants.

Dans le système immunitaire, les cellules NK éliminent les cellules
infectées/anormales sans sensibilisation préalable. Dans BioCybe, la
`NKCell` prend une **action de réponse** contre un processus identifié
comme malveillant (par le NetworkMonitor 3.f/3.h, le scanner, ou une
décision manuelle d'analyste).

C'est le SEUL module BioCybe qui pose des actions **destructives**
(tuer un processus). Conséquence : la sécurité passe avant tout.

GARDE-FOUS (défense en profondeur, chacun bloque indépendamment) :
  1. **Désactivé par défaut** (`enabled=False`). Rien ne s'exécute sans
     activation explicite.
  2. **Dry-run par défaut** (`dry_run=True`). Même activée, la NK cell
     décrit ce qu'elle FERAIT sans agir, tant qu'on n'a pas désactivé
     le dry-run.
  3. **Liste de processus protégés** : on ne touche JAMAIS aux process
     critiques (init/systemd, kernel, lsass, svchost, services, …) ni à
     BioCybe lui-même ni à son parent. Cross-platform.
  4. **Seuil de confiance** : on n'agit que sur les détections à haute
     confiance (défaut 90/100).
  5. **`kill` nécessite un opt-in séparé** (`allow_kill=True`).
     L'action par défaut est `SUSPEND` — **réversible** (resume), idéale
     pour figer un process en attendant une décision humaine/forensique.
  6. **Rate-limit** : pas plus de N actions par fenêtre, anti-emballement.
  7. **Audit systématique** : chaque décision ET chaque action (réussie,
     refusée, en échec) est journalisée dans la chaîne immuable.

L'isolation réseau d'un process se fait via sinkhole DNS (`HostsBlocker`
de la Phase 3.f) sur le hostname de l'IOC — pas de manipulation kernel
(iptables/eBPF) hors scope cross-platform.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import psutil

logger = logging.getLogger("biocybe.nk_cell")


class NKAction(str, Enum):
    """Action de réponse possible."""

    NONE = "none"  # ne rien faire (sous seuil, protégé, etc.)
    SUSPEND = "suspend"  # geler le process (réversible via resume)
    TERMINATE = "terminate"  # SIGTERM / arrêt propre demandé
    KILL = "kill"  # SIGKILL / arrêt forcé (nécessite allow_kill)
    ISOLATE_NETWORK = "isolate_network"  # sinkhole DNS du hostname IOC


# Processus à ne JAMAIS toucher — par nom (insensible à la casse).
# Tuer l'un de ceux-ci peut planter la machine ou ouvrir une faille.
_PROTECTED_NAMES = frozenset(
    {
        # Unix
        "init",
        "systemd",
        "systemd-journald",
        "systemd-logind",
        "kthreadd",
        "kworker",
        "ksoftirqd",
        "migration",
        "rcu_sched",
        "watchdog",
        "dbus-daemon",
        "sshd",
        "login",
        "bash",  # ne pas tuer le shell de l'admin
        "sh",
        "zsh",
        # Windows
        "system",
        "system idle process",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "svchost.exe",
        "explorer.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "registry",
        "memory compression",
        # BioCybe lui-même
        "python",
        "python.exe",
        "python3",
        "biocybe",
        "biocybe.exe",
    }
)

# PIDs systèmes intouchables.
_PROTECTED_PIDS = frozenset({0, 1, 4})

DEFAULT_MIN_CONFIDENCE = 90
DEFAULT_MAX_ACTIONS_PER_MINUTE = 10


@dataclass
class NKConfig:
    """Configuration de la cellule NK — conservatrice par défaut."""

    enabled: bool = False
    dry_run: bool = True
    min_confidence: int = DEFAULT_MIN_CONFIDENCE
    default_action: NKAction = NKAction.SUSPEND
    allow_kill: bool = False
    max_actions_per_minute: int = DEFAULT_MAX_ACTIONS_PER_MINUTE
    # Noms supplémentaires à protéger (en plus de la liste intégrée)
    extra_protected_names: frozenset[str] = field(default_factory=frozenset)
    extra_protected_pids: frozenset[int] = field(default_factory=frozenset)


@dataclass
class NKDecision:
    """Décision de réponse pour un processus donné."""

    pid: int | None
    process_name: str
    action: NKAction
    requested_action: NKAction
    reason: str
    confidence: int
    dry_run: bool
    executed: bool = False
    refused_reason: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "action": self.action.value,
            "requested_action": self.requested_action.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "dry_run": self.dry_run,
            "executed": self.executed,
            "refused_reason": self.refused_reason,
            "error": self.error,
        }


class NKCell:
    """Cellule NK : décide et exécute des réponses sur des processus.

    Usage typique (via daemon ou CLI) :
        nk = NKCell(NKConfig(enabled=True, dry_run=False, allow_kill=False))
        decision = nk.evaluate(pid=1234, process_name="malware.exe",
                               confidence=100, reason="C2 ThreatFox")
        nk.respond(decision)   # suspend (réversible) si tout est OK

    `evaluate()` ne touche RIEN — il décide. `respond()` exécute (sauf
    dry-run). Cette séparation permet de logger/valider la décision avant
    l'action, et de tester la logique de décision sans effet de bord.
    """

    def __init__(
        self,
        config: NKConfig | None = None,
        *,
        audit_fn=None,
        hosts_blocker=None,
    ):
        self.config = config or NKConfig()
        # Injection pour testabilité : audit_fn(action, actor, outcome, details)
        self._audit_fn = audit_fn
        self._hosts_blocker = hosts_blocker
        self._action_times: list[float] = []
        # Compteurs cumulés par outcome (observabilité — exposé en métriques)
        self.action_counts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._own_pid = os.getpid()
        try:
            self._own_ppid = os.getppid()
        except (AttributeError, OSError):
            self._own_ppid = -1

    # ------------------------------------------------------------------
    # Sécurité
    # ------------------------------------------------------------------

    def is_protected(self, pid: int | None, process_name: str) -> str | None:
        """Retourne une raison si le process est protégé, sinon None."""
        if pid is None:
            return "pid inconnu"
        if pid in _PROTECTED_PIDS or pid in self.config.extra_protected_pids:
            return f"pid {pid} protégé (système)"
        if pid == self._own_pid:
            return "c'est le process BioCybe lui-même"
        if pid == self._own_ppid:
            return "c'est le process parent de BioCybe"
        name = (process_name or "").strip().lower()
        if name in _PROTECTED_NAMES or name in self.config.extra_protected_names:
            return f"process protégé par nom : {process_name}"
        return None

    def _rate_limited(self) -> bool:
        """True si on a dépassé le quota d'actions sur la dernière minute."""
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            self._action_times[:] = [t for t in self._action_times if t >= cutoff]
            if len(self._action_times) >= self.config.max_actions_per_minute:
                return True
            self._action_times.append(now)
            return False

    # ------------------------------------------------------------------
    # Décision
    # ------------------------------------------------------------------

    def evaluate(
        self,
        *,
        pid: int | None,
        process_name: str,
        confidence: int,
        reason: str,
        requested_action: NKAction | None = None,
    ) -> NKDecision:
        """Décide quelle action prendre. N'exécute rien.

        Applique les garde-fous : enabled, seuil de confiance, protection,
        downgrade kill→default si allow_kill est faux.
        """
        requested = requested_action or self.config.default_action
        decision = NKDecision(
            pid=pid,
            process_name=process_name,
            action=NKAction.NONE,
            requested_action=requested,
            reason=reason,
            confidence=int(confidence),
            dry_run=self.config.dry_run,
        )

        if not self.config.enabled:
            decision.refused_reason = "NK cell désactivée (nk.enabled=false)"
            return decision

        if requested == NKAction.NONE:
            decision.refused_reason = "action demandée = none"
            return decision

        if int(confidence) < self.config.min_confidence:
            decision.refused_reason = (
                f"confidence {confidence} < seuil {self.config.min_confidence}"
            )
            return decision

        protected = self.is_protected(pid, process_name)
        if protected:
            decision.refused_reason = f"protégé : {protected}"
            return decision

        # Downgrade kill → action par défaut si kill non autorisé
        action = requested
        if action == NKAction.KILL and not self.config.allow_kill:
            action = (
                self.config.default_action
                if self.config.default_action != NKAction.KILL
                else NKAction.SUSPEND
            )
            decision.reason += f" [kill refusé (allow_kill=false), downgrade -> {action.value}]"

        decision.action = action
        return decision

    # ------------------------------------------------------------------
    # Exécution
    # ------------------------------------------------------------------

    def respond(self, decision: NKDecision) -> NKDecision:
        """Exécute l'action décidée (sauf dry-run). Audit systématique."""
        if decision.action == NKAction.NONE:
            self._audit(decision, outcome="skipped")
            return decision

        if self.config.dry_run:
            decision.dry_run = True
            self._audit(decision, outcome="dry_run")
            logger.info(
                "[NK DRY-RUN] aurait fait %s sur pid=%s (%s)",
                decision.action.value,
                decision.pid,
                decision.process_name,
            )
            return decision

        if self._rate_limited():
            decision.refused_reason = "rate-limit atteint (anti-emballement)"
            self._audit(decision, outcome="rate_limited")
            logger.warning("[NK] rate-limit atteint, action %s ignorée", decision.action.value)
            return decision

        try:
            if decision.action == NKAction.ISOLATE_NETWORK:
                self._do_isolate(decision)
            else:
                self._do_process_action(decision)
            decision.executed = True
            self._audit(decision, outcome="executed")
            logger.warning(
                "[NK] %s exécuté sur pid=%s (%s) — %s",
                decision.action.value,
                decision.pid,
                decision.process_name,
                decision.reason,
            )
        except psutil.NoSuchProcess:
            decision.error = "process déjà terminé"
            self._audit(decision, outcome="no_such_process")
        except psutil.AccessDenied:
            decision.error = "access denied (privilèges insuffisants)"
            self._audit(decision, outcome="access_denied")
        except Exception as exc:
            decision.error = str(exc)
            self._audit(decision, outcome="error")
            logger.error("[NK] échec %s sur pid=%s : %s", decision.action.value, decision.pid, exc)

        return decision

    def _do_process_action(self, decision: NKDecision) -> None:
        proc = psutil.Process(decision.pid)
        # Re-vérifie le nom au moment d'agir (anti-réutilisation de PID :
        # le PID a pu être recyclé pour un autre process entre evaluate et
        # respond). Si le nom ne correspond plus, on refuse.
        try:
            current_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            raise
        if (
            decision.process_name
            and current_name
            and current_name.lower() != decision.process_name.lower()
        ):
            decision.refused_reason = (
                f"PID recyclé : attendu '{decision.process_name}', "
                f"trouvé '{current_name}' — refus"
            )
            raise RuntimeError(decision.refused_reason)

        if decision.action == NKAction.SUSPEND:
            proc.suspend()
        elif decision.action == NKAction.TERMINATE:
            proc.terminate()
        elif decision.action == NKAction.KILL:
            proc.kill()
        else:
            raise ValueError(f"action process inconnue : {decision.action}")

    def _do_isolate(self, decision: NKDecision) -> None:
        if self._hosts_blocker is None:
            raise RuntimeError("isolation réseau demandée mais HostsBlocker non fourni")
        # Le hostname à sinkholer est passé via reason/metadata côté appelant ;
        # ici on attend qu'il soit fourni dans process_name comme fallback.
        # En pratique l'appelant utilise resume()/isolate_host() directement.
        raise NotImplementedError(
            "isolate_network passe par isolate_host(hostname) — voir CLI/daemon"
        )

    def isolate_host(self, hostname: str) -> bool:
        """Sinkhole un hostname IOC via le HostsBlocker (Phase 3.f)."""
        if self._hosts_blocker is None:
            logger.warning("[NK] isolate_host sans HostsBlocker configuré")
            return False
        existing = self._hosts_blocker.list_blocked()
        if hostname not in existing:
            self._hosts_blocker.apply([*existing, hostname])
        self._audit(
            NKDecision(
                pid=None,
                process_name=hostname,
                action=NKAction.ISOLATE_NETWORK,
                requested_action=NKAction.ISOLATE_NETWORK,
                reason=f"sinkhole {hostname}",
                confidence=100,
                dry_run=self.config.dry_run,
                executed=not self.config.dry_run,
            ),
            outcome="dry_run" if self.config.dry_run else "executed",
        )
        return not self.config.dry_run

    def resume_process(self, pid: int) -> bool:
        """Réveille un process suspendu (annule un SUSPEND)."""
        try:
            psutil.Process(pid).resume()
            logger.info("[NK] pid=%s repris (resume)", pid)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            logger.error("[NK] resume pid=%s échoué : %s", pid, exc)
            return False

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit(self, decision: NKDecision, *, outcome: str) -> None:
        details = decision.to_dict()
        # Compteur cumulé par outcome (observabilité)
        with self._lock:
            self.action_counts[outcome] = self.action_counts.get(outcome, 0) + 1
        if self._audit_fn is not None:
            try:
                self._audit_fn(
                    "nk_response", actor="nk_cell", outcome=outcome, details=details
                )
                return
            except Exception as exc:
                logger.error("[NK] audit_fn a échoué : %s", exc)
        # Fallback : audit log par défaut de BioCybe
        try:
            from ..audit import audit as _audit

            _audit("nk_response", actor="nk_cell", outcome=outcome, details=details)
        except Exception:
            pass


__all__ = [
    "NKAction",
    "NKCell",
    "NKConfig",
    "NKDecision",
]
