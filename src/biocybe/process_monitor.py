"""Télémétrie processus — voir les attaques qui n'écrivent aucun fichier.

Pourquoi
--------
Signatures, IOC et dérive de fichiers ne voient pas une attaque qui
n'utilise que les outils du système (*living-off-the-land* : PowerShell,
certutil, vssadmin, un shell lancé par un serveur web...) ni un agent
(humain ou IA) qui enchaîne des commandes légitimes. Le seul endroit où ça
se voit : **qui lance quoi, avec quelle ligne de commande**.

Ce module :
  - observe les **créations de processus** (polling psutil, cross-OS, sans
    driver) avec le contexte **parent** (nom, exe, ligne de commande) ;
  - évalue des **règles déclaratives** (format Sigma-lite, YAML ou dict) ;
  - émet un `ProcessMatch` par règle déclenchée, consommé par le moteur
    inflammatoire (corrélation avec fichier/C2/ransomware) et l'audit.

Limites honnêtes
----------------
  - Polling (défaut 2 s) : un processus qui naît ET meurt entre deux
    passages n'est pas vu. eBPF (Linux) / ETW (Windows) supprimeraient ce
    trou ; l'architecture (règles + `ProcessEvent`) est prête à les recevoir.
  - Sans root/admin, on ne voit que les processus de l'utilisateur courant.
  - Les règles livrées sont un socle prudent, pas une couverture exhaustive.

Détection uniquement : ce module ne termine ni ne suspend rien (c'est le
rôle de la cellule NK, avec ses garde-fous).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.procmon")

DEFAULT_INTERVAL_S = 2.0
DEFAULT_MAX_ALERTS_PER_KEY_PER_HOUR = 5

# Parents « racines » : les relier comme entité fusionnerait tout l'hôte
# en un seul incident (tout descend de systemd / explorer).
ROOT_PARENT_NAMES = frozenset(
    {
        "systemd",
        "init",
        "launchd",
        "kthreadd",
        "explorer.exe",
        "services.exe",
        "wininit.exe",
        "svchost.exe",
        "smss.exe",
        "csrss.exe",
    }
)

_FIELDS = ("name", "exe", "cmdline", "username", "parent_name", "parent_exe", "parent_cmdline")


# --------------------------------------------------------------------------- #
# Modèle
# --------------------------------------------------------------------------- #


@dataclass
class ProcessEvent:
    """Création de processus observée (avec contexte parent)."""

    pid: int
    ppid: int | None
    name: str
    exe: str
    cmdline: str
    username: str = ""
    create_time: float = 0.0
    parent_name: str = ""
    parent_exe: str = ""
    parent_cmdline: str = ""

    def field_value(self, name: str) -> str:
        return str(getattr(self, name, "") or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline[:2000],
            "username": self.username,
            "create_time": self.create_time,
            "parent_name": self.parent_name,
            "parent_exe": self.parent_exe,
            "parent_cmdline": self.parent_cmdline[:2000],
        }


@dataclass
class _Matcher:
    field: str
    op: str  # equals | contains | startswith | endswith | regex
    values: tuple[str, ...]
    negate: bool = False
    _regexes: tuple[re.Pattern, ...] = ()

    def match(self, event: ProcessEvent) -> bool:
        raw = event.field_value(self.field)
        if self.field in ("name", "parent_name"):
            raw = Path(raw.replace("\\", "/")).name or raw
        val = raw.lower()
        if self.op == "regex":
            hit = any(r.search(raw) for r in self._regexes)
        elif self.op == "equals":
            hit = val in self.values
        elif self.op == "contains":
            hit = any(v in val for v in self.values)
        elif self.op == "startswith":
            hit = any(val.startswith(v) for v in self.values)
        elif self.op == "endswith":
            hit = any(val.endswith(v) for v in self.values)
        else:  # pragma: no cover - validé au chargement
            hit = False
        return hit != self.negate


@dataclass
class ProcessRule:
    """Règle déclarative (Sigma-lite).

    ``match`` : dict ``"<champ>[|<op>][|not]": valeur(s)``. Toutes les
    clés doivent matcher (ET) ; les valeurs d'une clé sont en OU. Champs :
    name, exe, cmdline, username, parent_name, parent_exe, parent_cmdline.
    Opérateurs : equals (défaut), contains, startswith, endswith, regex.
    Comparaison insensible à la casse (sauf regex : utiliser ``(?i)``).
    """

    rule_id: str
    title: str
    weight: float
    match: dict[str, Any]
    mitre: tuple[str, ...] = ()
    description: str = ""
    enabled: bool = True
    _matchers: list[_Matcher] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.rule_id or not re.fullmatch(r"[a-z0-9_.-]+", self.rule_id):
            raise ValueError(f"procmon: rule_id invalide {self.rule_id!r} ([a-z0-9_.-]+)")
        if not self.match:
            raise ValueError(f"procmon: règle {self.rule_id} sans condition")
        self.weight = max(0.0, min(100.0, float(self.weight)))
        self.mitre = tuple(self.mitre or ())
        self._matchers = [self._compile(k, v) for k, v in self.match.items()]

    def _compile(self, key: str, value: Any) -> _Matcher:
        parts = key.split("|")
        fld = parts[0]
        if fld not in _FIELDS:
            raise ValueError(f"procmon: champ inconnu {fld!r} dans {self.rule_id}")
        negate = "not" in parts[1:]
        ops = [p for p in parts[1:] if p != "not"]
        op = ops[0] if ops else "equals"
        if op not in ("equals", "contains", "startswith", "endswith", "regex"):
            raise ValueError(f"procmon: opérateur inconnu {op!r} dans {self.rule_id}")
        values = value if isinstance(value, list | tuple) else [value]
        values = tuple(str(v) for v in values)
        if op == "regex":
            return _Matcher(fld, op, values, negate, tuple(re.compile(v) for v in values))
        return _Matcher(fld, op, tuple(v.lower() for v in values), negate)

    def matches(self, event: ProcessEvent) -> bool:
        return self.enabled and all(m.match(event) for m in self._matchers)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProcessRule:
        return cls(
            rule_id=str(data["id"]),
            title=str(data.get("title", data["id"])),
            weight=float(data.get("weight", 40)),
            match=dict(data["match"]),
            mitre=tuple(data.get("mitre") or ()),
            description=str(data.get("description", "")),
            enabled=bool(data.get("enabled", True)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "weight": self.weight,
            "mitre": list(self.mitre),
            "match": self.match,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class ProcessMatch:
    event: ProcessEvent
    rule: ProcessRule
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "title": self.rule.title,
            "weight": self.rule.weight,
            "mitre": list(self.rule.mitre),
            "timestamp": self.timestamp,
            "process": self.event.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Règles livrées (socle prudent, équivalents de règles Sigma publiques)
# --------------------------------------------------------------------------- #

_SHELLS = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "sh",
    "bash",
    "dash",
    "zsh",
    "pwsh",
]

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "office_spawns_shell",
        "title": "Application bureautique qui lance un shell / script host",
        "weight": 70,
        "mitre": ["T1204.002", "T1059"],
        "description": "Macro ou document piégé : Word/Excel/Outlook n'ont pas à lancer de shell.",
        "match": {
            "parent_name": [
                "winword.exe",
                "excel.exe",
                "powerpnt.exe",
                "outlook.exe",
                "onenote.exe",
                "msaccess.exe",
            ],
            "name": _SHELLS,
        },
    },
    {
        "id": "webserver_spawns_shell",
        "title": "Serveur web qui lance un shell (webshell probable)",
        "weight": 70,
        "mitre": ["T1505.003", "T1059"],
        "match": {
            "parent_name": [
                "nginx",
                "apache2",
                "httpd",
                "php-fpm",
                "php-cgi",
                "w3wp.exe",
                "tomcat",
                "lighttpd",
            ],
            "name": _SHELLS,
        },
    },
    {
        "id": "shadow_copy_deletion",
        "title": "Suppression des copies de sauvegarde (précurseur ransomware)",
        "weight": 90,
        "mitre": ["T1490"],
        "description": "Les ransomwares détruisent les points de restauration avant de chiffrer.",
        "match": {
            "cmdline|regex": [
                r"(?i)vssadmin(\.exe)?\s+.*delete\s+shadows",
                r"(?i)wmic(\.exe)?\s+.*shadowcopy\s+.*delete",
                r"(?i)wbadmin(\.exe)?\s+.*delete\s+(catalog|systemstatebackup)",
                r"(?i)bcdedit(\.exe)?\s+.*recoveryenabled\s+no",
            ]
        },
    },
    {
        "id": "powershell_encoded_command",
        "title": "PowerShell avec commande encodée",
        "weight": 55,
        "mitre": ["T1059.001", "T1027"],
        "match": {
            "name": ["powershell.exe", "pwsh.exe", "pwsh"],
            "cmdline|regex": [r"(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}"],
        },
    },
    {
        "id": "lolbin_download",
        "title": "Binaire système détourné pour télécharger (LOLBin)",
        "weight": 60,
        "mitre": ["T1105", "T1218"],
        "match": {
            "cmdline|regex": [
                r"(?i)certutil(\.exe)?\s+.*-urlcache",
                r"(?i)bitsadmin(\.exe)?\s+.*/transfer",
                r"(?i)mshta(\.exe)?\s+.*https?://",
                r"(?i)regsvr32(\.exe)?\s+.*/i:https?://",
            ]
        },
    },
    {
        "id": "download_piped_to_shell",
        "title": "Téléchargement exécuté directement dans un shell",
        "weight": 50,
        "mitre": ["T1059.004", "T1105"],
        "match": {"cmdline|regex": [r"(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"]},
    },
    {
        "id": "exec_from_temp",
        "title": "Exécutable lancé depuis un dossier temporaire / téléchargements",
        "weight": 25,
        "mitre": ["T1204.002"],
        "description": "Signal faible seul ; pèse lourd corrélé (co-stimulation).",
        "match": {
            "exe|regex": [
                r"(?i)[\\/](tmp|var[\\/]tmp|dev[\\/]shm)[\\/]",
                r"(?i)\\appdata\\local\\temp\\",
                r"(?i)[\\/]downloads[\\/]",
            ]
        },
    },
    {
        "id": "credential_file_access",
        "title": "Ligne de commande qui lit des secrets (clés SSH, cloud, navigateur)",
        "weight": 45,
        "mitre": ["T1552.001", "T1555"],
        "match": {
            "cmdline|regex": [
                r"(?i)[\\/]\.ssh[\\/](id_[a-z0-9]+|authorized_keys)\b",
                r"(?i)[\\/]\.aws[\\/]credentials\b",
                r"(?i)[\\/]\.kube[\\/]config\b",
                r"(?i)[\\/]\.docker[\\/]config\.json\b",
                r"(?i)login data|cookies\.sqlite|key[34]\.db",
            ],
            "name|not": ["ssh", "ssh.exe", "scp", "sftp", "ssh-agent", "ssh-add", "git"],
        },
    },
    {
        "id": "ai_agent_spawns_shell",
        "title": "Agent / runtime IA qui lance un shell",
        "weight": 15,
        "mitre": ["T1059"],
        "description": (
            "Informatif (sous le seuil seul) : un agent IA qui exécute des commandes est "
            "normal ; combiné à un accès secrets ou un C2, la co-stimulation l'escalade."
        ),
        "match": {
            "parent_cmdline|regex": [
                r"(?i)\b(ollama|llama[-_.]?cpp|vllm|lmstudio|open-?interpreter|autogpt|crewai|"
                r"langchain|mcp[-_]?server|claude|codex|aider|gpt-?engineer)\b"
            ],
            "name": _SHELLS,
        },
    },
]


def load_rules(
    paths: Iterable[str | Path] = (), *, include_defaults: bool = True
) -> list[ProcessRule]:
    """Règles livrées + règles YAML additionnelles (fichiers ou dossiers).

    Une règle YAML de même ``id`` qu'une règle livrée la remplace (permet de
    la désactiver avec ``enabled: false`` ou d'en ajuster le poids). Une
    règle invalide est ignorée avec un log d'erreur, sans bloquer les autres.
    """
    by_id: dict[str, ProcessRule] = {}
    if include_defaults:
        for d in DEFAULT_RULES:
            r = ProcessRule.from_dict(d)
            by_id[r.rule_id] = r
    for p in paths:
        p = Path(p)
        files = sorted(p.glob("*.y*ml")) if p.is_dir() else [p]
        for f in files:
            if not f.is_file():
                logger.warning("procmon: fichier de règles introuvable %s", f)
                continue
            try:
                import yaml

                data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
            except Exception as exc:
                logger.error("procmon: %s illisible : %s", f, exc)
                continue
            items = data.get("rules", []) if isinstance(data, dict) else data
            for item in items or []:
                try:
                    r = ProcessRule.from_dict(item)
                    by_id[r.rule_id] = r
                except Exception as exc:
                    logger.error("procmon: règle invalide dans %s : %s", f, exc)
    return list(by_id.values())


# --------------------------------------------------------------------------- #
# Moniteur
# --------------------------------------------------------------------------- #

ProcessProvider = Callable[[], list[dict[str, Any]]]
MatchCallback = Callable[[ProcessMatch], None]


def _join_cmdline(cmd: Any) -> str:
    if isinstance(cmd, list | tuple):
        return " ".join(str(c) for c in cmd)
    return str(cmd or "")


def _psutil_provider() -> list[dict[str, Any]]:
    import psutil

    out = []
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        info = p.info
        if info.get("pid") is None:
            continue
        out.append(info)
    return out


class ProcessMonitor:
    """Observe les créations de processus et évalue les règles.

    Le premier passage établit la baseline (processus déjà présents) sans
    alerter, sauf ``scan_existing=True``. Une création = un couple
    ``(pid, create_time)`` jamais vu (robuste au recyclage de PID).
    """

    def __init__(
        self,
        rules: list[ProcessRule] | None = None,
        *,
        interval: float = DEFAULT_INTERVAL_S,
        on_match: MatchCallback | None = None,
        scan_existing: bool = False,
        provider: ProcessProvider | None = None,
        max_alerts_per_key_per_hour: int = DEFAULT_MAX_ALERTS_PER_KEY_PER_HOUR,
        clock: Callable[[], float] = time.time,
        source: str = "poll",
    ):
        self.rules = rules if rules is not None else load_rules()
        self.interval = max(0.5, float(interval))
        self.on_match = on_match
        self.scan_existing = bool(scan_existing)
        self._provider = provider or _psutil_provider
        self.max_alerts_per_key_per_hour = int(max_alerts_per_key_per_hour)
        self._clock = clock
        self._seen: set[tuple[int, float]] = set()
        self._baselined = False
        self._alert_history: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        # Source d'événements : "poll" (psutil), "netlink" (Linux, noyau),
        # "sysmon" (Windows), "auto" (meilleure dispo, sinon poll).
        self.source_kind = (source or "poll").lower()
        self._source = None
        self.active_source = "poll"
        self.stats = {
            "polls": 0,
            "processes_observed": 0,
            "new_processes": 0,
            "matches": 0,
            "suppressed_rate_limit": 0,
            "errors": 0,
        }

    # ---- une passe ---------------------------------------------------------

    def poll(self) -> list[ProcessMatch]:
        """Une passe : retourne les matches sur les NOUVEAUX processus."""
        raw = self._provider()
        by_pid = {int(p["pid"]): p for p in raw if p.get("pid") is not None}
        current: set[tuple[int, float]] = set()
        new_events: list[ProcessEvent] = []
        for pid, info in by_pid.items():
            key = (pid, float(info.get("create_time") or 0.0))
            current.add(key)
            if key in self._seen:
                continue
            if not self._baselined and not self.scan_existing:
                continue
            new_events.append(self._to_event(info, by_pid))

        with self._lock:
            self._seen = current  # oublie les processus terminés (mémoire bornée)
            self._baselined = True
            self.stats["polls"] += 1
            self.stats["processes_observed"] = len(current)
            self.stats["new_processes"] += len(new_events)

        matches = []
        for ev in new_events:
            matches.extend(self.evaluate(ev))
        return matches

    def evaluate(self, event: ProcessEvent) -> list[ProcessMatch]:
        out = []
        for rule in self.rules:
            try:
                if rule.matches(event):
                    out.append(ProcessMatch(event=event, rule=rule, timestamp=self._clock()))
            except Exception as exc:  # une règle cassée ne doit pas tout bloquer
                self.stats["errors"] += 1
                logger.error("procmon: règle %s a levé : %s", rule.rule_id, exc)
        return out

    def scan_existing_processes(self) -> list[ProcessMatch]:
        """Évalue les règles sur TOUS les processus actuels (one-shot CLI)."""
        raw = self._provider()
        by_pid = {int(p["pid"]): p for p in raw if p.get("pid") is not None}
        matches = []
        for info in by_pid.values():
            matches.extend(self.evaluate(self._to_event(info, by_pid)))
        return matches

    @staticmethod
    def _to_event(info: dict[str, Any], by_pid: dict[int, dict[str, Any]]) -> ProcessEvent:
        ppid = info.get("ppid")
        parent = by_pid.get(int(ppid)) if ppid is not None else None
        if parent is None and ppid:
            parent = _lookup_parent(int(ppid))
        parent = parent or {}
        return ProcessEvent(
            pid=int(info["pid"]),
            ppid=int(ppid) if ppid is not None else None,
            name=str(info.get("name") or ""),
            exe=str(info.get("exe") or ""),
            cmdline=_join_cmdline(info.get("cmdline")),
            username=str(info.get("username") or ""),
            create_time=float(info.get("create_time") or 0.0),
            parent_name=str(parent.get("name") or ""),
            parent_exe=str(parent.get("exe") or ""),
            parent_cmdline=_join_cmdline(parent.get("cmdline")),
        )

    # ---- anti-tempête --------------------------------------------------------

    def _should_alert(self, m: ProcessMatch) -> bool:
        key = (m.rule.rule_id, m.event.exe or m.event.name)
        now = self._clock()
        with self._lock:
            hist = [t for t in self._alert_history.get(key, []) if now - t < 3600]
            if len(hist) >= self.max_alerts_per_key_per_hour:
                self._alert_history[key] = hist
                self.stats["suppressed_rate_limit"] += 1
                return False
            hist.append(now)
            self._alert_history[key] = hist
            if len(self._alert_history) > 10_000:
                self._alert_history.clear()
            return True

    def dispatch(self, matches: list[ProcessMatch]) -> int:
        sent = 0
        for m in matches:
            if not self._should_alert(m):
                continue
            self.stats["matches"] += 1
            sent += 1
            logger.warning(
                "[PROCMON] %s : %s (pid %s) <- %s | %s",
                m.rule.rule_id,
                m.event.name,
                m.event.pid,
                m.event.parent_name or "?",
                m.event.cmdline[:200],
            )
            if self.on_match is not None:
                try:
                    self.on_match(m)
                except Exception as exc:
                    self.stats["errors"] += 1
                    logger.error("procmon: on_match a levé : %s", exc)
        return sent

    # ---- thread --------------------------------------------------------------

    def handle_event(self, event: ProcessEvent) -> int:
        """Point d'entrée des sources temps réel : évalue + dispatch."""
        with self._lock:
            self.stats["new_processes"] += 1
        return self.dispatch(self.evaluate(event))

    def start(self) -> None:
        if self._source is not None or (self._thread is not None and self._thread.is_alive()):
            return
        self._stop_event.clear()
        n_rules = sum(1 for r in self.rules if r.enabled)
        if self.source_kind != "poll":
            from .process_sources import SourceUnavailable, build_source

            try:
                src = build_source(self.source_kind, self.handle_event)
                if src is not None:
                    src.start()
                    self._source = src
                    self.active_source = src.name
                    logger.info(
                        "ProcessMonitor démarré (%d règles, source temps réel %s)",
                        n_rules,
                        src.name,
                    )
                    return
            except SourceUnavailable as exc:
                logger.warning(
                    "procmon : source %s indisponible (%s) — repli sur polling psutil "
                    "(un processus plus court que %.1fs peut échapper)",
                    self.source_kind,
                    exc,
                    self.interval,
                )
        self.active_source = "poll"
        self._thread = threading.Thread(target=self._loop, name="biocybe-procmon", daemon=True)
        self._thread.start()
        logger.info(
            "ProcessMonitor démarré (%d règles actives, polling %.1fs)", n_rules, self.interval
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._source is not None:
            self._source.stop()
            self.stats.update({f"source_{k}": v for k, v in self._source.stats.items()})
            self._source = None
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("ProcessMonitor arrêté (source %s). Stats : %s", self.active_source, self.stats)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.dispatch(self.poll())
            except Exception as exc:
                self.stats["errors"] += 1
                logger.error("procmon: erreur de passe : %s", exc)
            self._stop_event.wait(self.interval)


def _lookup_parent(ppid: int) -> dict[str, Any] | None:
    try:
        import psutil

        p = psutil.Process(ppid)
        with p.oneshot():
            return {"name": p.name(), "exe": p.exe(), "cmdline": p.cmdline()}
    except Exception:
        return None
