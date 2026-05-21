"""Surveillance temps réel des connexions réseau sortantes (Phase 3.f).

Complète la `NetworkSentinel` (Phase 3.e, statique sur fichiers) avec
une surveillance **live** des sockets ouverts par les processus locaux.

Approche : polling de `psutil.net_connections('inet')` à intervalle
configurable, croisé avec le moteur `IOCLookup` chargé en mémoire. Pas
de capture pcap (root + libpcap), pas d'eBPF (Linux-only), pas
d'iptables/NFQUEUE. C'est délibéré : cross-platform, pas de dépendance
lourde, fonctionne en non-root pour observer ses propres processus
(root/admin pour voir TOUTES les connexions du système).

Complémentaire :
  - `HostsBlocker` (ce module) — bloque proactivement via sinkhole DNS
    dans le fichier `hosts` (section marquée BioCybe, réversible)
  - `NetworkMonitor` — détecte/alerte (passif)
  - À combiner pour avoir détection + prévention

Limites assumées (documentées vs cachées) :
  - Polling ≠ event-driven. Une connexion très courte peut être
    manquée entre deux ticks. Intervalle 1-5 s recommandé.
  - `net_connections()` requiert root sur Linux/macOS pour voir tous
    les processus ; sans root on ne voit que ses propres processus.
    On le détecte au démarrage et on logge un warning explicite.
  - DNS reverse lookup (IP → hostname) optionnel et timeout-bound.
    Beaucoup d'IPs malveillantes n'ont pas de PTR, donc on ne s'en
    sert que pour enrichir, jamais pour décider.
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from .intel.ioc_lookup import IOCHit, IOCLookup

logger = logging.getLogger("biocybe.network_monitor")


# ----------------------------------------------------------------------
# NetworkMonitor — détection live
# ----------------------------------------------------------------------

DEFAULT_INTERVAL_S = 5.0
DEFAULT_REVERSE_DNS_TIMEOUT_S = 0.3
DEFAULT_MAX_ALERTS_PER_KEY_PER_HOUR = 6  # anti-storm


@dataclass
class ConnectionRecord:
    """Une connexion observée (snapshot ponctuel)."""

    pid: int | None
    process_name: str
    process_exe: str
    laddr: str  # "host:port"
    raddr: str  # "host:port"
    remote_ip: str
    remote_port: int
    status: str  # "ESTABLISHED", "SYN_SENT", ...
    reverse_dns: str = ""  # PTR si résolu, sinon ""
    hit: IOCHit | None = None  # None = bénin, sinon = matched

    @property
    def is_malicious(self) -> bool:
        return self.hit is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "process_exe": self.process_exe,
            "laddr": self.laddr,
            "raddr": self.raddr,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "status": self.status,
            "reverse_dns": self.reverse_dns,
            "hit": self.hit.to_dict() if self.hit else None,
        }


class NetworkMonitor:
    """Surveille les connexions sortantes contre IOCLookup.

    Modes d'usage :
      - **One-shot** : `monitor.snapshot()` → liste de `ConnectionRecord`
        (utile pour `biocybe netmon scan`)
      - **Continu** : `monitor.start()` puis `monitor.stop()`. Le thread
        appelle `on_match(record)` pour chaque IOC détecté, avec
        dédup anti-storm.

    Le dédup est par clé `(pid, remote_ip)` avec un compteur horaire :
    si la même connexion se rouvre 100x/min, on n'envoie pas 100
    notifications.
    """

    def __init__(
        self,
        lookup: IOCLookup,
        *,
        interval: float = DEFAULT_INTERVAL_S,
        reverse_dns: bool = False,
        reverse_dns_timeout: float = DEFAULT_REVERSE_DNS_TIMEOUT_S,
        on_match: Callable[[ConnectionRecord], None] | None = None,
        max_alerts_per_key_per_hour: int = DEFAULT_MAX_ALERTS_PER_KEY_PER_HOUR,
    ):
        self.lookup = lookup
        self.interval = max(0.5, float(interval))
        self.reverse_dns = bool(reverse_dns)
        self.reverse_dns_timeout = float(reverse_dns_timeout)
        self.on_match = on_match
        self.max_alerts_per_key_per_hour = int(max_alerts_per_key_per_hour)

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        # clé (pid, remote_ip) → [timestamps des alertes émises dans l'heure]
        self._alert_history: dict[tuple[int | None, str], list[float]] = {}
        self._history_lock = threading.Lock()

        # Privilege check : sur Linux/macOS, sans root, on ne voit que
        # ses propres processus. Sur Windows, idem sans admin.
        self._privileged = _is_privileged()
        if not self._privileged:
            logger.warning(
                "NetworkMonitor : pas de privileges root/admin — "
                "seulement les connexions des processus appartenant a "
                "l'utilisateur courant seront visibles. Lance en root/admin "
                "pour une couverture complete."
            )

    # ------------------------------------------------------------------
    # Snapshot one-shot
    # ------------------------------------------------------------------

    def snapshot(self) -> list[ConnectionRecord]:
        """Liste l'état courant des connexions inet + matche les IOCs."""
        records: list[ConnectionRecord] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.error("net_connections refuse : %s — relance en root/admin", exc)
            return records

        for c in conns:
            if c.raddr is None or not c.raddr:
                # Pas de remote → écoute (LISTEN). Pas intéressant pour
                # cette surveillance sortante.
                continue
            remote_ip = c.raddr.ip if hasattr(c.raddr, "ip") else ""
            remote_port = c.raddr.port if hasattr(c.raddr, "port") else 0
            if not remote_ip:
                continue
            # Filtre les loopback / link-local : pas d'IOC plausible là.
            if _is_local_ip(remote_ip):
                continue

            pid = c.pid
            pname, pexe = _safe_process_info(pid)

            raddr_str = f"{remote_ip}:{remote_port}"
            laddr_str = ""
            if c.laddr:
                laddr_str = f"{c.laddr.ip}:{c.laddr.port}" if hasattr(c.laddr, "ip") else ""

            # Lookup : d'abord IP exacte (avec/sans port), puis reverse DNS
            # si activé et résolu
            hit = self.lookup.lookup_ip(raddr_str)
            if hit is None:
                hit = self.lookup.lookup_ip(remote_ip)

            reverse = ""
            if hit is None and self.reverse_dns:
                reverse = _try_reverse_dns(remote_ip, self.reverse_dns_timeout)
                if reverse:
                    host_hit = self.lookup.lookup_hostname(reverse)
                    if host_hit:
                        hit = host_hit

            records.append(
                ConnectionRecord(
                    pid=pid,
                    process_name=pname,
                    process_exe=pexe,
                    laddr=laddr_str,
                    raddr=raddr_str,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    status=str(c.status),
                    reverse_dns=reverse,
                    hit=hit,
                )
            )
        return records

    # ------------------------------------------------------------------
    # Surveillance continue (thread)
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            logger.warning("NetworkMonitor.start() : deja en cours")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="biocybe-netmon", daemon=True
        )
        self._thread.start()
        logger.info("NetworkMonitor demarre (intervalle %.1fs)", self.interval)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("NetworkMonitor arrete")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                records = self.snapshot()
            except Exception as exc:
                logger.error("NetworkMonitor : erreur snapshot : %s", exc)
                records = []

            for r in records:
                if not r.is_malicious:
                    continue
                if not self._should_alert(r):
                    continue
                if self.on_match is not None:
                    try:
                        self.on_match(r)
                    except Exception as exc:
                        logger.error("NetworkMonitor : on_match a leve : %s", exc)
                else:
                    logger.warning(
                        "IOC reseau detecte : pid=%s name=%s -> %s (%s, conf=%d)",
                        r.pid,
                        r.process_name,
                        r.raddr,
                        r.hit.source if r.hit else "?",
                        r.hit.confidence if r.hit else 0,
                    )

            # Sleep par petits chunks pour répondre rapidement à stop()
            slept = 0.0
            while slept < self.interval and not self._stop_event.is_set():
                step = min(0.25, self.interval - slept)
                time.sleep(step)
                slept += step

    def _should_alert(self, record: ConnectionRecord) -> bool:
        """Rate-limit : max N alertes par (pid, ip) par heure."""
        key = (record.pid, record.remote_ip)
        now = time.time()
        cutoff = now - 3600.0
        with self._history_lock:
            history = self._alert_history.setdefault(key, [])
            # Purge les vieux events
            history[:] = [t for t in history if t >= cutoff]
            if len(history) >= self.max_alerts_per_key_per_hour:
                return False
            history.append(now)
            return True


# ----------------------------------------------------------------------
# NetworkMonitorService — bundle daemon-friendly (Phase 3.h)
# ----------------------------------------------------------------------


class NetworkMonitorService:
    """Encapsule un `NetworkMonitor` + rechargement auto de l'`IOCLookup`.

    Pensé pour le daemon BioCybe (Phase 3.h) : surveillance live des
    connexions sortantes, avec rechargement transparent des feeds quand
    un `intel update` (cron Phase 3.g) a écrit de nouveaux IOCs — sans
    redémarrer le daemon.

    Le rechargement se base sur un fingerprint des `last_update.txt` de
    chaque feed. `maybe_reload()` est appelé périodiquement par la boucle
    du daemon ; il ne recharge que si le fingerprint a changé (pas de
    relecture disque inutile à chaque tick).

    Comme `IOCLookup.reload()` mute l'instance en place, le `NetworkMonitor`
    qui détient une référence au même objet voit immédiatement les
    nouveaux IOCs — pas besoin de recréer le monitor.
    """

    def __init__(
        self,
        db_path: str | Path = "db/signatures",
        *,
        interval: float = DEFAULT_INTERVAL_S,
        reverse_dns: bool = False,
        on_match: Callable[[ConnectionRecord], None] | None = None,
        lookup: IOCLookup | None = None,
    ):
        self.db_path = Path(db_path)
        self.lookup = lookup or IOCLookup.from_db(db_path)
        self.monitor = NetworkMonitor(
            self.lookup,
            interval=interval,
            reverse_dns=reverse_dns,
            on_match=on_match,
        )
        self._feed_fingerprint = self._compute_feed_fingerprint()

    def _compute_feed_fingerprint(self) -> str:
        """Hash des `last_update.txt` de tous les feeds connus.

        Change dès qu'un feed est rafraîchi → déclenche un reload.
        """
        import hashlib

        parts: list[str] = []
        for subdir in ("hashes", "urlhaus", "threatfox"):
            f = self.db_path / subdir / "last_update.txt"
            try:
                parts.append(f"{subdir}:{f.read_text(encoding='utf-8').strip()}")
            except OSError:
                parts.append(f"{subdir}:absent")
        joined = "|".join(parts)
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def maybe_reload(self) -> bool:
        """Recharge l'IOCLookup si les feeds ont changé. Retourne True si reload."""
        fp = self._compute_feed_fingerprint()
        if fp != self._feed_fingerprint:
            old_total = self.lookup.total
            self.lookup.reload()  # mute en place → le monitor voit les nouveaux IOCs
            self._feed_fingerprint = fp
            logger.info(
                "NetworkMonitorService : IOCs rechargés (%d -> %d)",
                old_total,
                self.lookup.total,
            )
            return True
        return False

    def start(self) -> None:
        self.monitor.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.monitor.stop(timeout=timeout)

    @property
    def ioc_total(self) -> int:
        return self.lookup.total


# ----------------------------------------------------------------------
# HostsBlocker — sinkhole DNS via fichier hosts
# ----------------------------------------------------------------------

BIOCYBE_HOSTS_MARKER_START = "# BIOCYBE-IOC-BLOCK START — ne pas modifier manuellement"
BIOCYBE_HOSTS_MARKER_END = "# BIOCYBE-IOC-BLOCK END"
SINKHOLE_IP = "0.0.0.0"  # noqa: S104 — sinkhole DNS, pas un bind d'interface
MAX_HOSTS_ENTRIES = 50_000  # garde-fou anti-DoS du fichier hosts


def _default_hosts_path() -> Path:
    if platform.system() == "Windows":
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(windir) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


@dataclass
class HostsBlockerStats:
    blocked: list[str] = field(default_factory=list)
    skipped_invalid: list[str] = field(default_factory=list)
    capped: bool = False


class HostsBlocker:
    """Gère une section BioCybe dans le fichier hosts (sinkhole DNS).

    Écrit des entrées `0.0.0.0 <hostname>` dans une section délimitée
    par des marqueurs BioCybe pour pouvoir être retirée proprement.
    Backup automatique avant chaque mutation : `<hosts>.biocybe.bak`.

    Garde-fous :
      - Validation stricte des hostnames (pas de newline injection, pas
        de wildcard, pas de TLD vide)
      - Localhost et nous-mêmes interdits
      - Cap à `MAX_HOSTS_ENTRIES` entrées
      - Écriture atomique (tempfile + os.replace) — pas de hosts cassé
        en cas d'interruption

    Usage CLI : `biocybe netmon block apply --from-feeds --yes`
    """

    def __init__(self, hosts_path: Path | None = None):
        self.hosts_path = hosts_path or _default_hosts_path()
        self.backup_path = self.hosts_path.with_suffix(self.hosts_path.suffix + ".biocybe.bak")

    # ---------------------- API publique ----------------------

    def apply(self, hostnames: list[str]) -> HostsBlockerStats:
        """Écrit (ou remplace) la section BioCybe avec les hostnames donnés."""
        stats = HostsBlockerStats()

        clean: list[str] = []
        seen: set[str] = set()
        for h in hostnames:
            if not isinstance(h, str):
                stats.skipped_invalid.append(str(h))
                continue
            normalized = h.strip().lower().rstrip(".")
            if not _is_safe_hostname(normalized):
                stats.skipped_invalid.append(h)
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            clean.append(normalized)
            if len(clean) >= MAX_HOSTS_ENTRIES:
                stats.capped = True
                break

        stats.blocked = clean

        existing = self._read_existing()
        new_content = self._splice(existing, clean)
        self._backup_if_needed()
        self._atomic_write(new_content)

        logger.info(
            "HostsBlocker : %d hostnames sinkholes (capped=%s, invalides=%d)",
            len(clean),
            stats.capped,
            len(stats.skipped_invalid),
        )
        return stats

    def clear(self) -> int:
        """Retire la section BioCybe. Retourne le nombre d'entrées retirées."""
        existing = self._read_existing()
        before, in_section, after = _split_by_markers(existing)
        removed = sum(
            1 for line in in_section if line.strip() and not line.strip().startswith("#")
        )
        new_content = "".join(before) + "".join(after)
        if removed:
            self._backup_if_needed()
        self._atomic_write(new_content)
        logger.info("HostsBlocker : section BioCybe retiree (%d entrees)", removed)
        return removed

    def list_blocked(self) -> list[str]:
        """Liste les hostnames actuellement sinkholes par BioCybe."""
        existing = self._read_existing()
        _, in_section, _ = _split_by_markers(existing)
        out: list[str] = []
        for line in in_section:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == SINKHOLE_IP:
                out.append(parts[1])
        return out

    def status(self) -> dict[str, Any]:
        """État courant : nombre d'entrées, taille fichier, backup existe ?"""
        blocked = self.list_blocked()
        return {
            "hosts_path": str(self.hosts_path),
            "exists": self.hosts_path.exists(),
            "writable": _is_writable(self.hosts_path),
            "blocked_count": len(blocked),
            "blocked_sample": blocked[:5],
            "backup_exists": self.backup_path.exists(),
        }

    # ---------------------- helpers internes ----------------------

    def _read_existing(self) -> list[str]:
        if not self.hosts_path.exists():
            return []
        try:
            return self.hosts_path.read_text(encoding="utf-8", errors="replace").splitlines(
                keepends=True
            )
        except OSError as exc:
            logger.error("HostsBlocker : impossible de lire %s : %s", self.hosts_path, exc)
            return []

    def _splice(self, existing: list[str], hostnames: list[str]) -> str:
        before, _in_section, after = _split_by_markers(existing)
        # Si pas de hostnames à écrire, on supprime simplement la section
        if not hostnames:
            return "".join(before) + "".join(after)
        block: list[str] = []
        block.append(BIOCYBE_HOSTS_MARKER_START + "\n")
        block.append(
            f"# Genere par BioCybe le {datetime.now().isoformat(timespec='seconds')}\n"
        )
        block.append(f"# {len(hostnames)} hostnames sinkholes vers {SINKHOLE_IP}\n")
        for h in hostnames:
            block.append(f"{SINKHOLE_IP}\t{h}\n")
        block.append(BIOCYBE_HOSTS_MARKER_END + "\n")
        # Assure une newline entre `before` et le marker si nécessaire
        if before and not before[-1].endswith("\n"):
            before[-1] = before[-1] + "\n"
        return "".join(before) + "".join(block) + "".join(after)

    def _backup_if_needed(self) -> None:
        """Backup une seule fois — préserve l'état pré-BioCybe."""
        if not self.hosts_path.exists():
            return
        if self.backup_path.exists():
            return
        try:
            self.backup_path.write_bytes(self.hosts_path.read_bytes())
            logger.info("HostsBlocker : backup cree %s", self.backup_path)
        except OSError as exc:
            logger.warning("HostsBlocker : backup impossible : %s", exc)

    def _atomic_write(self, content: str) -> None:
        """Écrit le fichier hosts de façon atomique (tempfile + replace)."""
        dst = self.hosts_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".biocybe-hosts-", dir=str(dst.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            os.replace(tmp_path, dst)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _split_by_markers(
    lines: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Sépare un fichier hosts en (avant, section_biocybe, après).

    Si pas de section : (lignes, [], [])
    """
    start_idx: int | None = None
    end_idx: int | None = None
    for i, line in enumerate(lines):
        s = line.strip()
        if start_idx is None and s.startswith("# BIOCYBE-IOC-BLOCK START"):
            start_idx = i
        elif start_idx is not None and s.startswith("# BIOCYBE-IOC-BLOCK END"):
            end_idx = i
            break
    if start_idx is None or end_idx is None:
        return lines, [], []
    return lines[:start_idx], lines[start_idx : end_idx + 1], lines[end_idx + 1 :]


def _is_safe_hostname(host: str) -> bool:
    """Refuse tout ce qui pourrait casser /etc/hosts ou créer un blocage stupide."""
    if not host or len(host) > 253:
        return False
    if any(c.isspace() or c in "#\n\r\t<>\"'`" for c in host):
        return False
    if "*" in host:
        return False  # pas de wildcards
    if host in ("localhost", "localhost.localdomain", "broadcasthost"):
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    if "." not in host:
        # Hosts mono-label refusés — risque de bloquer "router" ou "printer"
        return False
    # Format général : labels alphanum-hyphen
    for label in host.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    return True


def _is_local_ip(ip: str) -> bool:
    """True si IP loopback, link-local, multicast — pas pertinent pour IOC."""
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # invalide → on l'ignore
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _safe_process_info(pid: int | None) -> tuple[str, str]:
    """Renvoie (name, exe) avec gestion des PIDs disparus/inaccessibles."""
    if pid is None or pid <= 0:
        return "<unknown>", ""
    try:
        p = psutil.Process(pid)
        name = p.name() or "<unnamed>"
        try:
            exe = p.exe() or ""
        except (psutil.AccessDenied, OSError):
            exe = ""
        return name, exe
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "<unknown>", ""


def _try_reverse_dns(ip: str, timeout: float) -> str:
    """Reverse DNS avec timeout strict. Renvoie "" en cas d'échec."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _aliases, _ip_list = socket.gethostbyaddr(ip)
        return host
    except (OSError, socket.herror, socket.gaierror):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def _is_privileged() -> bool:
    """True si root (Unix) ou admin (Windows)."""
    if platform.system() == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def _is_writable(path: Path) -> bool:
    """True si on peut écrire le fichier (existe + écrivable, ou dir parent écrivable)."""
    if path.exists():
        return os.access(path, os.W_OK)
    parent = path.parent
    return parent.exists() and os.access(parent, os.W_OK)


__all__ = [
    "BIOCYBE_HOSTS_MARKER_END",
    "BIOCYBE_HOSTS_MARKER_START",
    "MAX_HOSTS_ENTRIES",
    "SINKHOLE_IP",
    "ConnectionRecord",
    "HostsBlocker",
    "HostsBlockerStats",
    "NetworkMonitor",
    "NetworkMonitorService",
]
