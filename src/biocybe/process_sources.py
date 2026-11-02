"""Sources d'événements processus temps réel (sans trou de polling).

Le polling psutil (``ProcessMonitor`` par défaut) rate tout processus qui
naît et meurt entre deux passages — exactement le profil d'un one-liner
offensif. Ces sources reçoivent les créations au fil de l'eau :

``NetlinkProcSource`` (Linux)
    *Proc connector* du noyau (netlink ``NETLINK_CONNECTOR`` /
    ``CN_IDX_PROC``) : le noyau pousse chaque ``fork``/``exec``. Aucune
    dépendance, aucun module eBPF à compiler ; requiert root
    (``CAP_NET_ADMIN``). Le noyau ne transmet que les PID : nom, exe et
    ligne de commande sont lus dans ``/proc`` à la réception. Si le
    processus est déjà mort, l'événement est émis **partiel** (PID, parent
    connu) et compté — jamais silencieusement perdu.

``SysmonSource`` (Windows)
    Ingestion de **Sysmon Event ID 1** (ProcessCreate) depuis
    ``Microsoft-Windows-Sysmon/Operational`` via ``wevtutil``. Journal
    durable : image, ligne de commande, parent et sa ligne de commande sont
    fournis par Sysmon, même pour un processus de 1 ms. Requiert Sysmon
    installé (standard SOC).

Les deux produisent des ``ProcessEvent`` : les règles ne changent pas.
"""

from __future__ import annotations

import logging
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .process_monitor import ProcessEvent

logger = logging.getLogger("biocybe.procmon.source")

EventCallback = Callable[[ProcessEvent], None]


class SourceUnavailable(RuntimeError):
    """La source ne peut pas fonctionner sur cet hôte (OS, droits, Sysmon absent)."""


class _LRU(OrderedDict):
    def __init__(self, maxsize: int):
        super().__init__()
        self.maxsize = maxsize

    def put(self, key, value) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.maxsize:
            self.popitem(last=False)


# --------------------------------------------------------------------------- #
# Linux : proc connector netlink
# --------------------------------------------------------------------------- #

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
NLMSG_DONE = 3
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002

_NLMSGHDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid (16 o)
_CN_MSG = struct.Struct("=IIIIHH")  # idx, val, seq, ack, len, flags (20 o)
_PROC_EVENT_HDR = struct.Struct("=IIQ")  # what, cpu, timestamp_ns (16 o)
_PAIR = struct.Struct("=II")
_QUAD = struct.Struct("=IIII")


def parse_proc_connector(data: bytes) -> list[tuple[int, tuple[int, ...]]]:
    """Décode un datagramme netlink -> [(what, champs)] (fork: 4 champs, exec: 2)."""
    out: list[tuple[int, tuple[int, ...]]] = []
    offset = 0
    while offset + _NLMSGHDR.size <= len(data):
        nl_len = _NLMSGHDR.unpack_from(data, offset)[0]
        if nl_len < _NLMSGHDR.size or offset + nl_len > len(data):
            break
        ev = offset + _NLMSGHDR.size + _CN_MSG.size
        if ev + _PROC_EVENT_HDR.size <= offset + nl_len:
            what = _PROC_EVENT_HDR.unpack_from(data, ev)[0]
            body = ev + _PROC_EVENT_HDR.size
            if what == PROC_EVENT_FORK and body + _QUAD.size <= offset + nl_len:
                out.append((what, _QUAD.unpack_from(data, body)))
            elif what == PROC_EVENT_EXEC and body + _PAIR.size <= offset + nl_len:
                out.append((what, _PAIR.unpack_from(data, body)))
        offset += (nl_len + 3) & ~3  # NLMSG_ALIGN
    return out


def _read_proc(pid: int, root: Path = Path("/proc")) -> dict[str, Any] | None:
    base = root / str(pid)
    try:
        raw = (base / "cmdline").read_bytes()
        cmdline = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
        name = (base / "comm").read_text("utf-8", "replace").strip()
        ppid = None
        uid = None
        for line in (base / "status").read_text("utf-8", "replace").splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
            elif line.startswith("Uid:"):
                uid = line.split()[1]
        try:
            exe = os.readlink(base / "exe")
        except OSError:
            exe = cmdline[0] if cmdline else ""
        return {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": cmdline, "uid": uid}
    except (OSError, ValueError):
        return None


def _username(uid: str | None) -> str:
    if uid is None:
        return ""
    try:
        import pwd

        return pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return str(uid)


class NetlinkProcSource:
    """Flux temps réel fork/exec du noyau Linux."""

    name = "netlink"

    def __init__(self, on_event: EventCallback, *, proc_root: str | Path = "/proc"):
        self.on_event = on_event
        self.proc_root = Path(proc_root)
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._fork_parent = _LRU(65_536)  # child_tgid -> parent_tgid
        self._info = _LRU(8_192)  # tgid -> infos /proc (parents morts compris)
        self.stats = {"exec_events": 0, "fork_events": 0, "partial_events": 0, "overruns": 0}

    @staticmethod
    def check_available() -> None:
        if not sys.platform.startswith("linux"):
            raise SourceUnavailable("proc connector : Linux uniquement")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise SourceUnavailable("proc connector : requiert root (CAP_NET_ADMIN)")

    def _open(self) -> socket.socket:
        self.check_available()
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.bind((0, CN_IDX_PROC))
            self._send_op(sock, PROC_CN_MCAST_LISTEN)
        except OSError as exc:
            raise SourceUnavailable(f"proc connector indisponible : {exc}") from exc
        return sock

    @staticmethod
    def _send_op(sock: socket.socket, op: int) -> None:
        payload = struct.pack("=I", op)
        cn = _CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0) + payload
        sock.send(_NLMSGHDR.pack(_NLMSGHDR.size + len(cn), NLMSG_DONE, 0, 0, 0) + cn)

    def start(self) -> None:
        self._sock = self._open()  # lève SourceUnavailable AVANT de lancer le thread
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="biocybe-netlink", daemon=True)
        self._thread.start()
        logger.info("Source processus temps réel : proc connector netlink (noyau)")

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._sock is not None:
            try:
                self._send_op(self._sock, PROC_CN_MCAST_IGNORE)
            except OSError:
                pass
            self._sock.close()
            self._sock = None

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._sock], [], [], 0.5)
                if not ready:
                    continue
                data = self._sock.recv(65536)
            except OSError as exc:
                # ENOBUFS : le noyau a jeté des événements (rafale) -> compté
                self.stats["overruns"] += 1
                logger.warning("proc connector : débordement / erreur (%s)", exc)
                continue
            for what, fields in parse_proc_connector(data):
                try:
                    self.handle(what, fields)
                except Exception as exc:
                    logger.error("proc connector : traitement événement : %s", exc)

    def handle(self, what: int, fields: tuple[int, ...]) -> ProcessEvent | None:
        """Traite un événement décodé (public pour les tests)."""
        if what == PROC_EVENT_FORK:
            _, parent_tgid, child_pid, child_tgid = fields
            if child_pid == child_tgid:  # nouveau processus (pas un thread)
                self.stats["fork_events"] += 1
                self._fork_parent.put(child_tgid, parent_tgid)
                if parent_tgid not in self._info:
                    info = _read_proc(parent_tgid, self.proc_root)
                    if info:
                        self._info.put(parent_tgid, info)
            return None
        if what != PROC_EVENT_EXEC:
            return None
        pid, tgid = fields
        if pid != tgid:
            return None
        self.stats["exec_events"] += 1
        info = _read_proc(tgid, self.proc_root)
        ppid = info.get("ppid") if info else self._fork_parent.get(tgid)
        if info:
            self._info.put(tgid, info)
        parent = self._info.get(ppid) if ppid else None
        if parent is None and ppid:
            parent = _read_proc(ppid, self.proc_root)
            if parent:
                self._info.put(ppid, parent)
        parent = parent or {}
        if info is None:
            self.stats["partial_events"] += 1
        ev = ProcessEvent(
            pid=tgid,
            ppid=ppid,
            name=(info or {}).get("name", ""),
            exe=(info or {}).get("exe", ""),
            cmdline=" ".join((info or {}).get("cmdline", [])),
            username=_username((info or {}).get("uid")),
            parent_name=parent.get("name", ""),
            parent_exe=parent.get("exe", ""),
            parent_cmdline=" ".join(parent.get("cmdline", [])),
        )
        self.on_event(ev)
        return ev


# --------------------------------------------------------------------------- #
# Windows : Sysmon Event ID 1
# --------------------------------------------------------------------------- #

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

Runner = Callable[[list[str]], str]


def _default_runner(cmd: list[str]) -> str:
    return subprocess.run(  # noqa: S603 - binaire système, arguments fixes
        cmd, capture_output=True, text=True, timeout=30, check=True
    ).stdout


def parse_sysmon_events(xml_text: str) -> list[tuple[int, ProcessEvent]]:
    """Parse la sortie ``wevtutil qe ... /f:xml`` -> [(EventRecordID, event)].

    Ne garde que les Event ID 1 (ProcessCreate). Tolérant aux événements
    malformés (ignorés).
    """
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(f"<Events>{text}</Events>")  # noqa: S314 - journal local
    except ET.ParseError as exc:
        logger.error("Sysmon : XML illisible (%s)", exc)
        return []
    out = []
    for event in root.iter(f"{_EVT_NS}Event"):
        system = event.find(f"{_EVT_NS}System")
        if system is None:
            continue
        try:
            event_id = int(system.findtext(f"{_EVT_NS}EventID") or 0)
            record_id = int(system.findtext(f"{_EVT_NS}EventRecordID") or 0)
        except ValueError:
            continue
        if event_id != 1:
            continue
        data = {
            d.get("Name"): (d.text or "")
            for d in event.iter(f"{_EVT_NS}Data")
            if d.get("Name") is not None
        }
        try:
            image = data.get("Image", "")
            parent_image = data.get("ParentImage", "")
            ev = ProcessEvent(
                pid=int(data.get("ProcessId") or 0),
                ppid=int(data["ParentProcessId"]) if data.get("ParentProcessId") else None,
                name=Path(image.replace("\\", "/")).name,
                exe=image,
                cmdline=data.get("CommandLine", ""),
                username=data.get("User", ""),
                parent_name=Path(parent_image.replace("\\", "/")).name,
                parent_exe=parent_image,
                parent_cmdline=data.get("ParentCommandLine", ""),
            )
        except ValueError:
            continue
        out.append((record_id, ev))
    return out


class SysmonSource:
    """Lit les ProcessCreate Sysmon au fil de l'eau (signet EventRecordID)."""

    name = "sysmon"

    def __init__(
        self,
        on_event: EventCallback,
        *,
        interval: float = 1.0,
        runner: Runner | None = None,
        batch: int = 500,
    ):
        self.on_event = on_event
        self.interval = max(0.2, float(interval))
        self._run = runner or _default_runner
        self.batch = int(batch)
        self._last_record = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = {"events": 0, "polls": 0, "errors": 0}

    def check_available(self) -> None:
        if self._run is _default_runner and not sys.platform.startswith("win"):
            raise SourceUnavailable("Sysmon : Windows uniquement")
        try:
            self._run(["wevtutil", "gl", SYSMON_CHANNEL])
        except Exception as exc:
            raise SourceUnavailable(f"Sysmon non installé / canal inaccessible : {exc}") from exc

    def _query(self, xpath: str, *, reverse: bool, count: int) -> str:
        return self._run(
            [
                "wevtutil",
                "qe",
                SYSMON_CHANNEL,
                f"/q:{xpath}",
                "/f:xml",
                f"/rd:{'true' if reverse else 'false'}",
                f"/c:{count}",
            ]
        )

    def start(self) -> None:
        self.check_available()
        # Signet : on part du dernier événement existant (pas de rejeu de
        # l'historique au démarrage — même logique que la baseline du polling).
        latest = parse_sysmon_events(self._query("*[System[EventID=1]]", reverse=True, count=1))
        self._last_record = latest[0][0] if latest else 0
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="biocybe-sysmon", daemon=True)
        self._thread.start()
        logger.info(
            "Source processus temps réel : Sysmon Event ID 1 (signet %d)", self._last_record
        )

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def poll_once(self) -> list[ProcessEvent]:
        xpath = f"*[System[EventID=1 and EventRecordID>{int(self._last_record)}]]"
        events = parse_sysmon_events(self._query(xpath, reverse=False, count=self.batch))
        self.stats["polls"] += 1
        out = []
        for record_id, ev in sorted(events, key=lambda x: x[0]):
            if record_id <= self._last_record:
                continue
            self._last_record = record_id
            self.stats["events"] += 1
            out.append(ev)
            self.on_event(ev)
        return out

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self.stats["errors"] += 1
                logger.error("Sysmon : lecture du journal a échoué : %s", exc)
            self._stop.wait(self.interval)


# --------------------------------------------------------------------------- #
# Sélection
# --------------------------------------------------------------------------- #


def build_source(kind: str, on_event: EventCallback, **kw):
    """Construit la source demandée ; ``auto`` choisit la meilleure dispo.

    Retourne ``None`` pour ``poll`` (ou ``auto`` sans source temps réel
    disponible) : l'appelant reste alors en polling psutil.
    Lève ``SourceUnavailable`` si une source EXPLICITE n'est pas utilisable.
    """
    kind = (kind or "auto").lower()
    if kind == "poll":
        return None
    if kind == "netlink":
        NetlinkProcSource.check_available()
        return NetlinkProcSource(on_event)
    if kind == "sysmon":
        src = SysmonSource(on_event, **kw)
        src.check_available()
        return src
    if kind != "auto":
        raise SourceUnavailable(f"source procmon inconnue : {kind!r}")
    for candidate in ("netlink", "sysmon"):
        try:
            return build_source(candidate, on_event, **kw)
        except SourceUnavailable as exc:
            logger.debug("procmon auto : %s", exc)
    return None
