"""Capteur d'injection mémoire — dernier angle mort (T1055) partiellement comblé.

L'injection de code (shellcode dans un processus légitime, chargement
réflexif, exécution « fileless ») n'écrit rien sur disque : signatures,
watcher et procmon ne la voient pas. Sans pilote noyau, on ne peut pas
intercepter l'acte d'injection — mais on peut voir **ce qu'il laisse en
mémoire** et dans l'état du processus.

Linux (``/proc``, root pour voir les autres processus) :
  - ``anon_exec`` / ``wx_anon`` : région exécutable **non adossée à un
    fichier** (shellcode), pire si aussi inscriptible (RWX). Inclut les
    mappings partagés anonymes, que le noyau affiche ``/dev/zero (deleted)``
    — un détecteur qui ne regarde que les régions sans chemin les rate ;
  - ``memfd_exec`` : code exécuté depuis un ``memfd`` (fileless, T1620) ;
  - ``deleted_exec`` : code exécuté depuis un fichier supprimé après
    lancement (effacement de traces, T1070.004) ;
  - ``ptrace_attached`` : processus tracé par un autre (T1055.008) ;
  - ``ld_preload_writable`` : ``LD_PRELOAD`` pointant vers un dossier
    modifiable (/tmp, /dev/shm, home) (T1574.006).

Windows (Sysmon) :
  - EID 8 ``CreateRemoteThread`` (T1055) ;
  - EID 10 accès à ``lsass.exe`` avec droits de lecture mémoire (T1003.001).

Limites honnêtes : instantané périodique (une injection qui nettoie avant
le passage échappe) ; les runtimes JIT (Java, Node, navigateurs, .NET...)
allouent légitimement de la mémoire exécutable anonyme — allowlistés pour
``anon_exec``/``wx_anon`` uniquement, ce qu'un attaquant injectant dans un
navigateur exploite ; aucune visibilité sur l'injection dans le noyau.
Détection uniquement.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.injmon")

# Runtimes qui génèrent du code à la volée (JIT) : mémoire exécutable anonyme normale.
DEFAULT_JIT_ALLOWLIST = frozenset(
    {
        "java",
        "node",
        "nodejs",
        "chrome",
        "chromium",
        "chromium-browser",
        "firefox",
        "firefox-esr",
        "electron",
        "code",
        "dotnet",
        "mono",
        "pypy",
        "pypy3",
        "luajit",
        "beam.smp",
        "deno",
        "bun",
        "qemu-system-x86_64",
        "wine64-preloader",
        "claude",
    }
)
DEFAULT_DEBUGGERS = frozenset({"gdb", "lldb", "strace", "ltrace", "rr", "valgrind", "perf"})
_PSEUDO_REGIONS = {"[vdso]", "[vsyscall]", "[vvar]", "[uprobes]", "[vvar_vclock]"}
_WRITABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/run/user/")  # noqa: S108
# memfd exécutés légitimement : runc se ré-exécute depuis un memfd (protection
# CVE-2019-5736). Observé aussi en pratique : agents de télémétrie/sandbox.
# Ajouter les siens via config (injmon.memfd_allowlist) — attention, le nom
# d'un memfd est choisi par le processus : allowlister = faire confiance.
DEFAULT_MEMFD_ALLOWLIST = frozenset({"runc_cloned"})

WEIGHTS = {
    "wx_anon": (70.0, ("T1055",)),
    "anon_exec": (55.0, ("T1055",)),
    "memfd_exec": (75.0, ("T1620", "T1055")),
    "deleted_exec": (60.0, ("T1070.004", "T1620")),
    "ptrace_attached": (60.0, ("T1055.008",)),
    "ld_preload_writable": (50.0, ("T1574.006",)),
    "remote_thread": (70.0, ("T1055",)),
    "lsass_access": (85.0, ("T1003.001",)),
}


@dataclass
class InjectionFinding:
    kind: str
    pid: int
    process_name: str
    process_exe: str
    weight: float
    mitre: tuple[str, ...]
    summary: str
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "pid": self.pid,
            "process_name": self.process_name,
            "process_exe": self.process_exe,
            "weight": self.weight,
            "mitre": list(self.mitre),
            "summary": self.summary,
            "timestamp": self.timestamp,
            "details": self.details,
        }


def _finding(kind, pid, name, exe, summary, **details) -> InjectionFinding:
    weight, mitre = WEIGHTS[kind]
    return InjectionFinding(
        kind=kind,
        pid=pid,
        process_name=name,
        process_exe=exe,
        weight=weight,
        mitre=mitre,
        summary=summary,
        details=details,
    )


def parse_maps_line(line: str) -> dict[str, Any] | None:
    parts = line.split(maxsplit=5)
    if len(parts) < 5:
        return None
    addr, perms = parts[0], parts[1]
    path = parts[5].strip() if len(parts) == 6 else ""
    try:
        start_s, end_s = addr.split("-")
        start, end = int(start_s, 16), int(end_s, 16)
    except ValueError:
        return None
    return {"start": start, "end": end, "perms": perms, "path": path}


def classify_region(region: dict[str, Any]) -> str | None:
    """Retourne le type d'anomalie d'une région, ou None si normale."""
    perms, path = region["perms"], region["path"]
    if "x" not in perms or path in _PSEUDO_REGIONS:
        return None
    writable = "w" in perms
    if path.startswith("/memfd:"):
        return "memfd_exec"
    anonymous = (
        path == ""
        or path.startswith("/dev/zero")
        or path.startswith("/SYSV")
        or path in ("[heap]", "[stack]")
        or path.startswith("[anon")
    )
    if anonymous:
        return "wx_anon" if writable else "anon_exec"
    if path.endswith(" (deleted)"):
        return "deleted_exec"
    return None


class InjectionScanner:
    """Analyse /proc (Linux) à la recherche de traces d'injection."""

    def __init__(
        self,
        *,
        proc_root: str | Path = "/proc",
        jit_allowlist: frozenset[str] = DEFAULT_JIT_ALLOWLIST,
        debuggers: frozenset[str] = DEFAULT_DEBUGGERS,
        memfd_allowlist: frozenset[str] = DEFAULT_MEMFD_ALLOWLIST,
    ):
        self.proc_root = Path(proc_root)
        self.jit_allowlist = frozenset(x.lower() for x in jit_allowlist)
        self.debuggers = frozenset(x.lower() for x in debuggers)
        self.memfd_allowlist = tuple(memfd_allowlist)
        self.stats: Counter[str] = Counter()

    def _read(self, pid: int, name: str, mode: str = "r") -> Any:
        p = self.proc_root / str(pid) / name
        return p.read_bytes() if mode == "rb" else p.read_text("utf-8", "replace")

    def _identity(self, pid: int) -> tuple[str, str]:
        try:
            name = self._read(pid, "comm").strip()
        except OSError:
            name = ""
        try:
            exe = os.readlink(self.proc_root / str(pid) / "exe")
        except OSError:
            exe = ""
        return name, exe

    def _is_jit(self, name: str, exe: str) -> bool:
        base = Path(exe.replace(" (deleted)", "")).name.lower() if exe else ""
        return name.lower() in self.jit_allowlist or base in self.jit_allowlist

    def scan_pid(self, pid: int) -> list[InjectionFinding]:
        name, exe = self._identity(pid)
        try:
            maps = self._read(pid, "maps")
        except OSError:
            self.stats["unreadable"] += 1
            return []
        self.stats["processes"] += 1
        out = self.analyze_maps(pid, name, exe, maps)
        out += self._check_tracer(pid, name, exe)
        out += self._check_preload(pid, name, exe)
        return out

    def analyze_maps(self, pid: int, name: str, exe: str, maps: str) -> list[InjectionFinding]:
        """Analyse le contenu d'un ``/proc/<pid>/maps`` (réutilisable : rejeu, tests)."""
        out: list[InjectionFinding] = []
        jit = self._is_jit(name, exe)
        seen_kinds: set[str] = set()
        for line in maps.splitlines():
            region = parse_maps_line(line)
            if region is None:
                continue
            kind = classify_region(region)
            if kind is None or kind in seen_kinds:
                continue
            if jit and kind in ("anon_exec", "wx_anon"):
                self.stats["jit_skipped"] += 1
                continue
            if kind == "memfd_exec" and region["path"][len("/memfd:") :].startswith(
                self.memfd_allowlist
            ):
                self.stats["memfd_allowlisted"] += 1
                continue
            seen_kinds.add(kind)
            size = region["end"] - region["start"]
            out.append(
                _finding(
                    kind,
                    pid,
                    name,
                    exe,
                    f"{name or '?'} (pid {pid}) : région {region['perms']} "
                    f"{region['path'] or '[anonyme]'} de {size} octets à "
                    f"0x{region['start']:x}",
                    perms=region["perms"],
                    path=region["path"],
                    address=hex(region["start"]),
                    size=size,
                )
            )
        return out

    def _check_tracer(self, pid, name, exe) -> list[InjectionFinding]:
        try:
            status = self._read(pid, "status")
        except OSError:
            return []
        tracer = 0
        for line in status.splitlines():
            if line.startswith("TracerPid:"):
                try:
                    tracer = int(line.split()[1])
                except (IndexError, ValueError):
                    tracer = 0
        if not tracer:
            return []
        tname, texe = self._identity(tracer)
        f = _finding(
            "ptrace_attached",
            pid,
            name,
            exe,
            f"{name or '?'} (pid {pid}) est tracé par {tname or '?'} (pid {tracer})",
            tracer_pid=tracer,
            tracer_name=tname,
            tracer_exe=texe,
        )
        if tname.lower() in self.debuggers:
            f.weight = 20.0  # débogueur connu : signal faible (le nom peut mentir)
        return [f]

    def _check_preload(self, pid, name, exe) -> list[InjectionFinding]:
        try:
            env = self._read(pid, "environ", "rb")
        except OSError:
            return []
        for var in env.split(b"\0"):
            if not var.startswith(b"LD_PRELOAD="):
                continue
            value = var.split(b"=", 1)[1].decode("utf-8", "replace")
            libs = [x for x in value.replace(":", " ").split() if x]
            bad = [x for x in libs if x.startswith(_WRITABLE_DIRS)]
            if bad:
                return [
                    _finding(
                        "ld_preload_writable",
                        pid,
                        name,
                        exe,
                        f"{name or '?'} (pid {pid}) précharge {', '.join(bad)} "
                        "depuis un dossier modifiable",
                        libraries=bad,
                    )
                ]
        return []

    def scan_all(self, *, exclude: set[int] | None = None) -> list[InjectionFinding]:
        exclude = exclude or set()
        out = []
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            if pid in exclude:
                continue
            out += self.scan_pid(pid)
        return out


# --------------------------------------------------------------------------- #
# Windows : Sysmon EID 8 / EID 10
# --------------------------------------------------------------------------- #

# Droits d'accès qui permettent de lire la mémoire de lsass (dump d'identifiants)
_LSASS_READ_MASKS = (0x0010, 0x1FFFFF)  # PROCESS_VM_READ, PROCESS_ALL_ACCESS
_SYSMON_NOISY_SOURCES = frozenset(
    {"csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "msmpeng.exe", "lsass.exe"}
)


def parse_sysmon_injection_events(xml_text: str) -> list[tuple[int, InjectionFinding]]:
    import xml.etree.ElementTree as ET

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(f"<Events>{text}</Events>")  # noqa: S314 - journal local
    except ET.ParseError:
        return []
    out = []
    for ev in root.iter(f"{ns}Event"):
        system = ev.find(f"{ns}System")
        if system is None:
            continue
        try:
            eid = int(system.findtext(f"{ns}EventID") or 0)
            rid = int(system.findtext(f"{ns}EventRecordID") or 0)
        except ValueError:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.iter(f"{ns}Data")}
        src_img = data.get("SourceImage", "")
        src_name = Path(src_img.replace("\\", "/")).name
        tgt_img = data.get("TargetImage", "")
        tgt_name = Path(tgt_img.replace("\\", "/")).name
        try:
            src_pid = int(data.get("SourceProcessId") or 0)
        except ValueError:
            continue
        if src_name.lower() in _SYSMON_NOISY_SOURCES:
            continue
        if eid == 8:
            out.append(
                (
                    rid,
                    _finding(
                        "remote_thread",
                        src_pid,
                        src_name,
                        src_img,
                        f"{src_name} crée un thread distant dans {tgt_name} "
                        f"(fonction {data.get('StartFunction') or '?'})",
                        target_image=tgt_img,
                        target_pid=data.get("TargetProcessId"),
                    ),
                )
            )
        elif eid == 10 and tgt_name.lower() == "lsass.exe":
            try:
                access = int(data.get("GrantedAccess", "0"), 16)
            except ValueError:
                continue
            if not any(access & m == m for m in _LSASS_READ_MASKS):
                continue
            out.append(
                (
                    rid,
                    _finding(
                        "lsass_access",
                        src_pid,
                        src_name,
                        src_img,
                        f"{src_name} ouvre lsass.exe avec accès mémoire (0x{access:x})",
                        granted_access=hex(access),
                    ),
                )
            )
    return out


class SysmonInjectionSource:
    """Sysmon EID 8 / 10 via wevtutil (Windows), signet EventRecordID."""

    def __init__(self, on_finding: Callable[[InjectionFinding], None], *, runner=None):
        from .process_sources import SYSMON_CHANNEL, _default_runner

        self.on_finding = on_finding
        self._run = runner or _default_runner
        self._channel = SYSMON_CHANNEL
        self._last = 0

    def _query(self, xpath: str, *, reverse: bool, count: int) -> str:
        return self._run(
            [
                "wevtutil",
                "qe",
                self._channel,
                f"/q:{xpath}",
                "/f:xml",
                f"/rd:{'true' if reverse else 'false'}",
                f"/c:{count}",
            ]
        )

    def prime(self) -> None:
        latest = parse_sysmon_injection_events(
            self._query("*[System[EventID=8 or EventID=10]]", reverse=True, count=1)
        )
        # Pas de finding retenu (bruit filtré) : on part du dernier enregistrement brut.
        raw = self._query("*[System[EventID=8 or EventID=10]]", reverse=True, count=1)
        import re

        m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", raw)
        self._last = int(m.group(1)) if m else (latest[0][0] if latest else 0)

    def poll_once(self) -> list[InjectionFinding]:
        xpath = f"*[System[(EventID=8 or EventID=10) and EventRecordID>{int(self._last)}]]"
        raw = self._query(xpath, reverse=False, count=1000)
        import re

        ids = [int(x) for x in re.findall(r"<EventRecordID>(\d+)</EventRecordID>", raw)]
        out = []
        for _rid, f in sorted(parse_sysmon_injection_events(raw), key=lambda x: x[0]):
            out.append(f)
            self.on_finding(f)
        if ids:
            self._last = max([*ids, self._last])
        return out


# --------------------------------------------------------------------------- #
# Moniteur périodique
# --------------------------------------------------------------------------- #


class InjectionMonitor:
    """Scan périodique ; chaque anomalie n'est signalée qu'une fois par processus."""

    def __init__(
        self,
        scanner: InjectionScanner | None = None,
        *,
        interval: float = 30.0,
        on_finding: Callable[[InjectionFinding], None] | None = None,
        sysmon_runner=None,
    ):
        self.scanner = scanner or InjectionScanner()
        self.interval = max(2.0, float(interval))
        self.on_finding = on_finding
        self._seen: set[tuple] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sysmon: SysmonInjectionSource | None = None
        self._sysmon_runner = sysmon_runner
        self.active_source: str | None = None

    def _key(self, f: InjectionFinding) -> tuple:
        start = ""
        try:
            stat = (self.scanner.proc_root / str(f.pid) / "stat").read_text()
            start = stat.rsplit(")", 1)[1].split()[19]  # starttime : anti-recyclage de PID
        except (OSError, IndexError):
            pass
        return (f.pid, start, f.kind, f.details.get("address"))

    def handle(self, findings: list[InjectionFinding]) -> list[InjectionFinding]:
        new = []
        for f in findings:
            key = self._key(f)
            if key in self._seen:
                continue
            self._seen.add(key)
            new.append(f)
            logger.warning("[INJMON] %s : %s", f.kind, f.summary)
            if self.on_finding is not None:
                try:
                    self.on_finding(f)
                except Exception as exc:
                    logger.error("injmon: on_finding a levé : %s", exc)
        if len(self._seen) > 50_000:
            self._seen.clear()
        return new

    def poll(self) -> list[InjectionFinding]:
        if self._sysmon is not None:
            return self.handle(self._sysmon.poll_once())
        return self.handle(self.scanner.scan_all(exclude={os.getpid()}))

    def start(self) -> bool:
        if sys.platform.startswith("win") or self._sysmon_runner is not None:
            try:
                self._sysmon = SysmonInjectionSource(lambda f: None, runner=self._sysmon_runner)
                self._sysmon.prime()
                self.active_source = "sysmon"
            except Exception as exc:
                logger.warning("injmon : Sysmon EID 8/10 indisponible (%s)", exc)
                return False
        elif self.scanner.proc_root.is_dir():
            self.active_source = "procfs"
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                logger.warning("injmon : sans root, seuls les processus de l'utilisateur sont vus")
        else:
            logger.warning("injmon : ni /proc ni Sysmon — capteur inactif")
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="biocybe-injmon", daemon=True)
        self._thread.start()
        logger.info("Capteur injection actif (%s, %.0fs)", self.active_source, self.interval)
        return True

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception as exc:
                logger.error("injmon : passe en erreur : %s", exc)
            self._stop.wait(self.interval)
