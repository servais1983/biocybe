"""Capteur DNS — tunneling, DGA, beaconing, IOC (angle mort T1071.004).

Le DNS traverse presque tous les pare-feux : c'est un canal C2 et
d'exfiltration classique (tunneling : données encodées dans les
sous-domaines), et le domaine de rendez-vous des malwares à DGA. BioCybe
ne le voyait pas (``biocybe coverage`` : T1071.004 « non observable »).

Architecture : **analyse séparée des sources**.

``DnsAnalyzer`` (pur, déterministe, testable) consomme des ``DnsQuery`` :
  - **tunneling** : beaucoup de sous-domaines *uniques*, longs et à forte
    entropie sous un même domaine enregistré (ou rafale TXT/NULL) ;
  - **DGA / NXDOMAIN** : rafale de domaines distincts inexistants ;
  - **beaconing** : requêtes au même nom à intervalle quasi constant ;
  - **IOC** : nom présent dans les feeds threat intel (IOCLookup).

Sources :
  - ``PacketDnsSource`` (Linux, root) : capture brute ``AF_PACKET`` des
    requêtes/réponses UDP/53, sans dépendance (pas de scapy/libpcap) ;
  - ``SysmonDnsSource`` (Windows) : Sysmon Event ID 22 — rattache chaque
    requête au **processus** émetteur (Image, PID) ;
  - ``read_zeek_dns_log`` : logs Zeek ``dns.log`` (TSV ou JSON) pour
    l'analyse rétrospective (retro-hunt) d'un SOC.

Limites honnêtes : DNS chiffré (DoH/DoT) invisible à la capture réseau —
seul Sysmon 22 (côté client Windows) le voit ; la capture ne connaît pas le
processus émetteur ; les seuils sont des heuristiques (allowlist de CDN
fournie, ajustable). Détection uniquement.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import logging
import math
import socket
import struct
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("biocybe.dnsmon")

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
RCODE_NXDOMAIN = 3

# Domaines légitimes à sous-domaines aléatoires (CDN, cloud) : exclus des
# heuristiques tunneling/DGA (pas du matching IOC). Ajustable en config.
DEFAULT_ALLOWLIST = (
    "in-addr.arpa",
    "ip6.arpa",
    "local",
    "localhost",
    "amazonaws.com",
    "cloudfront.net",
    "akamaiedge.net",
    "akamai.net",
    "akadns.net",
    "googleusercontent.com",
    "googleapis.com",
    "gvt1.com",
    "1e100.net",
    "windows.net",
    "azureedge.net",
    "trafficmanager.net",
    "cloudflare.net",
    "fastly.net",
    "msedge.net",
    "spotify.com",
)

_TWO_LEVEL_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "gouv", "ne", "or"}


# --------------------------------------------------------------------------- #
# Modèle
# --------------------------------------------------------------------------- #


@dataclass
class DnsQuery:
    qname: str
    qtype: str = "A"
    rcode: int | None = None  # None = inconnu (requête sans réponse vue)
    timestamp: float = field(default_factory=time.time)
    client: str = ""  # IP source / hôte
    pid: int | None = None  # connu via Sysmon 22
    process_exe: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        self.qname = (self.qname or "").strip().rstrip(".").lower()


@dataclass
class DnsFinding:
    kind: str  # dns_tunneling | dns_nxdomain_burst | dns_beaconing | dns_ioc
    domain: str
    weight: float
    mitre: tuple[str, ...]
    summary: str
    timestamp: float
    pid: int | None = None
    process_exe: str = ""
    client: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "domain": self.domain,
            "weight": self.weight,
            "mitre": list(self.mitre),
            "summary": self.summary,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_exe": self.process_exe,
            "client": self.client,
            "details": self.details,
        }


def registered_domain(name: str) -> str:
    """Approximation du domaine enregistré (eTLD+1) sans liste PSL."""
    labels = [x for x in name.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _TWO_LEVEL_SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #


@dataclass
class DnsAnalyzerConfig:
    window_seconds: float = 300.0
    cooldown_seconds: float = 600.0  # une alerte par (type, domaine) par période
    # Tunneling
    tunnel_min_unique: int = 20
    tunnel_min_mean_len: float = 24.0
    tunnel_min_entropy: float = 3.5
    tunnel_txt_min: int = 20  # rafale TXT/NULL vers un même domaine
    # DGA / NXDOMAIN
    nx_window_seconds: float = 60.0
    nx_min_count: int = 25
    nx_min_distinct: int = 20
    # Beaconing
    beacon_min_queries: int = 8
    beacon_min_interval: float = 5.0
    beacon_max_cv: float = 0.15
    allowlist: tuple[str, ...] = DEFAULT_ALLOWLIST
    max_tracked: int = 20_000

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> DnsAnalyzerConfig:
        cfg = cls()
        for k, v in (data or {}).items():
            if k == "allowlist" and v is not None:
                cfg.allowlist = tuple(DEFAULT_ALLOWLIST) + tuple(str(x).lower() for x in v)
            elif hasattr(cfg, k) and v is not None:
                setattr(cfg, k, type(getattr(cfg, k))(v))
        return cfg


class DnsAnalyzer:
    """Heuristiques DNS à fenêtre glissante. Thread-safe."""

    def __init__(
        self,
        config: DnsAnalyzerConfig | None = None,
        *,
        ioc_lookup: Any = None,
    ):
        self.config = config or DnsAnalyzerConfig()
        self.ioc_lookup = ioc_lookup
        self._lock = threading.Lock()
        self._subs: dict[str, deque] = defaultdict(deque)  # domaine -> (ts, sous-domaine, qtype)
        self._nx: dict[str, deque] = defaultdict(deque)  # émetteur -> (ts, qname)
        self._beacon: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=16))
        self._last_alert: dict[tuple[str, str], float] = {}
        self.stats = Counter()

    def _allowed(self, name: str) -> bool:
        return any(name == a or name.endswith("." + a) for a in self.config.allowlist)

    def _cooldown_ok(self, kind: str, key: str, now: float) -> bool:
        last = self._last_alert.get((kind, key))
        if last is not None and now - last < self.config.cooldown_seconds:
            return False
        self._last_alert[(kind, key)] = now
        return True

    @staticmethod
    def _emitter(q: DnsQuery) -> str:
        return f"pid:{q.pid}" if q.pid is not None else (q.client or "host")

    def feed(self, q: DnsQuery) -> list[DnsFinding]:
        if not q.qname:
            return []
        with self._lock:
            self.stats["queries"] += 1
            out: list[DnsFinding] = []
            out += self._check_ioc(q)
            if not self._allowed(q.qname):
                out += self._check_tunneling(q)
                out += self._check_nxdomain(q)
                out += self._check_beaconing(q)
            if len(self._subs) > self.config.max_tracked:
                self._subs.clear()
                self._beacon.clear()
            for f in out:
                self.stats[f.kind] += 1
            return out

    def feed_many(self, queries: Iterable[DnsQuery]) -> list[DnsFinding]:
        out: list[DnsFinding] = []
        for q in queries:
            out += self.feed(q)
        return out

    # ---- heuristiques ----------------------------------------------------

    def _finding(self, q: DnsQuery, kind, domain, weight, mitre, summary, **details):
        return DnsFinding(
            kind=kind,
            domain=domain,
            weight=weight,
            mitre=tuple(mitre),
            summary=summary,
            timestamp=q.timestamp,
            pid=q.pid,
            process_exe=q.process_exe,
            client=q.client,
            details=details,
        )

    def _check_ioc(self, q: DnsQuery) -> list[DnsFinding]:
        if self.ioc_lookup is None:
            return []
        try:
            hit = self.ioc_lookup.lookup_hostname(q.qname)
        except Exception:
            return []
        if hit is None or not self._cooldown_ok("dns_ioc", q.qname, q.timestamp):
            return []
        conf = int(getattr(hit, "confidence", 0) or 60)
        return [
            self._finding(
                q,
                "dns_ioc",
                q.qname,
                float(conf),
                ["T1071.004"],
                f"résolution d'un domaine malveillant connu {q.qname} "
                f"[{getattr(hit, 'source', '?')}/{getattr(hit, 'malware', '?')}]",
                feed=getattr(hit, "source", None),
                malware=getattr(hit, "malware", None),
                confidence=conf,
            )
        ]

    def _check_tunneling(self, q: DnsQuery) -> list[DnsFinding]:
        cfg = self.config
        base = registered_domain(q.qname)
        sub = q.qname[: -len(base)].rstrip(".") if q.qname != base else ""
        dq = self._subs[base]
        dq.append((q.timestamp, sub, q.qtype))
        cutoff = q.timestamp - cfg.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        uniq = {s for _, s, _ in dq if s}
        txt = sum(1 for _, _, t in dq if t in ("TXT", "NULL"))
        if len(uniq) < min(cfg.tunnel_min_unique, 10) and txt < cfg.tunnel_txt_min:
            return []
        flat = [s.replace(".", "") for s in uniq]
        mean_len = sum(map(len, flat)) / len(flat) if flat else 0.0
        mean_ent = sum(shannon_entropy(s) for s in flat) / len(flat) if flat else 0.0
        by_shape = (
            len(uniq) >= cfg.tunnel_min_unique
            and mean_len >= cfg.tunnel_min_mean_len
            and mean_ent >= cfg.tunnel_min_entropy
        )
        by_txt = txt >= cfg.tunnel_txt_min and len(uniq) >= 10
        if not (by_shape or by_txt) or not self._cooldown_ok("dns_tunneling", base, q.timestamp):
            return []
        return [
            self._finding(
                q,
                "dns_tunneling",
                base,
                70.0,
                ["T1071.004", "T1048.003"],
                f"tunneling DNS probable vers {base} : {len(uniq)} sous-domaines uniques "
                f"en {cfg.window_seconds:.0f}s (long. moy. {mean_len:.0f}, entropie "
                f"{mean_ent:.2f}, TXT/NULL={txt})",
                unique_subdomains=len(uniq),
                mean_length=round(mean_len, 1),
                mean_entropy=round(mean_ent, 2),
                txt_null=txt,
                sample=sorted(uniq)[:5],
            )
        ]

    def _check_nxdomain(self, q: DnsQuery) -> list[DnsFinding]:
        if q.rcode != RCODE_NXDOMAIN:
            return []
        cfg = self.config
        key = self._emitter(q)
        dq = self._nx[key]
        dq.append((q.timestamp, q.qname))
        cutoff = q.timestamp - cfg.nx_window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct = {n for _, n in dq}
        if len(dq) < cfg.nx_min_count or len(distinct) < cfg.nx_min_distinct:
            return []
        if not self._cooldown_ok("dns_nxdomain_burst", key, q.timestamp):
            return []
        return [
            self._finding(
                q,
                "dns_nxdomain_burst",
                registered_domain(q.qname),
                50.0,
                ["T1568.002"],
                f"rafale NXDOMAIN ({len(dq)} réponses, {len(distinct)} domaines distincts "
                f"en {cfg.nx_window_seconds:.0f}s) depuis {key} : DGA probable",
                nxdomain=len(dq),
                distinct=len(distinct),
                sample=sorted(distinct)[:5],
            )
        ]

    def _check_beaconing(self, q: DnsQuery) -> list[DnsFinding]:
        cfg = self.config
        key = (self._emitter(q), q.qname)
        dq = self._beacon[key]
        dq.append(q.timestamp)
        if len(dq) < cfg.beacon_min_queries:
            return []
        ts = list(dq)
        intervals = [b - a for a, b in itertools.pairwise(ts)]
        mean = sum(intervals) / len(intervals)
        if mean < cfg.beacon_min_interval:
            return []
        std = math.sqrt(sum((i - mean) ** 2 for i in intervals) / len(intervals))
        cv = std / mean if mean else 1.0
        if cv > cfg.beacon_max_cv:
            return []
        # Un beacon lent (ex. horaire) relancerait l'alerte à chaque requête si le
        # cooldown est plus court que sa période : une alerte par épisode observé.
        last = self._last_alert.get(("dns_beaconing", key[1]))
        episode = max(cfg.cooldown_seconds, mean * cfg.beacon_min_queries)
        if last is not None and q.timestamp - last < episode:
            return []
        self._last_alert[("dns_beaconing", key[1])] = q.timestamp
        return [
            self._finding(
                q,
                "dns_beaconing",
                q.qname,
                30.0,
                ["T1071.004"],
                f"beaconing DNS : {q.qname} interrogé toutes les {mean:.0f}s "
                f"(variation {cv:.0%}, {len(ts)} requêtes) depuis {key[0]}",
                interval_mean=round(mean, 1),
                cv=round(cv, 3),
                queries=len(ts),
            )
        ]


# --------------------------------------------------------------------------- #
# Parsing paquet DNS (sans dépendance)
# --------------------------------------------------------------------------- #


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = off
    for _ in range(128):  # garde-fou anti-boucle de pointeurs
        if off >= len(buf):
            raise ValueError("nom tronqué")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("pointeur tronqué")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            continue
        off += 1
        labels.append(buf[off : off + ln].decode("ascii", "replace"))
        off += ln
    else:
        raise ValueError("boucle de compression")
    return ".".join(labels), (end if jumped else off)


def parse_dns_message(payload: bytes) -> tuple[bool, int, list[tuple[str, int]]]:
    """-> (is_response, rcode, [(qname, qtype)])."""
    if len(payload) < 12:
        raise ValueError("en-tête DNS trop court")
    _id, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    if qd > 16:
        raise ValueError("qdcount absurde")
    off = 12
    questions = []
    for _ in range(qd):
        name, off = _read_name(payload, off)
        if off + 4 > len(payload):
            raise ValueError("question tronquée")
        qtype = struct.unpack("!H", payload[off : off + 2])[0]
        off += 4
        questions.append((name, qtype))
    return bool(flags & 0x8000), flags & 0x000F, questions


def parse_ethernet_dns(frame: bytes, *, port: int = 53) -> list[DnsQuery]:
    """Trame Ethernet -> DnsQuery (IPv4/IPv6, UDP port 53). [] si non-DNS."""
    if len(frame) < 14:
        return []
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100 and len(frame) >= 18:  # VLAN
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if ethertype == 0x0800:
        if len(frame) < off + 20:
            return []
        ihl = (frame[off] & 0x0F) * 4
        if frame[off + 9] != 17:
            return []
        src = str(ipaddress.IPv4Address(frame[off + 12 : off + 16]))
        dst = str(ipaddress.IPv4Address(frame[off + 16 : off + 20]))
        off += ihl
    elif ethertype == 0x86DD:
        if len(frame) < off + 40 or frame[off + 6] != 17:
            return []  # extension headers non gérés (rares pour DNS)
        src = str(ipaddress.IPv6Address(frame[off + 8 : off + 24]))
        dst = str(ipaddress.IPv6Address(frame[off + 24 : off + 40]))
        off += 40
    else:
        return []
    if len(frame) < off + 8:
        return []
    sport, dport = struct.unpack("!HH", frame[off : off + 4])
    if port not in (sport, dport):
        return []
    try:
        is_resp, rcode, questions = parse_dns_message(frame[off + 8 :])
    except (ValueError, struct.error):
        return []
    client = dst if is_resp else src
    now = time.time()
    return [
        DnsQuery(
            qname=name,
            qtype=QTYPES.get(qt, str(qt)),
            rcode=rcode if is_resp else None,
            timestamp=now,
            client=client,
            source="packet",
        )
        for name, qt in questions
    ]


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #

QueryCallback = Callable[[DnsQuery], None]


class SourceUnavailable(RuntimeError):
    pass


class PacketDnsSource:
    """Capture brute AF_PACKET (Linux, root) du DNS UDP/53."""

    name = "packet"

    def __init__(self, on_query: QueryCallback, *, interface: str = ""):
        self.on_query = on_query
        self.interface = interface
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = Counter()

    def start(self) -> None:
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
            raise SourceUnavailable("capture AF_PACKET : Linux uniquement")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                sock.bind((self.interface, 0))
            sock.settimeout(0.5)
        except (PermissionError, OSError) as exc:
            raise SourceUnavailable(f"capture AF_PACKET refusée (root requis ?) : {exc}") from exc
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="biocybe-dns-pkt", daemon=True)
        self._thread.start()
        logger.info("Capteur DNS : capture AF_PACKET %s", self.interface or "(toutes interfaces)")

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _loop(self) -> None:
        assert self._sock is not None
        seen: deque = deque(maxlen=512)  # dédup : même trame vue sur 2 interfaces (lo)
        while not self._stop.is_set():
            try:
                frame, _addr = self._sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError as exc:
                self.stats["errors"] += 1
                logger.warning("capteur DNS : erreur de capture (%s)", exc)
                continue
            for q in parse_ethernet_dns(frame):
                key = (q.qname, q.qtype, q.rcode, q.client, int(q.timestamp * 10))
                if key in seen:
                    continue
                seen.append(key)
                self.stats["queries"] += 1
                try:
                    self.on_query(q)
                except Exception as exc:
                    logger.error("capteur DNS : traitement : %s", exc)


def parse_sysmon_dns_events(xml_text: str) -> list[tuple[int, DnsQuery]]:
    """Sysmon Event ID 22 (DNSEvent) -> [(EventRecordID, DnsQuery)]."""
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
            if int(system.findtext(f"{ns}EventID") or 0) != 22:
                continue
            rid = int(system.findtext(f"{ns}EventRecordID") or 0)
        except ValueError:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.iter(f"{ns}Data")}
        status = data.get("QueryStatus", "")
        try:
            pid = int(data["ProcessId"]) if data.get("ProcessId") else None
            # Sysmon : 0 = succès, 9003 = DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN)
            rcode = 0 if status == "0" else (RCODE_NXDOMAIN if status == "9003" else None)
        except ValueError:
            continue
        out.append(
            (
                rid,
                DnsQuery(
                    qname=data.get("QueryName", ""),
                    rcode=rcode,
                    pid=pid,
                    process_exe=data.get("Image", ""),
                    source="sysmon",
                ),
            )
        )
    return out


class SysmonDnsSource:
    """Sysmon Event ID 22 via wevtutil (Windows), signet EventRecordID."""

    name = "sysmon"

    def __init__(self, on_query: QueryCallback, *, interval: float = 1.0, runner=None):
        from .process_sources import SYSMON_CHANNEL, _default_runner

        self.on_query = on_query
        self.interval = max(0.2, float(interval))
        self._run = runner or _default_runner
        self._channel = SYSMON_CHANNEL
        self._last = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = Counter()

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

    def start(self) -> None:
        if self._run.__name__ == "_default_runner" and not sys.platform.startswith("win"):
            raise SourceUnavailable("Sysmon : Windows uniquement")
        try:
            latest = parse_sysmon_dns_events(
                self._query("*[System[EventID=22]]", reverse=True, count=1)
            )
        except Exception as exc:
            raise SourceUnavailable(f"Sysmon (EID 22) inaccessible : {exc}") from exc
        self._last = latest[0][0] if latest else 0
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="biocybe-dns-sysmon", daemon=True)
        self._thread.start()
        logger.info("Capteur DNS : Sysmon Event ID 22 (signet %d)", self._last)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def poll_once(self) -> list[DnsQuery]:
        xpath = f"*[System[EventID=22 and EventRecordID>{int(self._last)}]]"
        out = []
        for rid, q in sorted(
            parse_sysmon_dns_events(self._query(xpath, reverse=False, count=1000)),
            key=lambda x: x[0],
        ):
            if rid <= self._last:
                continue
            self._last = rid
            self.stats["queries"] += 1
            out.append(q)
            self.on_query(q)
        return out

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self.stats["errors"] += 1
                logger.error("Sysmon DNS : lecture a échoué : %s", exc)
            self._stop.wait(self.interval)


def read_zeek_dns_log(path: str | Path) -> Iterator[DnsQuery]:
    """Lit un ``dns.log`` Zeek (TSV avec en-tête #fields, ou JSON lines)."""
    fields: list[str] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if line.lstrip().startswith("{"):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
            elif fields:
                rec = dict(zip(fields, line.split("\t"), strict=False))
            else:
                continue
            qname = rec.get("query")
            if not qname or qname == "-":
                continue
            rcode_raw = rec.get("rcode")
            try:
                rcode = int(rcode_raw) if rcode_raw not in (None, "-", "") else None
            except (TypeError, ValueError):
                rcode = None
            try:
                ts = float(rec.get("ts") or time.time())
            except (TypeError, ValueError):
                ts = time.time()
            qtype = rec.get("qtype_name") or "A"
            yield DnsQuery(
                qname=qname,
                qtype=qtype if qtype != "-" else "A",
                rcode=rcode,
                timestamp=ts,
                client=str(rec.get("id.orig_h") or ""),
                source="zeek",
            )


def build_dns_source(kind: str, on_query: QueryCallback, **kw):
    """``auto`` : Sysmon (Windows) sinon capture paquets (Linux root)."""
    kind = (kind or "auto").lower()
    if kind == "packet":
        return PacketDnsSource(on_query, interface=kw.get("interface", ""))
    if kind == "sysmon":
        return SysmonDnsSource(on_query)
    if kind != "auto":
        raise SourceUnavailable(f"source DNS inconnue : {kind!r}")
    if sys.platform.startswith("win"):
        return SysmonDnsSource(on_query)
    return PacketDnsSource(on_query, interface=kw.get("interface", ""))


class DnsMonitor:
    """Source -> analyseur -> callback ``on_finding``."""

    def __init__(
        self,
        analyzer: DnsAnalyzer | None = None,
        *,
        source: str = "auto",
        interface: str = "",
        on_finding: Callable[[DnsFinding], None] | None = None,
    ):
        self.analyzer = analyzer or DnsAnalyzer()
        self.source_kind = source
        self.interface = interface
        self.on_finding = on_finding
        self._source = None
        self.active_source = None

    def handle(self, q: DnsQuery) -> list[DnsFinding]:
        findings = self.analyzer.feed(q)
        for f in findings:
            logger.warning("[DNSMON] %s : %s", f.kind, f.summary)
            if self.on_finding is not None:
                try:
                    self.on_finding(f)
                except Exception as exc:
                    logger.error("dnsmon: on_finding a levé : %s", exc)
        return findings

    def start(self) -> bool:
        try:
            src = build_dns_source(self.source_kind, self.handle, interface=self.interface)
            src.start()
        except SourceUnavailable as exc:
            logger.warning("Capteur DNS indisponible : %s", exc)
            return False
        self._source = src
        self.active_source = src.name
        return True

    def stop(self) -> None:
        if self._source is not None:
            self._source.stop()
            self._source = None
