"""Capteur DNS : heuristiques, parsing, sources, intégration."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import time
from types import SimpleNamespace

import pytest

from biocybe.dns_monitor import (
    DnsAnalyzer,
    DnsAnalyzerConfig,
    DnsMonitor,
    DnsQuery,
    SysmonDnsSource,
    parse_dns_message,
    parse_ethernet_dns,
    parse_sysmon_dns_events,
    read_zeek_dns_log,
    registered_domain,
    shannon_entropy,
)

T0 = 1_700_000_000.0


def _tunnel(n=30, domain="exfil-c2.test", qtype="TXT", t0=T0, client="10.0.0.5"):
    return [
        DnsQuery(
            f"{hashlib.sha256(str(i).encode()).hexdigest()[:40]}.{domain}",
            qtype=qtype,
            timestamp=t0 + i * 2,
            client=client,
        )
        for i in range(n)
    ]


def _kinds(findings):
    return [f.kind for f in findings]


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a.b.example.com", "example.com"),
        ("x.y.bbc.co.uk", "bbc.co.uk"),
        ("example.com", "example.com"),
        ("www.service-public.gouv.fr", "service-public.gouv.fr"),  # gouv.fr : suffixe public
    ],
)
def test_registered_domain(name, expected):
    assert registered_domain(name) == expected


def test_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy(hashlib.sha256(b"x").hexdigest()) > 3.5


# --------------------------------------------------------------------------- #
# Heuristiques
# --------------------------------------------------------------------------- #


def test_tunneling_detected_once_with_cooldown():
    an = DnsAnalyzer()
    findings = an.feed_many(_tunnel(60))
    assert _kinds(findings) == ["dns_tunneling"]  # une seule alerte (cooldown)
    f = findings[0]
    assert f.domain == "exfil-c2.test" and "T1071.004" in f.mitre
    assert f.details["unique_subdomains"] >= 20 and f.details["mean_entropy"] > 3.5


def test_txt_burst_detects_short_label_tunnel():
    an = DnsAnalyzer()
    qs = [DnsQuery(f"s{i:03d}.cmd.c2.test", qtype="TXT", timestamp=T0 + i) for i in range(25)]
    assert "dns_tunneling" in _kinds(an.feed_many(qs))


def test_realistic_benign_traffic_is_silent():
    """Navigation, CDN à sous-domaines aléatoires (allowlist), mises à jour,
    quelques NXDOMAIN (fautes de frappe) : aucun constat."""
    import random

    rng = random.Random(42)  # navigation humaine : intervalles aléatoires (Poisson)
    an = DnsAnalyzer()
    qs = []
    t = T0
    sites = ["example.com", "example.org", "wikipedia.org", "github.com", "bbc.co.uk"]
    for i in range(300):
        t += rng.expovariate(1 / 8.0)
        site = rng.choice(sites)
        qs.append(DnsQuery(f"{['www', 'api', 'static', 'mail'][i % 4]}.{site}", timestamp=t))
        # CDN : sous-domaines aléatoires mais allowlistés
        qs.append(
            DnsQuery(
                f"{hashlib.md5(str(i).encode()).hexdigest()}.cloudfront.net",
                timestamp=t,
            )
        )
        if i % 50 == 0:
            qs.append(DnsQuery(f"wwww.typo{i}.test", rcode=3, timestamp=t))
    assert an.feed_many(qs) == []


def test_legit_periodic_updater_is_weak_signal_not_incident():
    """Limite assumée : un logiciel légitime qui vérifie ses mises à jour à
    heure fixe ressemble à un beacon. Le signal est faible (30) et n'ouvre
    PAS d'incident seul ; il ne compte que corroboré (et se tolère via
    l'apprentissage FP ou l'allowlist)."""
    from biocybe.inflammation import InflammationEngine, from_dns_finding

    an = DnsAnalyzer()
    eng = InflammationEngine(host="h", clock=lambda: T0)
    findings = an.feed_many(
        [DnsQuery("update.vendor.test", timestamp=T0 + i * 3600) for i in range(10)]
    )
    assert _kinds(findings) == ["dns_beaconing"] and findings[0].weight == 30
    assert eng.ingest(from_dns_finding(findings[0])) is None


def test_nxdomain_burst_dga():
    an = DnsAnalyzer()
    qs = [
        DnsQuery(
            f"{hashlib.md5(str(i).encode()).hexdigest()[:14]}.test",
            rcode=3,
            timestamp=T0 + i,
            pid=4242,
            process_exe="/tmp/bot",
        )
        for i in range(30)
    ]
    findings = an.feed_many(qs)
    assert _kinds(findings) == ["dns_nxdomain_burst"]
    assert findings[0].pid == 4242 and "T1568.002" in findings[0].mitre


def test_beaconing_periodic_vs_jittered():
    an = DnsAnalyzer()
    periodic = [DnsQuery("update.beacon.test", timestamp=T0 + i * 60) for i in range(10)]
    assert "dns_beaconing" in _kinds(an.feed_many(periodic))
    an2 = DnsAnalyzer()
    jitter = [0, 7, 70, 75, 200, 230, 400, 405, 600, 800]
    irregular = [DnsQuery("news.example.test", timestamp=T0 + j) for j in jitter]
    assert an2.feed_many(irregular) == []


def test_ioc_domain_even_if_allowlisted_suffix_not_needed():
    class Lookup:
        def lookup_hostname(self, v):
            if v.endswith("evil-c2.test"):
                return SimpleNamespace(confidence=95, source="threatfox", malware="X")
            return None

    an = DnsAnalyzer(ioc_lookup=Lookup())
    f = an.feed(DnsQuery("panel.evil-c2.test", timestamp=T0))
    assert _kinds(f) == ["dns_ioc"] and f[0].weight == 95
    assert an.feed(DnsQuery("panel.evil-c2.test", timestamp=T0 + 5)) == []  # cooldown


def test_custom_allowlist_from_config():
    cfg = DnsAnalyzerConfig.from_dict({"allowlist": ["corp-cdn.test"], "tunnel_min_unique": 15})
    assert cfg.tunnel_min_unique == 15
    an = DnsAnalyzer(cfg)
    assert an.feed_many(_tunnel(60, domain="corp-cdn.test")) == []


# --------------------------------------------------------------------------- #
# Parsing paquets
# --------------------------------------------------------------------------- #


def _dns_query(name: str, qtype: int = 1, *, response=False, rcode=0) -> bytes:
    flags = (0x8000 if response else 0x0100) | rcode
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def _eth_ipv4_udp(payload: bytes, *, sport=40000, dport=53, vlan=False) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = (
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
        + socket.inet_aton("10.0.0.5")
        + socket.inet_aton("10.0.0.53")
    )
    eth = b"\x00" * 12 + (b"\x81\x00\x00\x01\x08\x00" if vlan else b"\x08\x00")
    return eth + ip + udp


def test_parse_dns_message_and_compression_loop_guard():
    resp, rcode, qs = parse_dns_message(_dns_query("a.b.test", 16, response=True, rcode=3))
    assert resp is True and rcode == 3 and qs == [("a.b.test", 16)]
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    with pytest.raises(ValueError):
        parse_dns_message(loop)
    with pytest.raises(ValueError):
        parse_dns_message(b"\x00\x01")


def test_parse_ethernet_variants():
    q = parse_ethernet_dns(_eth_ipv4_udp(_dns_query("x.c2.test", 16)))
    assert [(x.qname, x.qtype, x.rcode, x.client) for x in q] == [
        ("x.c2.test", "TXT", None, "10.0.0.5")
    ]
    r = parse_ethernet_dns(
        _eth_ipv4_udp(_dns_query("nx.test", response=True, rcode=3), sport=53, dport=40000)
    )
    assert r[0].rcode == 3 and r[0].client == "10.0.0.53"
    assert parse_ethernet_dns(_eth_ipv4_udp(_dns_query("v.test"), vlan=True))[0].qname == "v.test"
    assert parse_ethernet_dns(_eth_ipv4_udp(_dns_query("x.test"), dport=443, sport=1234)) == []
    assert parse_ethernet_dns(b"\x00" * 10) == []
    assert parse_ethernet_dns(_eth_ipv4_udp(b"\xff" * 5)) == []  # DNS malformé : ignoré


# --------------------------------------------------------------------------- #
# Capture réelle (Linux + root) : requêtes vers 127.0.0.1 uniquement
# --------------------------------------------------------------------------- #

_REAL = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(not _REAL, reason="capture AF_PACKET réelle : Linux + root")
def test_real_packet_capture_detects_tunnel_on_loopback():
    found = []
    mon = DnsMonitor(source="packet", interface="lo", on_finding=found.append)
    if not mon.start():
        pytest.skip("capture AF_PACKET indisponible ici")
    try:
        time.sleep(0.3)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(30):
            label = hashlib.sha256(f"real-{i}".encode()).hexdigest()[:40]
            s.sendto(_dns_query(f"{label}.loopback-tunnel.test", 16), ("127.0.0.1", 53))
        s.close()
        deadline = time.time() + 5
        while time.time() < deadline and not found:
            time.sleep(0.05)
    finally:
        mon.stop()
    assert [f.kind for f in found] == ["dns_tunneling"]
    assert found[0].domain == "loopback-tunnel.test"


# --------------------------------------------------------------------------- #
# Sysmon 22 / Zeek
# --------------------------------------------------------------------------- #

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon22(rid, qname, status="0", pid="1234", image=r"C:\Users\u\AppData\Local\Temp\x.exe"):
    return (
        f"<Event xmlns='{_NS}'><System><EventID>22</EventID><EventRecordID>{rid}"
        f"</EventRecordID></System><EventData><Data Name='QueryName'>{qname}</Data>"
        f"<Data Name='QueryStatus'>{status}</Data><Data Name='ProcessId'>{pid}</Data>"
        f"<Data Name='Image'>{image}</Data></EventData></Event>"
    )


def test_parse_sysmon22_links_process():
    evs = parse_sysmon_dns_events(_sysmon22(5, "a.test") + _sysmon22(6, "nx.test", "9003"))
    assert [(r, q.qname, q.rcode, q.pid) for r, q in evs] == [
        (5, "a.test", 0, 1234),
        (6, "nx.test", 3, 1234),
    ]
    assert evs[0][1].process_exe.endswith("x.exe")
    assert parse_sysmon_dns_events("<broken") == []


def test_sysmon_dns_source_bookmark():
    log = []

    def runner(cmd):
        q = next(a for a in cmd if a.startswith("/q:"))
        floor = int(q.split("EventRecordID>")[1].split("]")[0]) if ">" in q else -1
        items = [x for r, x in log if r > floor]
        return "".join(reversed(items) if "/rd:true" in cmd else items)

    log.append((1, _sysmon22(1, "old.test")))
    got = []
    src = SysmonDnsSource(got.append, runner=runner)
    src.start()
    try:
        log.append((2, _sysmon22(2, "new.test")))
        src.poll_once()
    finally:
        src.stop()
    assert [q.qname for q in got] == ["new.test"]


def test_zeek_tsv_and_json(tmp_path):
    tsv = tmp_path / "dns.log"
    lines = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tquery\tqtype_name\trcode",
    ]
    for q in _tunnel(30):
        lines.append(f"{q.timestamp}\tC1\t10.0.0.5\t{q.qname}\tTXT\t0")
    lines.append(f"{T0}\tC2\t10.0.0.5\t-\t-\t-")
    tsv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    qs = list(read_zeek_dns_log(tsv))
    assert len(qs) == 30 and qs[0].qtype == "TXT" and qs[0].rcode == 0

    js = tmp_path / "dns.json"
    js.write_text(
        "\n".join(
            json.dumps({"ts": T0 + i, "id.orig_h": "10.0.0.9", "query": f"q{i}.test", "rcode": 3})
            for i in range(3)
        )
        + "\nnot json\n",
        encoding="utf-8",
    )
    assert [q.rcode for q in read_zeek_dns_log(js)] == [3, 3, 3]


def test_cli_dns_analyze(tmp_path, capsys):
    from biocybe import cli

    log = tmp_path / "dns.log"
    log.write_text(
        "#fields\tts\tid.orig_h\tquery\tqtype_name\trcode\n"
        + "\n".join(f"{q.timestamp}\t10.0.0.5\t{q.qname}\tTXT\t0" for q in _tunnel(30))
        + "\n",
        encoding="utf-8",
    )
    assert cli.main(["dns", "analyze", str(log), "--no-ioc"]) == 1
    assert "dns_tunneling" in capsys.readouterr().out
    benign = tmp_path / "ok.log"
    benign.write_text("#fields\tts\tquery\n" + f"{T0}\twww.example.com\n", encoding="utf-8")
    assert cli.main(["dns", "analyze", str(benign), "--no-ioc"]) == 0


# --------------------------------------------------------------------------- #
# Corrélation
# --------------------------------------------------------------------------- #


def test_dns_tunnel_from_suspicious_process_is_systemic():
    """Processus lancé depuis /tmp (procmon) qui tunnelise en DNS (Sysmon 22) :
    même exe -> un seul incident systémique."""
    from biocybe.inflammation import DangerSignal, InflammationEngine, file_entity, from_dns_finding

    clock = [T0]
    eng = InflammationEngine(host="h", clock=lambda: clock[0])
    exe = "/tmp/.x/agent"
    eng.ingest(
        DangerSignal("process:exec_from_temp", "procmon", 25, entities=(file_entity(exe), "pid:77"))
    )
    an = DnsAnalyzer()
    inc = None
    for q in _tunnel(30):
        q.pid, q.process_exe = 77, exe
        for f in an.feed(q):
            clock[0] = q.timestamp
            inc = eng.ingest(from_dns_finding(f))
    assert inc is not None and inc.severity == "systemic"
    assert {"process:exec_from_temp", "dns:dns_tunneling"} <= set(inc.kinds)
    assert "T1071.004" in inc.mitre


def test_daemon_builder(monkeypatch):
    from biocybe import cli

    assert cli._build_dns_monitor_from_config({}, None) is None
    audited, notified = [], []
    monkeypatch.setattr("biocybe.audit.audit", lambda a, **kw: audited.append(a))
    mon = cli._build_dns_monitor_from_config(
        {"dnsmon": {"enabled": True, "db_path": "/nonexistent", "tunnel_min_unique": 20}},
        SimpleNamespace(notify=notified.append),
    )
    for q in _tunnel(30):
        mon.handle(q)
    assert audited == ["dns_finding"] and len(notified) == 1
