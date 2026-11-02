"""Validation end-to-end du système inflammatoire (corrélation multi-cellules).

Rejoue une kill chain complète avec de VRAIS composants :

  1. Watcher temps réel (watchdog) + vraie B-cell YARA sur un fichier EICAR
     -> signal ``file_malware``. La règle EICAR est de sévérité ``low``
     (poids 25 < seuil local 50) : le signal reste un PRÉCURSEUR sous le
     seuil — un fichier test isolé ne doit pas, seul, ouvrir un incident.
  2. Câblage netmon RÉEL du daemon (`_build_network_monitor_service_from_config`
     -> `on_match`) avec un `ConnectionRecord` dont l'exe est le fichier
     EICAR et l'IP distante une IP de test RFC 5737 -> signal ``network_ioc``
     -> incident ouvert directement SYSTÉMIQUE par co-stimulation, avec le
     fichier EICAR rattaché comme précurseur dans la chronologie.
     NB : la connexion est construite, pas observée (on ne lance pas un
     binaire malveillant qui contacte un C2). L'observation psutil réelle est
     déjà validée par `validate_intel_pipeline.py`.
  3. Auto-régénération réelle : baseline de fichiers, puis modification de
     masse -> rafale ransomware détectée par le watcher -> incident.
  4. Audit immuable : transitions présentes, chaîne SHA-256 intègre.
  5. CLI `biocybe incidents list` -> exit 2 (systémique ouvert) ; `show`.
  6. Résolution : décroissance (horloge avancée) -> incidents résolus.

Exit 0 si toutes les étapes passent.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

EICAR = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)", "7}$EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*"])
TEST_C2_IP = "203.0.113.66"  # RFC 5737 TEST-NET-3 — jamais une vraie cible
TIMEOUT = 15.0

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  {'[OK]  ' if ok else '[FAIL]'} {name}" + (f" — {detail}" if detail else ""))
    return ok


def wait_for(pred, timeout: float = TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="biocybe_inflam_"))
    old_cwd = os.getcwd()
    try:
        rules_dst = work / "rules" / "yara"
        rules_dst.mkdir(parents=True)
        for rule in (ROOT / "rules" / "yara").glob("*.yar"):
            shutil.copy(rule, rules_dst / rule.name)
        os.chdir(work)

        from biocybe import audit as audit_mod
        from biocybe import cli
        from biocybe.intel.ioc_lookup import IOCHit
        from biocybe.lymphocytes_b import BCell
        from biocybe.network_monitor import ConnectionRecord
        from biocybe.regeneration import SelfHealer
        from biocybe.scanner import sync_yara_rules
        from biocybe.watcher import FileSystemWatcher

        audit_log = audit_mod.AuditLog(work / "audit.jsonl")
        audit_mod.set_default(audit_log)
        notified: list = []
        notify_mgr = SimpleNamespace(notify=lambda ev: notified.append(ev))

        store = work / "incidents.jsonl"
        engine = cli._build_inflammation_from_config(
            {"inflammation": {"store_path": str(store)}}, notify_mgr
        )
        transitions: list[tuple[str, str, str]] = []
        engine.subscribe(lambda i, t: transitions.append((i.incident_id, t, i.severity)))

        watch = work / "watched"
        docs = watch / "docs"
        docs.mkdir(parents=True)
        protected = []
        for i in range(6):
            f = docs / f"rapport_{i}.txt"
            f.write_text(f"contenu sain {i}\n" * 20, encoding="utf-8")
            protected.append(f)
        healer = SelfHealer(vault_dir=work / "vault", manifest_path=work / "baseline.json")
        healer.baseline(protected)

        print("\n[1] Watcher réel + YARA : dépôt d'un fichier EICAR")
        sync_yara_rules()
        watcher = FileSystemWatcher(
            [watch],
            cell=BCell("realtime_watcher"),
            callback=cli._inflammation_watch_callback(engine),
            regen_callback=cli._inflammation_regen_callback(engine),
            regen_healer=healer,
            regen_burst_threshold=5,
            regen_burst_window=30.0,
        )
        watcher.start()
        try:
            time.sleep(0.5)
            dropper = watch / "dropper.exe"
            dropper.write_text(EICAR, encoding="ascii")
            check(
                "EICAR détecté par le watcher réel -> signal ingéré",
                wait_for(lambda: engine.stats["signals_received"] >= 1),
                f"detections={watcher.stats.detections}",
            )
            check(
                "signal faible isolé = précurseur, pas d'incident",
                engine.stats["signals_subthreshold"] == 1 and not engine.open_incidents(),
            )

            print("\n[2] Câblage netmon du daemon : l'exe EICAR contacte un C2 (RFC 5737)")
            (work / "db" / "signatures").mkdir(parents=True, exist_ok=True)
            service = cli._build_network_monitor_service_from_config(
                {"netmon": {"enabled": True, "db_path": str(work / "db" / "signatures")}},
                notify_mgr,
                inflammation=engine,
            )
            record = ConnectionRecord(
                pid=31337,
                process_name="dropper.exe",
                process_exe=str(dropper),
                laddr="10.0.0.5:51515",
                raddr=f"{TEST_C2_IP}:443",
                remote_ip=TEST_C2_IP,
                remote_port=443,
                status="ESTABLISHED",
                hit=IOCHit(
                    ioc_type="ip",
                    value=TEST_C2_IP,
                    source="abuse.ch/ThreatFox",
                    malware="TestBeacon",
                    confidence=80,
                ),
            )
            service.monitor.on_match(record)
            inc_id = transitions[0][0] if transitions else None
            inc = engine.get(inc_id) if inc_id else None
            check(
                "incident ouvert directement SYSTÉMIQUE (co-stimulation)",
                inc is not None
                and inc.severity == "systemic"
                and (inc_id, "opened", "systemic") in transitions,
                f"niveau={inc.current_level:.0f} costim={inc.signals[-1].costim_factor}"
                if inc
                else f"transitions={transitions}",
            )
            check(
                "fichier EICAR rattaché comme précurseur",
                inc is not None
                and inc.signals[0].kind == "file_malware"
                and inc.signals[0].correlation == "precursor",
            )
            check(
                "kill chain corrélée (file_malware + network_ioc, T1105 + T1071)",
                inc is not None
                and inc.kinds == ["file_malware", "network_ioc"]
                and {"T1105", "T1071"} <= set(inc.mitre),
                f"kinds={inc.kinds if inc else None} mitre={inc.mitre if inc else None}",
            )
            check("PID corrélé exposé pour réponse NK", inc is not None and inc.pids == [31337])

            print("\n[3] Auto-régénération réelle : modification de masse (ransomware)")
            for f in protected:
                f.write_text("ENCRYPTED" * 50, encoding="utf-8")
            check(
                "rafale ransomware -> incident",
                wait_for(
                    lambda: any("ransomware_burst" in i.kinds for i in engine.open_incidents())
                ),
                f"drift={watcher.stats.regen_drift_detected}",
            )
        finally:
            watcher.stop()

        rans = next((i for i in engine.open_incidents() if "ransomware_burst" in i.kinds), None)
        check(
            "incident ransomware SYSTÉMIQUE (fièvre hôte) + T1486",
            rans is not None and rans.severity == "systemic" and "T1486" in rans.mitre,
            f"hôte={engine.host_level:.0f}",
        )

        print("\n[4] Audit immuable + notifications")
        ok, errors = audit_log.verify()
        check("chaîne d'audit SHA-256 intègre", ok, "; ".join(errors[:3]))
        actions = [line for line in (work / "audit.jsonl").read_text("utf-8").splitlines()]
        check(
            "transitions auditées (incident_opened x2)",
            sum("incident_opened" in a for a in actions) == 2,
        )
        sevs = [e.severity.value for e in notified if e.kind.value == "incident"]
        check(
            "notification CRITICAL émise pour l'incident systémique", "critical" in sevs, str(sevs)
        )

        print("\n[5] CLI incidents")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["incidents", "list", "--store", str(store)])
        check("`incidents list` exit 2 (systémique ouvert)", rc == 2, f"rc={rc}")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["incidents", "show", inc_id or "x", "--store", str(store)])
        out = buf.getvalue()
        check("`incidents show` explique la chronologie", rc == 0 and "Chronologie" in out)
        print("\n" + "\n".join("      " + line for line in out.splitlines()[:12]))

        print("\n[6] Résolution par décroissance (horloge avancée de 2 h)")
        real_clock = engine._clock
        engine._clock = lambda: real_clock() + 7200
        resolved = engine.tick()
        check(
            "tous les incidents résolus quand le danger retombe",
            len(resolved) >= 2 and not engine.open_incidents(),
            f"résolus={len(resolved)}",
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["incidents", "list", "--store", str(store)])
        check("`incidents list` exit 0 après résolution", rc == 0, f"rc={rc}")
    finally:
        os.chdir(old_cwd)
        try:
            from biocybe import audit as audit_mod

            audit_mod.set_default(None)
        except Exception:
            pass
        shutil.rmtree(work, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\nRésultat : {len(results) - len(failed)}/{len(results)} PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
