"""V5 : validation du stack complet en daemon (5 min).

Démarre `biocybe` avec :
  - 6 cellules (2 macrophages + 2 b_cells + 2 t_cells)
  - Watcher real-time sur un dossier de test
  - Audit log activé via config
  - Quarantine automatique sur détection

Pendant la durée d'observation, on injecte périodiquement des fichiers
mixtes (IOC + bénins) dans le dossier surveillé. À la fin, on vérifie :

  - 0 erreur / traceback dans biocybe.log
  - audit log non corrompu (chaîne SHA-256 valide)
  - Toutes les injections IOC ont produit une entrée audit
    `quarantine_created` et un fichier dans `quarantine/`
  - 0 faux positif (pas de fichier bénin quarantiné)
  - RSS stable
  - Arrêt propre
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


EICAR_STRING = "".join([
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
])


def main() -> int:
    workdir = ROOT / "validation_v5_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    # Copie rules natives + community si présentes.
    # Phase 3.a : grâce au cache `compiled.yarc`, le 2e démarrage est
    # rapide même avec 748 règles communautaires (mesuré ~50 ms vs
    # ~1m15 sans cache sur Windows + Defender).
    (workdir / "rules" / "yara").mkdir(parents=True)
    for r in (ROOT / "rules" / "yara").glob("*.yar"):
        (workdir / "rules" / "yara" / r.name).write_bytes(r.read_bytes())
    if os.environ.get("V5_WITH_COMMUNITY") == "1":
        community = ROOT / "rules" / "yara" / "community"
        if community.is_dir():
            for sub in community.iterdir():
                if sub.is_dir():
                    shutil.copytree(sub, workdir / "rules" / "yara" / "community" / sub.name)
            print("[V5] Community rules activées (V5_WITH_COMMUNITY=1)")

    watched = workdir / "watched"
    watched.mkdir()

    # Config qui active audit + cellules
    cfg_path = workdir / "config" / "biocybe.yaml"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(
        """
core:
  state_save_interval: 60
  log_level: INFO

audit:
  enabled: true
  path: logs/audit.jsonl

cells:
  autoload: true
  enabled_types: [macrophage, b_cell, t_cell]
  macrophage:
    instances:
      - name: macrophage_system
        config:
          scan_interval: 300
  b_cell:
    instances:
      - name: b_cell_main
        config:
          db_path: db/signatures
  t_cell:
    instances:
      - name: t_cell_behavior
        config:
          model_dir: models/t_cell
          scan_interval_seconds: 10
""",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    cmd = [
        sys.executable, "-m", "biocybe",
        "-c", str(cfg_path),
        "--watch", str(watched),
        "--watch-quarantine",
    ]
    print(f"[V5] Daemon : {' '.join(cmd)}")

    popen_kwargs = {
        "env": env,
        "cwd": str(workdir),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(cmd, **popen_kwargs)

    try:
        # Attendre activement que le watcher soit prêt en cherchant
        # "Surveillance temps-réel" dans biocybe.log. Sinon on injecte
        # des fichiers avant qu'ils ne soient observés.
        biocybe_log_path = workdir / "biocybe.log"
        watcher_ready = False
        # Avec 748 community rules + Defender Windows, le COLD start
        # peut prendre 2-3 min (compile YARA mode tolérant). Au WARM
        # start (cache .yarc présent), c'est < 5s.
        startup_deadline = time.time() + 240  # 4 min max init (cold worst case)
        print("[V5] Attente démarrage watcher (max 120s)...")
        while time.time() < startup_deadline:
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                print(f"[V5] Daemon mort au démarrage. stderr :\n{stderr[-1500:]}")
                return 1
            if biocybe_log_path.exists():
                content = biocybe_log_path.read_text(encoding="utf-8", errors="replace")
                if "Surveillance temps-réel" in content:
                    watcher_ready = True
                    print(f"[V5] Watcher prêt après {int(time.time() - startup_deadline + 120)}s")
                    break
            time.sleep(1)
        if not watcher_ready:
            print("[V5] Watcher n'a jamais démarré (timeout 120s)")
            return 1

        p_info = psutil.Process(proc.pid)
        rss_baseline = p_info.memory_info().rss / (1024 * 1024)
        print(f"[V5] Daemon up, RSS baseline = {rss_baseline:.1f} MB")

        # Durée configurable via env (défaut 90s pour itération rapide).
        # Pour validation officielle prod : DAEMON_VALIDATION_DURATION=300
        duration_s = int(os.environ.get("DAEMON_VALIDATION_DURATION", "90"))
        inject_every_s = 15
        ioc_per_inject = 1
        benign_per_inject = 5

        injected_iocs = 0
        injected_benigns = 0
        next_inject = time.time() + 5
        deadline = time.time() + duration_s
        rss_samples = []

        while time.time() < deadline:
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                print(f"[V5] Daemon CRASHED. stderr tail :\n{stderr[-1500:]}")
                return 1
            if time.time() >= next_inject:
                # Injecter IOCs
                for i in range(ioc_per_inject):
                    f = watched / f"ioc_{injected_iocs:04d}.com"
                    f.write_text(EICAR_STRING, encoding="ascii")
                    injected_iocs += 1
                # Injecter bénins
                for i in range(benign_per_inject):
                    f = watched / f"benign_{injected_benigns:04d}.txt"
                    f.write_text(f"normal file {i}\n" * 5, encoding="utf-8")
                    injected_benigns += 1
                # Sample RSS
                try:
                    rss = p_info.memory_info().rss / (1024 * 1024)
                    rss_samples.append(rss)
                    elapsed = int(time.time() - (deadline - duration_s))
                    print(f"[{elapsed:>3}s] injected {injected_iocs} IOC + "
                          f"{injected_benigns} bénins ; RSS = {rss:.1f} MB")
                except psutil.NoSuchProcess:
                    break
                next_inject = time.time() + inject_every_s
            time.sleep(1)

        # Laisser 5s au watcher pour finir de traiter
        time.sleep(5)

        # Arrêt propre
        print("[V5] Signal d'arrêt...")
        if sys.platform == "win32":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=30)
            clean_shutdown = True
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            clean_shutdown = False

        # DEBUG : afficher fin de stderr (erreurs masquées)
        if stderr and stderr.strip():
            print("\n[V5] === STDERR DAEMON (tail) ===")
            print(stderr[-1500:])
        if stdout and stdout.strip():
            print("\n[V5] === STDOUT DAEMON (tail) ===")
            print(stdout[-500:])

        # ---- Analyse ----
        biocybe_log = workdir / "biocybe.log"
        audit_log = workdir / "logs" / "audit.jsonl"
        quarantine_manifest = workdir / "quarantine" / "manifest.json"

        log_content = biocybe_log.read_text(encoding="utf-8", errors="replace") if biocybe_log.exists() else ""
        error_lines = [l for l in log_content.splitlines() if " - ERROR - " in l]
        tracebacks = log_content.count("Traceback")

        # Audit log
        audit_entries = []
        if audit_log.exists():
            for line in audit_log.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        audit_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        quarantine_audit = [e for e in audit_entries if e.get("action") == "quarantine_created"]

        # Audit verify (chaîne)
        try:
            sys.path.insert(0, str(ROOT / "src"))
            from biocybe.audit import AuditLog  # noqa: PLC0415
            audit_obj = AuditLog(audit_log)
            audit_ok, audit_errors = audit_obj.verify()
        except Exception as exc:
            audit_ok = False
            audit_errors = [f"verify a planté : {exc}"]

        # Quarantine manifest
        manifest_entries = []
        if quarantine_manifest.exists():
            try:
                manifest_entries = json.loads(quarantine_manifest.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        # FP : un fichier bénin (begin_*.txt) en quarantaine ?
        fp_in_quarantine = [
            m for m in manifest_entries
            if Path(m["original_path"]).name.startswith("benign_")
        ]

        print()
        print("=" * 70)
        print(f"Durée daemon            : {duration_s}s + warmup")
        print(f"IOCs injectés           : {injected_iocs}")
        print(f"Bénins injectés         : {injected_benigns}")
        print(f"Audit entries           : {len(audit_entries)}")
        print(f"Audit quarantines       : {len(quarantine_audit)}")
        print(f"Quarantine manifest     : {len(manifest_entries)} entrée(s)")
        print(f"Faux positifs quarantine: {len(fp_in_quarantine)}")
        print(f"Audit chaîne OK         : {audit_ok}")
        print(f"Erreurs log             : {len(error_lines)}")
        print(f"Tracebacks log          : {tracebacks}")
        print(f"RSS min/max             : {min(rss_samples):.1f} / {max(rss_samples):.1f} MB")
        rss_drift = (max(rss_samples) - min(rss_samples)) / min(rss_samples) * 100 if rss_samples else 0
        print(f"RSS drift               : {rss_drift:+.1f}%")
        print(f"Arrêt propre            : {clean_shutdown}")
        print()

        issues = []
        if not clean_shutdown:
            issues.append("daemon ne s'arrête pas proprement")
        if tracebacks > 0:
            issues.append(f"{tracebacks} traceback(s) dans biocybe.log")
        if error_lines:
            issues.append(f"{len(error_lines)} ligne(s) ERROR dans biocybe.log (1er: {error_lines[0][:120]})")
        if not audit_ok:
            issues.append(f"audit chaîne SHA-256 corrompue : {audit_errors[:3]}")
        if len(quarantine_audit) < injected_iocs:
            issues.append(
                f"{injected_iocs - len(quarantine_audit)} IOC(s) injecté(s) "
                "n'ont PAS d'entrée audit quarantine_created"
            )
        if len(manifest_entries) < injected_iocs:
            issues.append(
                f"{injected_iocs - len(manifest_entries)} IOC(s) absent(s) du manifeste quarantaine"
            )
        if fp_in_quarantine:
            issues.append(f"{len(fp_in_quarantine)} faux positif(s) quarantinés !")
        if rss_drift > 30:
            issues.append(f"RSS drift {rss_drift:.1f}% > 30% (fuite mémoire ?)")

        if issues:
            print("VERDICT : FAIL")
            for i in issues:
                print(f"  - {i}")
            return 1
        print("VERDICT : PASS")
        return 0

    finally:
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
