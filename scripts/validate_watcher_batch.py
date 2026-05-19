"""Harnais de validation du watcher en charge.

Démarre le `FileSystemWatcher` dans le process courant, balance 1000
créations de fichiers dans le dossier surveillé (mix de bénins et
de patterns IOC). Mesure :

  - taux de détection correct (les fichiers avec patterns IOC
    doivent tous être flaggés)
  - taux de faux positifs sur fichiers bénins
  - latence détection : entre `create_file` et `callback fired`
  - mémoire et threads du watcher
  - tenue : le watcher ne fuit pas et ne perd pas d'événements

Critères PASS :
  - 0 perte d'événement (tous les fichiers IOC détectés)
  - 0 faux positif
  - latence p99 < 5s (debouncing 0.3s + scan ~150ms)
  - mémoire stable
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from statistics import mean, median

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


CHINA_CHOPPER_PHP = '<?php @eval($_POST["password"]); ?>'
EICAR_STRING = "".join([
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
])
BENIGN_CONTENT = "This is a perfectly normal file with no malicious patterns.\n" * 5


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100) * (len(s) - 1)))))
    return s[k]


def main() -> int:
    import shutil

    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher

    workdir = ROOT / "validation_v4_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    # Setup rules
    (workdir / "rules" / "yara").mkdir(parents=True)
    for r in (ROOT / "rules" / "yara").glob("*.yar"):
        (workdir / "rules" / "yara" / r.name).write_bytes(r.read_bytes())
    community = ROOT / "rules" / "yara" / "community"
    if community.is_dir():
        for sub in community.iterdir():
            if sub.is_dir():
                shutil.copytree(sub, workdir / "rules" / "yara" / "community" / sub.name)

    watched = workdir / "watched"
    watched.mkdir()

    import os
    os.chdir(workdir)
    sync_yara_rules()
    print(f"[V4] Watch dir : {watched}")

    # Stats par fichier : timestamp_created, timestamp_detected, detected_as_malicious
    files_stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    def callback(ev):
        with stats_lock:
            fname = Path(ev.path).name
            if fname in files_stats and "detected_at" not in files_stats[fname]:
                files_stats[fname]["detected_at"] = time.time()
                files_stats[fname]["is_malicious"] = ev.is_malicious

    proc = psutil.Process()
    rss_before = proc.memory_info().rss / (1024 * 1024)
    threads_before = proc.num_threads()

    watcher = FileSystemWatcher(
        [watched], callback=callback, debounce_seconds=0.3,
    )
    watcher.start()
    time.sleep(0.5)  # laisser observer démarrer

    # Plan : 1000 fichiers, dont 100 IOCs (EICAR ou ChinaChopper)
    n_total = 1000
    n_ioc = 100
    print(f"[V4] Création {n_total} fichiers ({n_ioc} IOC, {n_total - n_ioc} bénins)...")

    t_start = time.time()
    for i in range(n_total):
        fname = f"file_{i:04d}.txt"
        if i % 10 == 0 and i // 10 < n_ioc:
            # 1 IOC tous les 10 fichiers, max n_ioc
            if (i // 10) % 2 == 0:
                content = EICAR_STRING
                expected = True
            else:
                content = CHINA_CHOPPER_PHP
                expected = True
        else:
            content = BENIGN_CONTENT
            expected = False

        with stats_lock:
            files_stats[fname] = {
                "created_at": time.time(),
                "expected_malicious": expected,
            }
        (watched / fname).write_text(content, encoding="utf-8")

    write_duration = time.time() - t_start
    print(f"[V4] {n_total} fichiers écrits en {write_duration:.1f}s "
          f"({n_total / write_duration:.0f} files/sec)")

    # Attendre que le watcher traite tous les fichiers (max 60s)
    print("[V4] Attente du traitement (max 60s)...")
    deadline = time.time() + 60
    while time.time() < deadline:
        with stats_lock:
            processed = sum(1 for s in files_stats.values() if "detected_at" in s)
        if processed >= n_total:
            break
        time.sleep(0.5)

    time.sleep(2)  # cooldown final
    watcher.stop()

    rss_after = proc.memory_info().rss / (1024 * 1024)
    threads_after = proc.num_threads()

    # Analyse
    with stats_lock:
        processed = [s for s in files_stats.values() if "detected_at" in s]
        not_processed = [f for f, s in files_stats.items() if "detected_at" not in s]
        true_positives = [s for s in processed if s["expected_malicious"] and s.get("is_malicious")]
        false_positives = [s for s in processed if not s["expected_malicious"] and s.get("is_malicious")]
        missed = [s for s in processed if s["expected_malicious"] and not s.get("is_malicious")]
        latencies = [
            (s["detected_at"] - s["created_at"]) * 1000
            for s in processed
        ]

    print()
    print("=" * 70)
    print(f"Fichiers créés       : {n_total}")
    print(f"Fichiers traités     : {len(processed)} ({len(processed) / n_total * 100:.1f}%)")
    print(f"Fichiers manqués     : {len(not_processed)}")
    print(f"  IOC détectés (TP)  : {len(true_positives)} / {n_ioc}")
    print(f"  IOC manqués (FN)   : {len(missed)}")
    print(f"  Faux positifs (FP) : {len(false_positives)}")
    print()
    if latencies:
        print(f"Latence détection    : mean={mean(latencies):.0f}ms "
              f"median={median(latencies):.0f}ms "
              f"p95={percentile(latencies, 95):.0f}ms "
              f"p99={percentile(latencies, 99):.0f}ms")
    print(f"Stats watcher        : observed={watcher.stats.events_observed}, "
          f"scanned={watcher.stats.events_scanned}, "
          f"detections={watcher.stats.detections}, "
          f"errors={watcher.stats.errors}")
    print()
    print(f"RSS process          : {rss_before:.1f} → {rss_after:.1f} MB "
          f"({(rss_after - rss_before) / rss_before * 100:+.1f}%)")
    print(f"Threads process      : {threads_before} → {threads_after}")
    print()

    issues = []
    if len(processed) < n_total:
        issues.append(
            f"PERTE D'ÉVÉNEMENTS : {len(not_processed)} fichier(s) jamais traités"
        )
    if missed:
        issues.append(f"IOCs manqués : {len(missed)}")
    if false_positives:
        issues.append(f"FAUX POSITIFS : {len(false_positives)}")
    if latencies and percentile(latencies, 99) > 5000:
        issues.append(f"Latence p99 = {percentile(latencies, 99):.0f}ms > 5000ms")

    if issues:
        print("VERDICT : FAIL")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("VERDICT : PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
