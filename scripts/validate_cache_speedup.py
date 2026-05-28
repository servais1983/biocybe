"""Mesure le speedup du cache YARA en démarrage daemon réel.

Lance le daemon DEUX fois avec community rules :
  - 1er run : compile + crée le cache (COLD)
  - 2e run : recharge depuis cache (WARM)

Mesure le temps entre `os.makedirs(directory, exist_ok=True)` (1er log)
et `Surveillance temps-réel :` (watcher prêt) dans biocybe.log.

Critère PASS : warm_start < 10s (vs cold_start ~120s sur Windows).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")


def parse_ts(line: str) -> float | None:
    m = LOG_TS_RE.match(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f").timestamp()


def measure_startup(workdir: Path, max_wait: int) -> tuple[float, int]:
    """Lance le daemon dans workdir, mesure le temps jusqu'à 'Surveillance'.

    Retourne (startup_seconds, exit_code_du_test). exit=0 si OK.
    """
    cfg_path = workdir / "config" / "biocybe.yaml"
    watched = workdir / "watched"
    biocybe_log = workdir / "biocybe.log"
    if biocybe_log.exists():
        biocybe_log.unlink()

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    cmd = [
        sys.executable, "-m", "biocybe",
        "-c", str(cfg_path),
        "--watch", str(watched),
        "--watch-quarantine",
    ]
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

    started_polling = time.time()
    first_ts = None
    ready_ts = None

    try:
        deadline = time.time() + max_wait
        while time.time() < deadline:
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                print(f"  ✗ Daemon mort : {stderr[-500:]}")
                return -1, 1
            if biocybe_log.exists():
                try:
                    content = biocybe_log.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""
                if first_ts is None:
                    for line in content.splitlines():
                        ts = parse_ts(line)
                        if ts is not None:
                            first_ts = ts
                            break
                if first_ts is not None and "Surveillance temps-réel" in content:
                    for line in content.splitlines():
                        if "Surveillance temps-réel" in line:
                            ready_ts = parse_ts(line)
                            break
                    if ready_ts is not None:
                        break
            time.sleep(0.5)

        if ready_ts is None or first_ts is None:
            print(f"  ✗ Watcher pas prêt en {max_wait}s")
            return -1, 1
        return ready_ts - first_ts, 0
    finally:
        if proc.poll() is None:
            try:
                if sys.platform == "win32":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()


def main() -> int:
    workdir = ROOT / "validation_cache_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    # Setup : config + 748 community rules
    (workdir / "rules" / "yara").mkdir(parents=True)
    for r in (ROOT / "rules" / "yara").glob("*.yar"):
        (workdir / "rules" / "yara" / r.name).write_bytes(r.read_bytes())
    community = ROOT / "rules" / "yara" / "community"
    n_community = 0
    if community.is_dir():
        for sub in community.iterdir():
            if sub.is_dir():
                shutil.copytree(sub, workdir / "rules" / "yara" / "community" / sub.name)
                n_community += sum(1 for _ in (workdir / "rules" / "yara" / "community" / sub.name).glob("*.yar"))
    print(f"[cache-test] {n_community} community rules + 2 natives = {n_community + 2} fichiers YARA")

    (workdir / "watched").mkdir()
    (workdir / "config").mkdir()
    (workdir / "config" / "biocybe.yaml").write_text(
        """
core:
  state_save_interval: 9999
  log_level: INFO
cells:
  autoload: true
  enabled_types: [b_cell]
  b_cell:
    instances:
      - name: b_cell_main
        config:
          db_path: db/signatures
""",
        encoding="utf-8",
    )

    # Cold-start = compilation de ~744 règles SANS cache.
    # Cas observés sur Windows + Defender actif :
    #   - Bulk compile (toutes règles OK) : ~311 s
    #   - Mode tolérant (file-by-file, lorsque certaines règles
    #     communautaires ont des identifiants indéfinis comme "filepath")
    #     : ~1200 s (≈ 20 min). Mesure réelle observée le 2026-05-28.
    # Le timeout doit accommoder le pire cas. Le cold est informatif ;
    # la vraie assertion est le warm < 10s (preuve que .yarc fonctionne).
    print("[cache-test] RUN 1 (cold, compile + save cache)... (peut prendre 5-20 min)")
    cold_time, rc = measure_startup(workdir, max_wait=1800)
    if rc != 0:
        return 1
    print(f"[cache-test] COLD startup : {cold_time:.1f}s")

    cache_bin = workdir / "db" / "signatures" / "yara" / "compiled.yarc"
    cache_fp = workdir / "db" / "signatures" / "yara" / "compiled.fingerprint.json"
    if cache_bin.exists():
        print(f"[cache-test] Cache .yarc créé : {cache_bin.stat().st_size / 1024:.0f} KB")
    else:
        print("[cache-test] ✗ Cache .yarc PAS créé !")
        return 1

    print("[cache-test] RUN 2 (warm, load cache)...")
    warm_time, rc = measure_startup(workdir, max_wait=60)
    if rc != 0:
        return 1
    print(f"[cache-test] WARM startup : {warm_time:.1f}s")

    speedup = cold_time / max(warm_time, 0.1)
    print()
    print("=" * 60)
    print(f"COLD : {cold_time:>6.1f}s")
    print(f"WARM : {warm_time:>6.1f}s")
    print(f"Speedup : x{speedup:.0f}")
    print("=" * 60)

    if warm_time > 10:
        print("VERDICT : FAIL — warm start > 10s, cache n'aide pas assez")
        return 1
    print("VERDICT : PASS — cache YARA fonctionnel en daemon réel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
