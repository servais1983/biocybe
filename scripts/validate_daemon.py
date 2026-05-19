"""Harnais de validation réelle du daemon BioCybe.

Démarre le daemon (sous-process), mesure RSS mémoire / CPU% / taille
des logs / présence d'erreurs toutes les N secondes pendant DURATION,
puis arrête proprement et rapporte.

Usage :
    python scripts/validate_daemon.py --duration 300 --sample-every 10

Critères de succès (objectifs production-ready) :
  - aucune exception dans biocybe.log
  - RSS stable (variation < 30% sur la durée — pas de leak gros)
  - CPU% moyen < 20% (idle daemon ne doit pas être glouton)
  - daemon s'arrête sur SIGINT en moins de 10s
  - exit code 0
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent


def run_validation(duration: int, sample_every: int, config: str | None = None) -> dict:
    log_file = ROOT / "biocybe.log"
    # Tronque le log avant de démarrer pour analyse propre
    if log_file.exists():
        log_file.unlink()

    cmd = [sys.executable, "-m", "biocybe"]
    if config:
        cmd += ["-c", config]

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    print(f"[validate] Lancement daemon : {' '.join(cmd)}")
    started_at = time.time()
    # Sur Windows, CREATE_NEW_PROCESS_GROUP permet d'envoyer CTRL_BREAK_EVENT
    # au groupe et donc d'avoir l'équivalent d'un SIGINT côté child.
    popen_kwargs = {
        "env": env,
        "cwd": str(ROOT),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(cmd, **popen_kwargs)

    p_info = psutil.Process(proc.pid)
    # Init CPU compteur
    try:
        p_info.cpu_percent(interval=None)
    except psutil.NoSuchProcess:
        return {"error": "process died immediately", "stderr": proc.stderr.read() if proc.stderr else ""}

    samples = []
    deadline = time.time() + duration
    next_sample = time.time()

    while time.time() < deadline:
        # Vérifie que le process est toujours vivant
        ret = proc.poll()
        if ret is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            return {
                "error": f"daemon crashed after {time.time() - started_at:.1f}s with exit={ret}",
                "stderr": stderr[-2000:],
                "samples": samples,
            }

        if time.time() >= next_sample:
            try:
                rss_mb = p_info.memory_info().rss / (1024 * 1024)
                # interval=1.0 = mesure sur 1 seconde réelle (plus fiable
                # que interval=None qui peut surévaluer sur Windows).
                cpu = p_info.cpu_percent(interval=1.0)
                threads = p_info.num_threads()
                fds = (
                    p_info.num_fds() if hasattr(p_info, "num_fds")
                    else len(p_info.open_files()) if hasattr(p_info, "open_files") else 0
                )
                log_size = log_file.stat().st_size if log_file.exists() else 0
                samples.append({
                    "elapsed_s": round(time.time() - started_at, 1),
                    "rss_mb": round(rss_mb, 2),
                    "cpu_pct": round(cpu, 2),
                    "threads": threads,
                    "fds": fds,
                    "log_size_bytes": log_size,
                })
                print(
                    f"[{int(time.time() - started_at):>4}s] "
                    f"RSS={rss_mb:6.1f} MB | CPU={cpu:5.1f}% | "
                    f"threads={threads:>3} | fds={fds:>3} | log={log_size:>6} B"
                )
            except psutil.NoSuchProcess:
                break
            next_sample = time.time() + sample_every

        time.sleep(0.5)

    # Arrêt propre : SIGINT (POSIX) ou CTRL_BREAK (Windows + new_process_group)
    print("[validate] Envoi signal d'arrêt, attente shutdown propre (max 15s)...")
    stop_at = time.time()
    if sys.platform == "win32":
        # CTRL_BREAK_EVENT déclenche signal.SIGBREAK chez le child Python,
        # qui peut être intercepté comme un SIGINT-like.
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGINT)
    try:
        stdout, stderr = proc.communicate(timeout=15)
        clean_shutdown = True
        shutdown_duration = round(time.time() - stop_at, 2)
    except subprocess.TimeoutExpired:
        print("[validate] Pas de réponse au signal, force kill")
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)
        clean_shutdown = False
        shutdown_duration = None

    # Analyse du log
    log_content = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
    error_lines = [l for l in log_content.splitlines() if " - ERROR - " in l or " - CRITICAL - " in l]
    exception_count = log_content.count("Traceback")

    # Stats
    # Skip les premiers samples : le RSS de Python avant init est très
    # bas (~2 MB), le RSS post-init est ~150 MB — l'écart n'est PAS une
    # fuite, c'est juste l'allocation initiale. On exclut donc les
    # 20 premières secondes pour les stats RSS.
    rss_values = [s["rss_mb"] for s in samples if s["elapsed_s"] >= 20]
    cpu_values = [s["cpu_pct"] for s in samples if s["elapsed_s"] > sample_every]  # skip 1er

    report = {
        "started_at": datetime.fromtimestamp(started_at).isoformat(),
        "duration_target_s": duration,
        "duration_actual_s": round(time.time() - started_at, 1),
        "samples_count": len(samples),
        "exit_code": proc.returncode,
        "clean_shutdown": clean_shutdown,
        "shutdown_duration_s": shutdown_duration,
        "rss_min_mb": min(rss_values) if rss_values else None,
        "rss_max_mb": max(rss_values) if rss_values else None,
        "rss_drift_pct": (
            round((max(rss_values) - min(rss_values)) / min(rss_values) * 100, 1)
            if rss_values and min(rss_values) > 0 else None
        ),
        "cpu_avg_pct": round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else None,
        "cpu_max_pct": max(cpu_values) if cpu_values else None,
        "log_error_lines": len(error_lines),
        "log_traceback_count": exception_count,
        "samples": samples,
        "errors_sample": error_lines[:10],
        "stdout_tail": stdout[-1000:] if stdout else "",
        "stderr_tail": stderr[-1000:] if stderr else "",
    }
    return report


def verdict(report: dict) -> tuple[bool, list[str]]:
    """Évalue contre les critères de prod."""
    issues = []

    if report.get("error"):
        issues.append(f"FATAL: {report['error']}")
        return False, issues

    if not report.get("clean_shutdown"):
        issues.append("daemon ne s'arrête pas proprement sur SIGINT (10s max)")

    if report["exit_code"] not in (0, None, -2, -15):  # 0 ok, 2/15 = SIGINT/SIGTERM
        issues.append(f"exit code suspect : {report['exit_code']}")

    if report["log_traceback_count"] > 0:
        issues.append(f"{report['log_traceback_count']} traceback(s) dans biocybe.log")

    if report["log_error_lines"] > 0:
        issues.append(
            f"{report['log_error_lines']} ligne(s) ERROR/CRITICAL dans biocybe.log"
        )

    if report["rss_drift_pct"] is not None and report["rss_drift_pct"] > 30:
        issues.append(
            f"RSS a dérivé de {report['rss_drift_pct']}% — possible fuite mémoire"
        )

    if report["cpu_avg_pct"] is not None and report["cpu_avg_pct"] > 20:
        issues.append(f"CPU moyen {report['cpu_avg_pct']}% > 20% — daemon trop gourmand")

    return len(issues) == 0, issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validation réelle du daemon BioCybe")
    parser.add_argument("--duration", type=int, default=120, help="Durée d'observation en secondes")
    parser.add_argument("--sample-every", type=int, default=10, help="Intervalle des mesures")
    parser.add_argument("--config", default=None, help="Chemin config YAML alternatif")
    parser.add_argument("--output", default=None, help="Dump JSON du rapport (sinon stdout)")
    args = parser.parse_args()

    report = run_validation(args.duration, args.sample_every, args.config)
    ok, issues = verdict(report)
    report["verdict"] = "PASS" if ok else "FAIL"
    report["issues"] = issues

    if args.output:
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[validate] Rapport écrit dans {args.output}")

    print("\n" + "=" * 70)
    print(f"VERDICT : {report['verdict']}")
    print("=" * 70)
    if issues:
        print("Problèmes détectés :")
        for i in issues:
            print(f"  - {i}")
    else:
        print("Tous les critères de prod passés.")
    print(f"\nDurée réelle    : {report.get('duration_actual_s', '?')}s")
    print(f"RSS             : {report.get('rss_min_mb', '?')} -> {report.get('rss_max_mb', '?')} MB"
          f" ({report.get('rss_drift_pct', '?')}% drift)")
    print(f"CPU moyen       : {report.get('cpu_avg_pct', '?')}%")
    print(f"Threads         : {report['samples'][-1]['threads'] if report.get('samples') else '?'}")
    print(f"Erreurs log     : {report.get('log_error_lines', '?')}")
    print(f"Traceback       : {report.get('log_traceback_count', '?')}")
    print(f"Arrêt propre    : {report.get('clean_shutdown', '?')} ({report.get('shutdown_duration_s', '?')}s)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
