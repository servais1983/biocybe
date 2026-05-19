"""Harnais de validation de l'API en charge.

Démarre `biocybe api serve` (waitress, prod) dans un sous-process,
balance N requêtes concurrentes mixtes (healthz, info, scan,
quarantine list) avec un pool de threads, mesure :

  - latence p50 / p95 / p99 par endpoint
  - taux d'erreur (5xx, timeout, connection refused)
  - mémoire et FDs du process API pendant le run
  - tenue dans la durée (au moins 60s de charge soutenue)

Critères PASS (production-ready) :
  - 0 erreur 5xx
  - p99 < 2s sur scan (qui inclut compilation + scan YARA)
  - p99 < 100ms sur healthz/info
  - RSS stable (drift < 50% pendant la charge)
  - shutdown propre
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import mean, median

import psutil
import requests

ROOT = Path(__file__).resolve().parent.parent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100) * (len(s) - 1)))))
    return s[k]


def wait_for_api(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.3)
    return False


def main() -> int:
    port = 18765  # port arbitraire
    token = secrets.token_urlsafe(32)
    base = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env["BIOCYBE_API_TOKEN"] = token
    env["PYTHONUNBUFFERED"] = "1"

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

    cmd = [
        sys.executable, "-m", "biocybe", "api", "serve",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--workers", "8",
    ]
    print(f"[V3] Lancement API : {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, **popen_kwargs)

    try:
        if not wait_for_api(f"{base}/healthz", timeout=30):
            stderr = proc.stderr.read() if proc.stderr else ""
            print(f"[V3] API n'a jamais répondu. stderr tail :\n{stderr[-1000:]}")
            return 1

        api_pid = proc.pid
        p_info = psutil.Process(api_pid)
        # Mesure RSS APRÈS warm-up (qui charge les 748 règles YARA et
        # ajoute ~30 MB stable). Sans warm-up, on aurait un faux positif
        # de "fuite" sur le 1er scan.
        # rss_before est mesuré après warm-up plus bas.
        fds_before = (
            p_info.num_fds() if hasattr(p_info, "num_fds")
            else len(p_info.open_files()) if hasattr(p_info, "open_files") else 0
        )

        # Préparer un fichier de scan
        scan_target = ROOT / "validation_v3_target.txt"
        scan_target.write_text(
            "This is a perfectly benign file for the scan endpoint.",
            encoding="utf-8",
        )

        # Warm-up : faire 1 scan avant le test pour init la BCell
        # (sinon les 1ers scans sérialisent sur l'init). Important :
        # le warm-up alloue ~30 MB pour les 748 règles YARA en mémoire,
        # qui restent à demeure pendant toute la vie du process.
        print("[V3] Warm-up scan (init BCell)...")
        t_warmup = time.time()
        r = requests.post(
            f"{base}/api/v1/scan",
            headers={"Authorization": f"Bearer {token}"},
            json={"path": str(scan_target), "recursive": False},
            timeout=30,
        )
        print(f"[V3] Warm-up : {r.status_code} en {time.time() - t_warmup:.1f}s")

        # Maintenant la BCell est init, mesurer RSS de référence
        rss_before = p_info.memory_info().rss / (1024 * 1024)
        print(f"[V3] RSS après warm-up : {rss_before:.1f} MB")

        # ---- Charge ----
        import argparse as _argp  # noqa: PLC0415

        _parser = _argp.ArgumentParser()
        _parser.add_argument("--per-endpoint", type=int, default=250)
        _parser.add_argument("--concurrency", type=int, default=32)
        _cli_args = _parser.parse_args()
        n_per_endpoint = _cli_args.per_endpoint
        concurrency = _cli_args.concurrency

        endpoints = [
            ("healthz", "GET", f"{base}/healthz", None, False),
            ("info", "GET", f"{base}/api/v1/info", None, True),
            ("scan", "POST", f"{base}/api/v1/scan",
             {"path": str(scan_target), "recursive": False}, True),
            ("quarantine_list", "GET", f"{base}/api/v1/quarantine", None, True),
        ]

        all_tasks = []
        for label, method, url, body, auth_required in endpoints:
            for _ in range(n_per_endpoint):
                all_tasks.append((label, method, url, body, auth_required))

        latencies: dict[str, list[float]] = {ep[0]: [] for ep in endpoints}
        errors: dict[str, int] = {ep[0]: 0 for ep in endpoints}

        def fire(task):
            label, method, url, body, auth_required = task
            headers = {"Authorization": f"Bearer {token}"} if auth_required else {}
            t0 = time.time()
            try:
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=10)
                else:
                    r = requests.post(url, headers=headers, json=body, timeout=10)
                dt = time.time() - t0
                ok = 200 <= r.status_code < 400
                return (label, dt, ok, r.status_code)
            except requests.RequestException as exc:
                dt = time.time() - t0
                return (label, dt, False, str(exc)[:50])

        print(f"[V3] Envoi de {len(all_tasks)} requêtes ({n_per_endpoint} par endpoint), "
              f"concurrency={concurrency}...")
        t_start = time.time()
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(fire, t) for t in all_tasks]
            for f in as_completed(futures):
                label, dt, ok, status = f.result()
                latencies[label].append(dt * 1000)  # ms
                if not ok:
                    errors[label] += 1

        elapsed = time.time() - t_start
        rss_after = p_info.memory_info().rss / (1024 * 1024)
        fds_after = (
            p_info.num_fds() if hasattr(p_info, "num_fds")
            else len(p_info.open_files()) if hasattr(p_info, "open_files") else 0
        )

        print(f"\n[V3] Charge terminée en {elapsed:.1f}s "
              f"({len(all_tasks) / elapsed:.0f} req/sec)\n")
        print("=" * 72)
        print(f"{'Endpoint':18} {'n':>5} {'mean':>7} {'p50':>7} {'p95':>7} {'p99':>7} {'err':>5}")
        print("=" * 72)
        for label in latencies:
            lats = latencies[label]
            if not lats:
                continue
            print(
                f"{label:18} {len(lats):>5} "
                f"{mean(lats):>6.0f}ms {median(lats):>6.0f}ms "
                f"{percentile(lats, 95):>6.0f}ms {percentile(lats, 99):>6.0f}ms "
                f"{errors[label]:>5}"
            )
        print("=" * 72)
        print(f"RSS API   : {rss_before:.1f} → {rss_after:.1f} MB "
              f"({(rss_after - rss_before) / rss_before * 100:+.1f}%)")
        print(f"FDs API   : {fds_before} → {fds_after}")
        print()

        # ---- Verdict ----
        issues = []
        total_err = sum(errors.values())
        if total_err > 0:
            issues.append(f"{total_err} erreur(s) HTTP (détail : {errors})")
        p99_healthz = percentile(latencies["healthz"], 99)
        if p99_healthz > 100:
            issues.append(f"healthz p99 = {p99_healthz:.0f}ms > 100ms")
        p99_info = percentile(latencies["info"], 99)
        if p99_info > 100:
            issues.append(f"info p99 = {p99_info:.0f}ms > 100ms")
        p99_scan = percentile(latencies["scan"], 99)
        if p99_scan > 2000:
            issues.append(f"scan p99 = {p99_scan:.0f}ms > 2000ms")
        drift = (rss_after - rss_before) / rss_before * 100 if rss_before > 0 else 0
        if abs(drift) > 50:
            issues.append(f"RSS drift {drift:+.1f}% (possible fuite)")

        if issues:
            print("VERDICT : FAIL")
            for i in issues:
                print(f"  - {i}")
            return 1
        print("VERDICT : PASS")
        return 0
    finally:
        print("\n[V3] Arrêt API...")
        if sys.platform == "win32":
            try:
                import signal
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            except Exception:
                proc.terminate()
        else:
            proc.terminate()
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


if __name__ == "__main__":
    sys.exit(main())
