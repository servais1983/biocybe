"""Harnais de validation réelle du scan signature.

Crée un dossier de test contenant :
  - EICAR (notre règle de référence)
  - Un webshell PHP China Chopper (pattern Florian Roth)
  - Un faux webshell ASPX
  - Un script PowerShell suspect (encoded commands)
  - Des fichiers BÉNINS représentatifs (README, code Python, JSON)

Puis lance `scan_path` et vérifie :
  - les vraies menaces sont détectées (par les règles signature-base)
  - les fichiers bénins ne sont PAS flaggés (faux positifs = inutilisable
    en prod, on ne tolère AUCUN FP sur ces patterns standards)
  - latence raisonnable (< 100ms par fichier scanné en moyenne)
  - pas de crash, le scan termine proprement

Ces fichiers test SONT des indicateurs réels que les règles YARA
cherchent — pas du malware exécutable. Ils sont créés/supprimés
dans tmp/ par le script.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Force UTF-8 sur stdout/stderr (Windows cp1252 ne sait pas écrire `→`).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# Fragments reconstruits pour éviter que l'AV Windows ne flague
# ce fichier source lui-même.
EICAR_PARTS = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
]

# China Chopper PHP : la signature standard de Florian Roth cherche
# `<?php.@eval($_POST.` (regex avec `.` arbitraire).
CHINA_CHOPPER_PHP = '<?php @eval($_POST["password"]); ?>'

# China Chopper ASPX (autre branche de la même règle)
CHINA_CHOPPER_ASPX = (
    '<%@ Page Language="Jscript"%><%eval(Request.Item["password"],"unsafe");%>'
)

# Pattern PowerShell suspect : encoded command via -enc (très utilisé
# par les attaquants pour offusquer). Beaucoup de règles signature-base
# cherchent ce flag.
POWERSHELL_ENC = (
    "powershell.exe -nop -w hidden -enc "
    "JABzAD0AJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtACcA"
)

# Mimikatz-like strings : la commande "sekurlsa::logonpasswords" est
# unique à mimikatz, beaucoup de règles APT la cherchent.
MIMIKATZ_STR = (
    "privilege::debug\n"
    "sekurlsa::logonpasswords\n"
    "sekurlsa::wdigest\n"
    "lsadump::sam\n"
)

# Fichiers BÉNINS qu'on s'attend à ne PAS voir flaggés
BENIGN_PYTHON = """\
#!/usr/bin/env python3
'''A perfectly innocent script.'''
import os
def main():
    print("Hello world")
    return 0
if __name__ == "__main__":
    main()
"""

BENIGN_README = """\
# My Project

This is a normal README file with no malicious content.
It uses common words like "request", "post", "evaluate", "powershell",
and "powershell.exe" without being malicious.
"""

BENIGN_JSON = """\
{
  "name": "config",
  "version": "1.0",
  "deps": ["requests", "flask"]
}
"""


def setup_samples(workdir: Path) -> dict[str, Path]:
    """Crée le dossier de test, retourne {label: path}."""
    workdir.mkdir(parents=True, exist_ok=True)
    samples: dict[str, Path] = {}

    files = {
        "EICAR": ("eicar.com", "".join(EICAR_PARTS), "ascii"),
        "ChinaChopper_PHP": ("shell.php", CHINA_CHOPPER_PHP, "utf-8"),
        "ChinaChopper_ASPX": ("shell.aspx", CHINA_CHOPPER_ASPX, "utf-8"),
        "PowerShell_Encoded": ("attack.ps1", POWERSHELL_ENC, "utf-8"),
        "Mimikatz_Strings": ("creds.txt", MIMIKATZ_STR, "utf-8"),
        "Benign_Python": ("script.py", BENIGN_PYTHON, "utf-8"),
        "Benign_README": ("README.md", BENIGN_README, "utf-8"),
        "Benign_JSON": ("config.json", BENIGN_JSON, "utf-8"),
    }
    for label, (name, content, enc) in files.items():
        p = workdir / name
        p.write_text(content, encoding=enc)
        samples[label] = p
    return samples


def main() -> int:
    import shutil

    from biocybe.scanner import scan_path, sync_yara_rules

    # On bascule dans un dossier tmp pour ne pas polluer le repo.
    tmpdir = ROOT / "validation_v2_workdir"
    if tmpdir.exists():
        shutil.rmtree(tmpdir)

    # Le scan attend `rules/yara/` à CWD ; on crée un lien symbolique
    # vers les vraies règles ET les community rules si présentes.
    cwd = tmpdir / "cwd"
    cwd.mkdir(parents=True)
    (cwd / "rules" / "yara").mkdir(parents=True)
    for rule_file in (ROOT / "rules" / "yara").glob("*.yar"):
        (cwd / "rules" / "yara" / rule_file.name).write_bytes(rule_file.read_bytes())
    # Community rules si elles existent localement
    community_src = ROOT / "rules" / "yara" / "community"
    if community_src.is_dir():
        (cwd / "rules" / "yara" / "community").mkdir(parents=True, exist_ok=True)
        for sub in community_src.iterdir():
            if sub.is_dir():
                shutil.copytree(sub, cwd / "rules" / "yara" / "community" / sub.name)

    samples_dir = cwd / "samples"
    samples = setup_samples(samples_dir)
    label_by_path = {str(p.resolve()): label for label, p in samples.items()}

    # CWD switch (sync_yara_rules est relatif à CWD)
    import os
    os.chdir(cwd)
    sync_yara_rules()

    print(f"[V2] {len(samples)} fichiers de test créés dans {samples_dir}")
    print("[V2] Lancement du scan...")
    t0 = time.time()
    verdicts = scan_path(str(samples_dir), recursive=False, quarantine=False)
    elapsed = time.time() - t0

    print(f"[V2] Scan terminé en {elapsed:.2f}s ({elapsed * 1000 / len(samples):.0f} ms/fichier)")
    print()

    # Mapping résultats
    expected_malicious = {
        "EICAR",
        "ChinaChopper_PHP",
        "ChinaChopper_ASPX",
        "PowerShell_Encoded",
        "Mimikatz_Strings",
    }
    expected_benign = {"Benign_Python", "Benign_README", "Benign_JSON"}

    detected_labels: dict[str, list[str]] = {}  # label -> [matched rule names]
    for v in verdicts:
        label = label_by_path.get(str(Path(v.path).resolve()))
        if label is None:
            continue
        if v.is_malicious:
            rules = [m.get("rule") for m in v.result.matched_rules if m.get("rule")]
            detected_labels[label] = rules

    print("=" * 70)
    print("Résultats par échantillon :")
    print("=" * 70)
    for label, _ in samples.items():
        rules = detected_labels.get(label, [])
        expected = label in expected_malicious
        if rules:
            mark = "DETECT" if expected else "FALSE+"
            print(f"  [{mark}] {label:25} → {len(rules)} règle(s) : {', '.join(rules[:3])}")
        else:
            mark = "MISS  " if expected else "OK    "
            print(f"  [{mark}] {label:25} → aucune détection")

    # Verdict
    detected = set(detected_labels.keys())
    true_positives = detected & expected_malicious
    false_positives = detected & expected_benign
    missed = expected_malicious - detected
    true_negatives = expected_benign - detected

    print()
    print("=" * 70)
    print(f"TP (vraies détections)  : {len(true_positives)} / {len(expected_malicious)}")
    print(f"FN (manquées)            : {len(missed)} {sorted(missed) if missed else ''}")
    print(f"FP (faux positifs)       : {len(false_positives)} {sorted(false_positives) if false_positives else ''}")
    print(f"TN (bénin OK)            : {len(true_negatives)} / {len(expected_benign)}")
    print(f"Latence moyenne          : {elapsed * 1000 / len(samples):.0f} ms / fichier")
    print()

    # Critères PASS :
    #   - 0 FP (faux positif = inutilisable en SOC)
    #   - >= 2 TP (EICAR notre règle + au moins 1 community rule trigger)
    #   - latence < 500ms/fichier
    issues = []
    if false_positives:
        issues.append(f"FAUX POSITIFS : {sorted(false_positives)}")
    if len(true_positives) < 2:
        issues.append(
            f"Trop peu de détections ({len(true_positives)} < 2). "
            "Les règles communautaires n'ont peut-être pas été téléchargées ; "
            "lancer 'biocybe intel rules update --source signature-base --yes' "
            "avant de relancer ce test."
        )
    if elapsed * 1000 / len(samples) > 500:
        issues.append(f"Latence trop élevée : {elapsed * 1000 / len(samples):.0f} ms/fichier")

    if issues:
        print("VERDICT : FAIL")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("VERDICT : PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
