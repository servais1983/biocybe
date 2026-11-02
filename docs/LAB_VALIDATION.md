# Valider BioCybe en labo isolé

`biocybe coverage` mesure la **logique** de détection : il rejoue de la
télémétrie synthétique dans les vraies règles et le vrai moteur. Ce guide
mesure **le système complet**, capteurs compris, face à de vraies techniques
exécutées dans un labo que **vous contrôlez**. Le résultat est une scorecard
chiffrée : taux de détection, latence et faux positifs.

> **Cadre** : à faire uniquement sur des machines dédiées, isolées de la
> production, avec l'autorisation écrite de leur propriétaire. N'utilisez que
> des frameworks de test publiés et maintenus (Atomic Red Team, MITRE
> Caldera). Lisez **chaque** test avant de l'exécuter, puis lancez son
> nettoyage. Un test exécuté sur une machine de production n'est pas une
> validation, c'est un incident.

---

## 1. Topologie du labo

| Machine | Rôle | Configuration BioCybe |
|---|---|---|
| `lab-lin01` (Linux, VM) | cible Linux | root, `--procmon` (source `netlink`), `--dnsmon` (source `packet`), `--watch`, `--netmon` |
| `lab-win01` (Windows, VM) | cible Windows | **Sysmon** installé (config communautaire, par ex. SwiftOnSecurity / Olaf Hartong), `--procmon` (source `sysmon`), `--dnsmon` (source `sysmon`), `--watch` |
| `lab-sensor` (optionnel) | capteur réseau | Zeek. Ses `dns.log` sont analysés avec `biocybe dns analyze` |

Règles d'isolation :

- réseau dédié (VLAN ou réseau host-only), **sans route vers la production** ;
- sortie Internet coupée ou limitée à une liste stricte (dépôts de paquets,
  feeds IOC) ;
- **snapshot** de chaque VM avant la session, et retour au snapshot après ;
- horloges synchronisées (NTP) : la scorecard compare des horodatages.

## 2. Préparer BioCybe

```bash
pip install -e ".[soc]"
biocybe intel update --source all          # feeds IOC à jour
biocybe coverage                           # point de référence : la logique passe-t-elle ?
```

Configuration de labo (`config/biocybe.yaml`) :

```yaml
inflammation: { enabled: true }
procmon:      { enabled: true, source: auto }
dnsmon:       { enabled: true, source: auto }
netmon:       { enabled: true }
audit:        { enabled: true }   # chaque détection et chaque qualification tracées
nk:           { enabled: false }  # détection seule pendant la mesure
```

Lancement :

```bash
sudo biocybe --watch /home --watch /tmp --procmon --dnsmon --netmon
```

Au démarrage, vérifiez les lignes `source netlink`, `source sysmon` et
`source packet`. Un **repli sur le polling** est signalé dans les logs. Dans
ce cas la mesure de procmon ne vaut que pour ce mode : les processus
éphémères peuvent échapper au polling.

## 3. Mesurer d'abord les faux positifs (période de référence)

Avant toute technique offensive, laissez tourner BioCybe **24 à 48 h** sur une
activité normale : navigation, mises à jour, outils d'administration habituels.

```bash
biocybe incidents list --all
```

Chaque incident apparu pendant cette période est un **faux positif mesuré**.
Qualifiez-le avec `biocybe incidents mark <ID> --as false_positive` : le moteur
apprend une tolérance ciblée sur cette signature. Notez le nombre d'incidents
par jour, c'est votre taux de faux positifs de référence.

## 4. Plan de test

Une ligne par exécution, dans un CSV (modèle : `docs/lab_plan_template.csv`) :

```csv
technique,executed_at,test_name,host
T1490,2026-11-03T10:15:00,Atomic T1490-1,lab-win01
```

Techniques recommandées, alignées sur le corpus `biocybe coverage` :

| Technique | Capteur BioCybe attendu | Résultat `coverage` |
|---|---|---|
| T1490 Inhibit System Recovery | procmon | systémique |
| T1003.001 LSASS Memory | procmon | systémique |
| T1486 Data Encrypted for Impact | watcher + régénération (baseline préalable : `biocybe regen baseline`) | systémique |
| T1059.001 PowerShell | procmon | local |
| T1204.002 Malicious File (macro) | procmon | local |
| T1505.003 Web Shell | procmon (serveur web dans le labo) | local |
| T1053.005 Scheduled Task | procmon | local |
| T1070.001 Clear Windows Event Logs | procmon | local |
| T1021.002 SMB/Admin Shares | procmon (machine cible) | local |
| T1105 Ingress Tool Transfer | procmon | local |
| T1071.004 DNS | dnsmon | local |
| T1568.002 DGA | dnsmon | local |
| T1552.001 Credentials In Files | procmon | sous le seuil seul |
| T1547.001 Registry Run Keys | procmon | sous le seuil seul |
| T1055 Process Injection | aucun (angle mort connu) | non observable |

Avec Atomic Red Team (PowerShell, module `Invoke-AtomicRedTeam`) :

```powershell
Invoke-AtomicTest T1490 -ShowDetailsBrief    # lister les tests disponibles
Invoke-AtomicTest T1490 -TestNumbers 1 -ShowDetails   # LIRE le test
Invoke-AtomicTest T1490 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1490 -TestNumbers 1        # exécuter -> noter l'heure dans le plan
Invoke-AtomicTest T1490 -TestNumbers 1 -Cleanup
```

Laissez **au moins 2 minutes** entre deux techniques. Sans cet écart, deux
exécutions proches peuvent être fusionnées en un seul incident et brouiller la
lecture. Incluez **aussi** T1055 : une technique ratée et documentée vaut mieux
qu'une absence de mesure.

## 5. Scorecard

```bash
biocybe lab score --plan plan.csv                 # tableau lisible
biocybe lab score --plan plan.csv --json > score.json
```

Pour chaque exécution, la scorecard indique :

- `SYST` / `LOC ` / `RATÉ` ;
- la **latence** (premier signal moins heure d'exécution) ;
- les incidents correspondants.

Une technique compte comme détectée si un incident portant cette technique
MITRE (ou une de ses sous-techniques) apparaît dans la fenêtre
`[exécution - 60 s, exécution + 600 s]` (réglable avec `--window` et `--skew`).

Elle liste aussi les **incidents non expliqués**, ceux qu'aucune exécution du
plan ne justifie. Ce sont des faux positifs probables, ou des effets de bord
des outils de test ; qualifiez-les. Code de sortie : 1 si au moins une
technique est ratée.

## 6. Interpréter

| Écart observé | Cause probable | Action |
|---|---|---|
| `coverage` = détecté, labo = RATÉ | capteur aveugle : polling, pas root, Sysmon mal configuré, DoH | vérifier la source active au démarrage, la config Sysmon (EID 1 et 22) |
| labo = LOC, attendu SYST | corroboration absente (une seule cellule a vu l'attaque) | normal pour une technique isolée ; une chaîne complète doit monter en systémique |
| latence élevée | polling, `tick` du daemon, horloges désynchronisées | source temps réel, NTP |
| incidents non expliqués nombreux | règles trop sensibles dans **votre** environnement | `biocybe incidents mark --as false_positive`, `procmon.disabled_rules`, allowlist DNS |
| technique ratée partout | vraie lacune | ajouter un cas au corpus `coverage` (attendu `not_detected`), puis une règle ou un capteur |

Toute lacune trouvée en labo doit **entrer dans le corpus** de
`src/biocybe/coverage.py`. Elle devient alors un test de non-régression
permanent en CI.

## 7. Rapport

Un rapport de validation honnête contient :

1. la date, la version de BioCybe (`git rev-parse HEAD`), la topologie, les
   sources actives ;
2. le taux de faux positifs de la période de référence (incidents par jour) ;
3. la scorecard : taux de détection, part systémique, latence médiane et
   maximale ;
4. les techniques ratées, avec leur cause (tableau §6) ;
5. les angles morts connus non testés (DoH, injection mémoire, etc.).
