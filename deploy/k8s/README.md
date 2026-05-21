# Déploiement Kubernetes durci

Manifestes prêts pour la production, avec durcissement defense-in-depth.

## Fichiers

| Fichier | Contenu |
|---|---|
| `biocybe-api.yaml` | Deployment API REST + Service + PVC + NetworkPolicy |
| `../refresh/biocybe-intel-refresh-cronjob.yaml` | CronJob de refresh des feeds (Phase 3.g) |

## Durcissement appliqué

Chaque mesure bloque indépendamment (defense in depth) :

| Mesure | Effet |
|---|---|
| `runAsNonRoot: true` + uid/gid 10001 | jamais root, même si l'image était mal construite |
| `readOnlyRootFilesystem: true` | le FS racine est immuable ; writes uniquement sur volumes/tmpfs |
| `capabilities.drop: [ALL]` | aucune capability Linux (pas de raw socket, mount, etc.) |
| `allowPrivilegeEscalation: false` | pas d'escalade via setuid |
| `seccompProfile: RuntimeDefault` | filtre les syscalls dangereux |
| `resources.limits` (cgroups) | un agent de sécu ne doit **jamais OOM le nœud** |
| `automountServiceAccountToken: false` | pas de token K8s monté inutilement |
| `NetworkPolicy` | `/metrics` + API joignables seulement par ingress + Prometheus |
| Probes `/healthz` + `/readyz` | redémarrage auto + retrait du LB si pas prêt |

## Déploiement

```bash
# 1. Secret : token API (et clé de chiffrement quarantaine, optionnelle)
kubectl create secret generic biocybe-api \
  --from-literal=api-token="$(openssl rand -hex 32)" \
  --from-literal=quarantine-key="$(openssl rand -base64 32)"

# 2. Image avec l'extra web (Flask + waitress + Prometheus)
#    docker build --build-arg BIOCYBE_EXTRAS=web -t ghcr.io/servais1983/biocybe:latest .
#    docker push ghcr.io/servais1983/biocybe:latest

# 3. Déploiement
kubectl apply -f biocybe-api.yaml

# 4. Refresh des feeds (Phase 3.g)
kubectl create secret generic biocybe-intel \
  --from-literal=abusech-auth-key=VOTRE_CLE
kubectl apply -f ../refresh/biocybe-intel-refresh-cronjob.yaml

# Vérifs
kubectl get pods -l app.kubernetes.io/name=biocybe
kubectl get pvc
kubectl logs -l app.kubernetes.io/component=api --tail=50
```

## Probes — pourquoi deux endpoints

- **`/healthz`** (liveness) : « le process répond-il ? ». S'il échoue,
  K8s **redémarre** le pod. Pas d'auth (compatible kubelet).
- **`/readyz`** (readiness, Phase 3.c) : « peut-on router du trafic ? ».
  4 checks réels (quarantine_dir, rules_yara_compilable, metrics, auth).
  S'il échoue, K8s **retire le pod du Service** sans le tuer — le scan
  continue, on n'envoie juste plus de nouveau trafic. Le warning
  `intel_feeds_fresh` est exposé mais **non bloquant** (un feed stale ne
  sort pas le pod du LB).

## Notes

- `replicas: 2` : l'API est stateless (les états sont sur PVC), donc
  scalable horizontalement. La quarantaine en RWO est par-pod ; pour du
  multi-replica avec quarantaine partagée, passer le PVC quarantaine en
  RWX (selon le storage class).
- Le cache YARA `.yarc` est précompilé dans l'image (Phase 3.b) →
  démarrage en ~200 ms, d'où des probes agressives possibles.
- Adapter les `namespaceSelector` de la NetworkPolicy à votre cluster
  (noms des namespaces ingress / monitoring).
