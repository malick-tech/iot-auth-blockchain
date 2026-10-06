# Benchmarks du chapitre 5

Ce dossier automatise la mesure du trafic operationnel apres enrôlement d'un device.

## Prerequis

Les services suivants doivent etre demarres :

- backend Spring Boot sur `localhost:8083` ;
- Mosquitto et Node-RED ;
- Redis ;
- PostgreSQL ;
- Algorand LocalNet.

Le device doit deja etre enrôle et son fichier d'etat doit contenir un JWT valide. Par defaut, le benchmark utilise `devices/state/IOT-TEMP-001.json`.

## Lancer

Depuis PowerShell :

```powershell
.\experiments\run_benchmark.ps1
```

Ou directement :

```powershell
python experiments/benchmark.py
```

## Scenarios

- `mqtt_hit` : device vers Node-RED, validation locale avec cache Redis ;
- `mqtt_miss` : suppression de la clé Redis avant chaque requête, puis validation backend ;
- `backend_direct` : appel HTTP direct au backend, sans MQTT/Node-RED.

Les scénarios sont configurés dans `benchmark_config.json`. Pour une campagne longue, augmenter `requests_per_scenario` et `repetitions`.

Le rate limiting opérationnel est activé par défaut à 20 requêtes par minute.
Pour une campagne de latence qui dépasse ce quota, lancer temporairement le
backend avec :

```powershell
.\mvnw.cmd spring-boot:run -Dspring-boot.run.jvmArguments="-Diot.auth.rate-limit.enabled=false"
```

Réactiver ensuite le backend avec sa configuration normale pour les essais de
sécurité et d'exploitation.

## Resultats

Le runner produit :

- `experiments/results/benchmark_raw.csv` : une ligne par requête ;
- `experiments/results/benchmark_summary.csv` : nombre de requêtes, taux de succès, moyenne, p50, p95, p99, minimum et maximum.

Ces fichiers peuvent être importes dans Excel ou LibreOffice pour produire les graphiques du chapitre 5.

Le benchmark mesure le trafic operationnel. L'enrôlement et la publication du DID sur Algorand doivent etre mesures dans une campagne separee, car ils ne sont pas executes a chaque message IoT.

---

## Protocole de mesure v2

Corrige les défauts de la v1 (attente par `time.sleep(0.01)` : granularité de 10 ms ; `SUBSCRIBE` chronométré ;
30 mesures par scénario ; pas d'intervalle de confiance ni de test).

| Élément | v1 | v2 |
|---|---|---|
| Attente de la réponse | sondage `sleep(0.01)` | `threading.Event`, horodatage dans le callback d'arrivée |
| Abonnement MQTT | à chaque requête, dans la zone chronométrée | une fois, SUBACK attendu |
| Échauffement | aucun | `warmup_requests` requêtes exclues par scénario |
| Ordre | scénarios en séquence | blocs entrelacés, ordre randomisé (`seed`) |
| Échantillon | 30 × 3 | `requests_per_block` × `repetitions` = 1 000 par scénario (défaut) |
| Étalon de transport | aucun | `mqtt_echo_floor` (client → broker → client) |
| Statistiques | moyenne, p50/p95/p99 | médiane + IC 95 % bootstrap, p95, Mann-Whitney U, taille d'effet, réduction relative de médiane + IC |
| Échecs | mêlés aux latences | exclus des latences, listés dans `benchmark_failures.csv` |

**Prérequis** : `IOT_AUTH_RATE_LIMIT_ENABLED=false` pour le backend pendant la mesure, sinon les requêtes sont rejetées en 429.
La configuration mesurée diffère alors de la production : à écrire dans le chapitre 5.

**Précaution `TCP_NODELAY`.** Sur un banc à délais connus, un cache HIT injecté à 2 ms était mesuré à
~44 ms avec Mosquitto par défaut (Nagle + ACK retardé de TCP), et à ~2,6 ms avec `set_tcp_nodelay true`.
`gateway/mosquitto/mosquitto.conf` l'active désormais. Si vos mesures HIT affichent un plancher proche de 40 ms
(ou ~200 ms sous Windows), vérifiez ce point avant toute interprétation.

Sorties : `benchmark_raw.csv`, `benchmark_summary.csv`, `benchmark_comparisons.csv`, `benchmark_failures.csv`,
`benchmark_meta.json` (machine, version, graine, limites).
