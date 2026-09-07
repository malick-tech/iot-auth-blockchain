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
