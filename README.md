# IoT Auth

Système d'authentification sécurisée pour dispositifs IoT basé sur DID Algorand, Verifiable Credentials et JWT Proof-of-Possession. Développé dans le cadre d'un mémoire de M2.

## Architecture

| Composant | Rôle |
|---|---|
| `backend/` | API Spring Boot — enrôlement, authentification VC/JWT, révocation, audit, PostgreSQL/Redis/Algorand |
| `frontend/` | Console d'administration React/Vite — gestion des dispositifs, journaux d'audit |
| `devices/` | Simulateurs IoT Python — enrôlement MQTT, publication opérationnelle continue |
| `gateway/` | Gateway Node-RED + Mosquitto — pont MQTT ↔ HTTP, cache local JWT PoP |
| `smart-contract/` | Contrat PyTEAL Algorand — registre DID immuable on-chain |
| `experiments/` | Benchmark de performance et suite de tests E2E sécurité |

## Prérequis

- Java 25, Maven (ou `mvnw`)
- Docker Desktop
- AlgoKit + Algorand LocalNet (`algokit localnet start`)
- Python ≥ 3.11 (`pip install -r devices/requirements.txt`)
- Node.js ≥ 20 (pour le frontend)

## Variables d'environnement

Copier `.env.example` en `.env` (non versionné) et renseigner chaque valeur :

```powershell
# Secrets à générer une seule fois
$env:DB_USERNAME="malick"
$env:DB_PASSWORD="$(openssl rand -hex 16)"
$env:PGADMIN_DEFAULT_EMAIL="admin@example.com"
$env:PGADMIN_DEFAULT_PASSWORD="$(openssl rand -hex 16)"
$env:REDIS_PASSWORD="$(openssl rand -hex 32)"
$env:REDIS_GATEWAY_PASSWORD="$(openssl rand -hex 32)"
$env:IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64="$(openssl rand -base64 32)"
$env:IOT_AUTH_ADMIN_JWT_SECRET="$(openssl rand -base64 64)"
$env:IOT_AUTH_GATEWAY_SHARED_SECRET="$(openssl rand -hex 32)"
$env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD="<12 caractères minimum>"
$env:ALGORAND_APP_ID="1014"
$env:ALGORAND_ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$env:ALGORAND_DEPLOYER_MNEMONIC="<mnemonic 25 mots du compte déployeur>"
```

Aucun secret n'est fourni par défaut dans le dépôt. Voir `.env.example` pour la liste complète.

## Démarrage

**1. Infrastrucure Docker (PostgreSQL, Redis, pgAdmin, Redis Commander) :**

```powershell
cd backend
docker compose up -d
```

**2. Gateway MQTT + Node-RED :**

```powershell
cd gateway
docker compose up -d
```

**3. Algorand LocalNet :**

```powershell
algokit localnet start
```

**4. Backend Spring Boot :**

```powershell
cd backend
.\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev
```

**5. Frontend :**

```powershell
cd frontend
npm install
npm run dev
```

## Ports utiles

| Service | Adresse |
|---|---|
| Backend Spring Boot | `http://localhost:8083` |
| Frontend Vite | `http://localhost:5173` |
| pgAdmin | `http://localhost:5050` |
| Redis Commander | `http://localhost:8081` (loopback uniquement) |
| Redis | `localhost:6379` (loopback uniquement, mot de passe `REDIS_PASSWORD`) |
| PostgreSQL | `localhost:5432` |
| Node-RED | `http://localhost:1880` |
| Algorand algod | `http://localhost:4001` |
| Algorand indexer | `http://localhost:8980` |
| Lora LocalNet | `https://lora.algokit.io/localnet` |

## Compte admin initial

Au premier démarrage, le backend crée le compte `admin` **uniquement** si `IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD` est défini (12 caractères minimum). Aucun mot de passe par défaut n'existe dans le dépôt.

```powershell
$login = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8083/api/v1/admin/auth/login `
  -ContentType "application/json" `
  -Body (@{ username = "admin"; password = $env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
```

## Simulation de dispositifs

Le flux respecte la séparation des rôles — le simulateur ne crée jamais son enregistrement directement :

1. L'admin pré-enregistre le dispositif dans la console avec un numéro de série unique.
2. Le simulateur est lancé avec ce numéro de série.
3. Le simulateur parle **uniquement** à la gateway via MQTT.
4. Node-RED relaie le first-contact, le challenge-response et le renouvellement JWT vers le backend.
5. Le dispositif obtient son VC/JWT PoP, puis publie des métriques en continu.

```powershell
python devices/device_simulator.py --serial IOT-TEMP-001 --app-id 1014
```

## Sécurité

Le protocole d'authentification opérationnelle signe :

```
m = did ∥ jti ∥ timestamp ∥ requestId ∥ permission ∥ H(metricsJson)
```

- `requestId` (UUID par requête) : anti-rejeu, vérifié par SET NX Redis côté backend et gateway.
- `H(metricsJson)` : intégrité des métriques — toute altération après signature est détectée.
- Liaisons `VC.subject == DID` et `VC.issuer == adminDid` vérifiées avant la signature Ed25519.

Redis dispose d'un compte `gateway` à moindre privilège (lecture `device:*`, écriture `op_proof_used:*` uniquement). Les ports Redis et Redis Commander sont liés à `127.0.0.1`.

## API utiles

**Santé :**

```powershell
Invoke-RestMethod http://localhost:8083/actuator/health
```

**Logs d'audit :**

```powershell
$headers = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod `
  -Uri "http://localhost:8083/api/v1/admin/logs?page=0&size=10" `
  -Headers $headers
```

**Métriques IoT d'un dispositif :**

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:8083/api/v1/admin/devices/{did}/metrics?size=50" `
  -Headers $headers
```

## Algorand et DID

Le DID est au format `did:algo:custom:app:{appId}:{pubKeyHex}`. Le contrat LocalNet utilisé est l'application `1014`. Ne jamais committer de vrai mnemonic Algorand — fournir `ALGORAND_DEPLOYER_MNEMONIC` via variable d'environnement.

## Base de données et cache

- PostgreSQL : source de vérité principale (entités, VC, logs d'audit, métriques IoT).
- Redis : cache opérationnel (statut dispositif, JTI blacklist, nonces, anti-rejeu). Protégé par mot de passe, compte `gateway` à moindre privilège.
- La **révocation** écrit immédiatement dans Redis (blocage opérationnel < 1 s) et ancre on-chain (Algorand) en meilleur effort (recovery automatique si échec).
- La **suspension** n'écrit que dans PostgreSQL (réversible, pas de transaction Algorand).

## Tests et validation

Tests unitaires (94 tests, 0 échec) :

```powershell
cd backend
.\mvnw.cmd test
```

Benchmark de performance (scénarios `mqtt_hit`, `mqtt_miss`, `backend_direct`) :

```powershell
# Désactiver temporairement le rate-limit dans application.properties
# iot.auth.rate-limit.enabled=false
python experiments/benchmark.py --config experiments/benchmark_config.json
```

Suite E2E sécurité (cycle de vie complet + matrice de 9 attaques) :

```powershell
# Renseigner experiments/e2e_security_config.json avec les identifiants admin
python experiments/e2e_security_suite.py --phase all
```

Les résultats sont écrits dans `experiments/results/` (ignoré par git).

Frontend :

```powershell
cd frontend
npm run lint && npm run build
```
