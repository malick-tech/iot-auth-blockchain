# Backend Spring Boot

API principale du système IoT Auth.

## Responsabilités

- Pré-enregistrement des dispositifs (admin)
- Enrôlement cryptographique (sigma0/sigma1, Ed25519)
- Émission VC (Verifiable Credentials) et JWT PoP
- Vérification opérationnelle : JWT PoP + preuve de possession + anti-rejeu (SET NX Redis)
- Suspension (réversible), réactivation et révocation (irréversible + ancrage Algorand)
- Détection d'anomalies et suspension automatique
- Audit complet dans PostgreSQL (30+ types d'événements)
- Cache opérationnel Redis (TTL 300 s, compte `gateway` à moindre privilège)
- Intégration Algorand LocalNet pour le registre DID et la révocation on-chain

## Commandes utiles

Toutes les commandes se lancent depuis ce dossier.

```powershell
# Infrastructure (PostgreSQL, Redis, pgAdmin, Redis Commander)
docker compose up -d

# Tests unitaires (94 tests, 0 échec)
.\mvnw.cmd test

# Démarrage backend (profil dev)
.\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev
```

Gateway MQTT + Node-RED (depuis `../gateway`) :

```powershell
cd ../gateway
docker compose up -d
```

## Configuration locale

Le backend écoute sur `http://localhost:8083` avec :

| Ressource | Valeur par défaut |
|---|---|
| PostgreSQL | `jdbc:postgresql://localhost:5432/iot_auth_db` |
| Redis | `localhost:6379` (mot de passe `REDIS_PASSWORD`) |
| Algorand algod | `http://localhost:4001` |
| Algorand indexer | `http://localhost:8980` |
| App ID LocalNet | `1032` |

H2 est réservé aux tests automatisés.

## Variables d'environnement obligatoires

Aucun secret n'est fourni par défaut. Voir `.env.example` à la racine.

| Variable | Description |
|---|---|
| `DB_PASSWORD` | Mot de passe PostgreSQL |
| `REDIS_PASSWORD` | Mot de passe Redis (compte `default`) |
| `REDIS_GATEWAY_PASSWORD` | Mot de passe Redis (compte `gateway`, moindre privilège) |
| `IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64` | Clé Ed25519 32 octets en Base64 — signe tous les VC et JWT PoP |
| `IOT_AUTH_GATEWAY_SHARED_SECRET` | Secret partagé gateway ↔ backend (`X-Gateway-Secret`) |
| `IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD` | Mot de passe du compte admin initial (12 car. min) |
| `IOT_AUTH_ADMIN_JWT_SECRET` | Secret JWT admin ≥ 64 octets en Base64 (éphémère si absent en dev) |
| `ALGORAND_DEPLOYER_MNEMONIC` | Mnemonic 25 mots du compte déployeur de l'app `1032` |

Exemple de génération (PowerShell) :

```powershell
$env:REDIS_PASSWORD="$(openssl rand -hex 32)"
$env:REDIS_GATEWAY_PASSWORD="$(openssl rand -hex 32)"
$env:IOT_AUTH_ADMIN_PRIVATE_KEY_BASE64="$(openssl rand -base64 32)"
$env:IOT_AUTH_ADMIN_JWT_SECRET="$(openssl rand -base64 64)"
$env:IOT_AUTH_GATEWAY_SHARED_SECRET="$(openssl rand -hex 32)"
$env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD="<12 caractères minimum>"
$env:ALGORAND_DEPLOYER_MNEMONIC="<mnemonic-du-compte-déployeur>"
$env:ALGORAND_APP_ID="1032"
.\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev
```

## Rate limiting et benchmark

Le profil `dev` désactive le moniteur d'inactivité pour éviter la suspension des
dispositifs pendant les essais. Le rate limiting reste actif (20 req/min par IP).
Pour une campagne de benchmark, le désactiver temporairement dans `application.properties` :

```properties
iot.auth.rate-limit.enabled=false
```

## Sécurité Redis

Redis est protégé par mot de passe (`requirepass`) et expose un compte `gateway`
à moindre privilège : lecture sur `device:*`, écriture sur `op_proof_used:*` uniquement.
Les ports 6379 et 8081 (Redis Commander) sont liés à `127.0.0.1`.

## Audit

Les logs sont persistés dans PostgreSQL avec : acteur, DID, type d'événement,
résultat, administrateur responsable, IP source et champ `metadata` pour le
contexte structuré (motif, statut cible, `algorandTxId`, etc.).

La révocation suit le modèle fail-closed :

1. **Redis** : invalidation immédiate (blacklist JTI, suppression cache) — blocage opérationnel < 1 s.
2. **PostgreSQL** : statut `REVOKED` persisté avant l'appel Algorand.
3. **Algorand** : ancrage on-chain en meilleur effort — repris automatiquement par `AlgorandPublishingRecoveryService` si échec.

La suspension ne publie rien on-chain (réversible, PostgreSQL source de vérité).
