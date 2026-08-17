# IoT Auth

Projet de mémoire pour l'authentification sécurisée des dispositifs IoT avec DID Algorand, Verifiable Credentials, JWT PoP, gateway opérationnelle, PostgreSQL, Redis et interface d'administration React.

## Architecture

- `backend/` : API Spring Boot, logique d'enrôlement, authentification, VC/JWT, révocation, audit, intégration PostgreSQL/Redis/Algorand.
- `frontend/` : console d'administration React/Vite pour piloter les dispositifs, consulter l'état système et lire les journaux d'audit.
- `gateway/` : gateway Node-RED et scripts de test pour les flux opérationnels IoT.
- `smart-contract/` : contrat Algorand utilisé pour publier et résoudre les DID sur LocalNet.
- `compose.yaml` : PostgreSQL, Redis, pgAdmin, Redis Commander et Node-RED.

## Services Locaux

```powershell
docker compose up -d
```

Ports utiles :

- Backend Spring Boot : `http://localhost:8083`
- Frontend Vite : `http://localhost:5173`
- PostgreSQL : `localhost:5432`
- pgAdmin : `http://localhost:5050`
- Redis : `localhost:6379`
- Redis Commander : `http://localhost:8081`
- Node-RED : `http://localhost:1880`
- Algorand LocalNet algod : `http://localhost:4001`
- Algorand indexer : `http://localhost:8980`
- Lora LocalNet : `https://lora.algokit.io/localnet`

## Démarrage

1. Démarrer les services Docker :

```powershell
docker compose up -d
```

2. Vérifier Algorand LocalNet :

```powershell
algokit localnet status
```

3. Démarrer le backend :

```powershell
cd backend
.\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev
```

4. Démarrer le frontend :

```powershell
cd frontend
npm install
npm run dev
```

## Compte Admin

En développement, si aucun compte admin n'existe, le backend crée un compte par défaut :

- Identifiant : `admin`
- Mot de passe : `changeme123`

Ce mot de passe doit être changé ou remplacé par une configuration dédiée avant toute démonstration sensible.

## Base de Données et Cache

Le profil `dev` utilise PostgreSQL, pas H2 :

- base : `iot_auth_db`
- utilisateur : `malick`
- mot de passe par défaut : `1234`

Redis sert de cache opérationnel rapide pour les informations nécessaires à la gateway : statut du dispositif, clé publique, permissions et compteurs d'échecs.

H2 reste réservé aux tests automatisés.

## Logs et Audit

Les journaux d'audit sont stockés durablement dans PostgreSQL. Ils servent à répondre à la question : qui a fait quoi, quand, sur quel dispositif, avec quel résultat et avec quel contexte.

Les logs incluent notamment :

- connexions admin réussies ou échouées ;
- création de comptes admin ;
- pré-enregistrement des dispositifs ;
- enrôlement, challenge-response, VC, JWT et VP ;
- authentification réussie ou échouée ;
- violations de permissions ;
- anomalies et suspensions ;
- réactivation et révocation ;
- tentatives d'accès d'un dispositif révoqué ;
- confirmations ou erreurs de publication Algorand.

Pour les actions critiques, le champ `metadata` conserve le contexte structuré : motif, statut cible, action Redis, remise à zéro des compteurs, et `algorandTxId` quand une transaction Algorand existe.

La révocation suit le modèle du document de conception :

- Redis : effet immédiat par suppression du cache ;
- Algorand : preuve permanente pour l'état irréversible ;
- PostgreSQL : trace exploitable avec motif, horodatage, administrateur et transaction.

La suspension est réversible : PostgreSQL reste la source de vérité et aucune transaction Algorand n'est publiée pour une simple suspension.

## API Utiles

Santé du backend :

```powershell
Invoke-RestMethod http://localhost:8083/actuator/health
```

Connexion admin :

```powershell
$login = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8083/api/admin/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"admin","password":"changeme123"}'
```

Lecture des logs filtrés par admin :

```powershell
$headers = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod `
  -Uri "http://localhost:8083/api/admin/logs?page=0&size=10&adminUsername=admin" `
  -Headers $headers
```

## Algorand et DID

Le projet vise un usage compatible avec l'approche DID Algorand :

- DID au format `did:algo:...` ;
- publication du DID Document sur Algorand LocalNet ;
- résolution via application/box storage ;
- révocation irréversible publiée on-chain ;
- consultation des transactions via Lora LocalNet.

Ne jamais mettre un vrai mnemonic Algorand dans le dépôt. Utiliser une variable d'environnement locale :

```powershell
$env:ALGORAND_DEPLOYER_MNEMONIC="..."
$env:ALGORAND_APP_ID="1010"
```

## Validation

Backend :

```powershell
cd backend
.\mvnw.cmd clean test
```

Frontend :

```powershell
cd frontend
npm run lint
npm run build
```

Dernière validation effectuée :

- backend : 19 tests OK ;
- frontend lint : OK ;
- frontend build : OK ;
- health backend : PostgreSQL `UP`, Redis `UP`.
