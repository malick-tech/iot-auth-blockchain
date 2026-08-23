# IoT Auth

Projet de mémoire pour l'authentification sécurisée des dispositifs IoT avec DID Algorand, Verifiable Credentials, JWT PoP, gateway opérationnelle, PostgreSQL, Redis et interface d'administration React.

## Architecture

- `backend/` : API Spring Boot, logique d'enrôlement, authentification, VC/JWT, révocation, audit, intégration PostgreSQL/Redis/Algorand.
- `frontend/` : console d'administration React/Vite pour piloter les dispositifs, consulter l'état système et lire les journaux d'audit.
- `devices/` : simulateurs de dispositifs IoT persistants qui s'enrolent puis communiquent en continu.
- `gateway/` : gateway Node-RED et scripts de test pour les flux opérationnels IoT.
- `smart-contract/` : contrat Algorand utilisé pour publier et résoudre les DID sur LocalNet.
- `backend/compose.yaml` : PostgreSQL, Redis, pgAdmin, Redis Commander et Node-RED.

## Services Locaux

```powershell
cd backend
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
cd backend
docker compose up -d
```

2. Vérifier Algorand LocalNet :

```powershell
algokit localnet status
```

3. Démarrer le backend :

```powershell
cd backend
.\mvnw.cmd spring-boot:run
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

## Supervision d'inactivite

Le backend surveille automatiquement les dispositifs actifs. Si un dispositif `ACTIVE` ne communique plus pendant le delai imparti, le systeme le passe en `SUSPENDED`, supprime son cache Redis et ecrit un log avec l'acteur `SYSTEM`.

Parametres principaux :

```properties
iot.auth.inactivity-monitor.enabled=true
iot.auth.inactivity-monitor.timeout-seconds=90
iot.auth.inactivity-monitor.scan-interval-ms=30000
```

Chaque communication operationnelle autorisee met a jour `lastSeenAt`. Si le simulateur est arrete ou si la gateway ne recoit plus de messages, le device sera suspendu automatiquement apres le timeout.

## Simulation de dispositifs

Le dispositif n'est pas cree directement par le script. Le flux respecte la separation des roles :

1. L'administrateur pre-enregistre le dispositif dans la console avec un numero de serie unique.
2. Le simulateur est lance avec ce meme numero de serie, qui lui est propre.
3. Le simulateur parle uniquement a la gateway via MQTT.
4. La gateway relaie le first-contact, le challenge-response et le renouvellement JWT vers le backend.
5. Le simulateur obtient son VC/JWT PoP, puis publie en continu vers la gateway.

Installation des dependances Python :

```powershell
pip install -r devices/requirements.txt
```

Exemple de lancement apres pre-enregistrement du serial `IOT-TEMP-001` :

```powershell
python devices/device_simulator.py --serial IOT-TEMP-001 --type capteur-temperature --location Ziguinchor-Lab
```

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
