# Backend Spring Boot

Ce dossier contient le backend principal du systeme :

- pre-enregistrement des dispositifs ;
- enrolement cryptographique ;
- emission VC/JWT PoP ;
- suspension, reactivation et revocation ;
- audit metier dans PostgreSQL ;
- cache operationnel Redis ;
- integration Algorand LocalNet pour les DID et la revocation.
- communication MQTT via Node-RED, gateway unique entre les devices et le backend.

## Commandes utiles

Toutes les commandes backend se lancent depuis ce dossier.

```powershell
docker compose up -d
.\mvnw.cmd clean test
.\mvnw.cmd spring-boot:run
```

Node-RED et Mosquitto sont demarres depuis `../gateway` :

```powershell
cd ../gateway
docker compose up -d
```

Le fichier `compose.yaml` declare `name: iot-auth` afin de reutiliser les conteneurs existants du systeme (`iot-auth-postgres-1`, `iot-auth-redis-1`, etc.) meme si Docker Compose est lance depuis le dossier `backend/`.

## Execution locale

La configuration par defaut ecoute sur `http://localhost:8083` et utilise :

- PostgreSQL : `jdbc:postgresql://localhost:5432/iot_auth_db`
- Redis : `localhost:6379`
- Algorand algod : `http://localhost:4001`
- Algorand indexer : `http://localhost:8980`
- App ID LocalNet : `1014`

H2 est reserve aux tests.

Le profil `dev` désactive le moniteur d'inactivité pour éviter la suspension des
devices pendant les essais. Le rate limiting opérationnel reste actif avec un
quota de 20 requêtes par minute et par adresse source. Pour une campagne de
benchmark locale uniquement, le désactiver au lancement :

```powershell
.\mvnw.cmd spring-boot:run -Dspring-boot.run.jvmArguments="-Diot.auth.rate-limit.enabled=false"
```

Le secret `iot.auth.admin.jwt-secret` doit être Base64 et représenter au moins
64 octets décodés. Générer une clé dédiée hors du dépôt :

```powershell
openssl rand -base64 64
```

Pour publier un DID sur Algorand, definir localement `ALGORAND_DEPLOYER_MNEMONIC` avec le mnemonic du compte createur de l'application `1014`. Ne jamais l'ajouter au depot.

## Audit

Les logs sont persistes dans PostgreSQL avec l'acteur, le DID, le type d'evenement, le resultat, l'administrateur responsable et un champ `metadata` pour le contexte structure.

Le test d'integration principal couvre le backend, PostgreSQL, Redis, Node-RED, MQTT et Algorand LocalNet.

Validation actuelle : `./mvnw.cmd test` passe avec 89 tests, 0 échec et 0 erreur.
