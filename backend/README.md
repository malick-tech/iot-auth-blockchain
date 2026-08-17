# Backend Spring Boot

Ce dossier contient le backend principal du systeme :

- pre-enregistrement des dispositifs ;
- enrolement cryptographique ;
- emission VC/JWT PoP ;
- suspension, reactivation et revocation ;
- audit metier dans PostgreSQL ;
- cache operationnel Redis ;
- integration Algorand LocalNet pour les DID et la revocation.

## Commandes utiles

Toutes les commandes backend se lancent depuis ce dossier.

```powershell
docker compose up -d
.\mvnw.cmd clean test
.\mvnw.cmd spring-boot:run
```

Le fichier `compose.yaml` declare `name: iot-auth` afin de reutiliser les conteneurs existants du systeme (`iot-auth-postgres-1`, `iot-auth-redis-1`, etc.) meme si Docker Compose est lance depuis le dossier `backend/`.

## Execution locale

La configuration par defaut ecoute sur `http://localhost:8083` et utilise :

- PostgreSQL : `jdbc:postgresql://localhost:5432/iot_auth_db`
- Redis : `localhost:6379`
- Algorand algod : `http://localhost:4001`
- Algorand indexer : `http://localhost:8980`

H2 est reserve aux tests.

## Audit

Les logs sont persistes dans PostgreSQL avec l'acteur, le DID, le type d'evenement, le resultat, l'administrateur responsable et un champ `metadata` pour le contexte structure.
