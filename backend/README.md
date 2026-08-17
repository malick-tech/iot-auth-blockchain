# Backend Spring Boot

Ce dossier contient le backend principal du système :

- pré-enregistrement des dispositifs ;
- enrôlement cryptographique ;
- émission VC/JWT PoP ;
- suspension, réactivation et révocation ;
- audit métier dans PostgreSQL ;
- cache opérationnel Redis ;
- intégration Algorand LocalNet pour les DID et la révocation.

## Commandes utiles

```powershell
.\mvnw.cmd clean test
.\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev
```

## Profil dev

Le profil `dev` écoute sur `http://localhost:8083` et utilise :

- PostgreSQL : `jdbc:postgresql://localhost:5432/iot_auth_db`
- Redis : `localhost:6379`
- Algorand algod : `http://localhost:4001`
- Algorand indexer : `http://localhost:8980`

H2 est réservé aux tests.

## Audit

Les logs sont persistés dans PostgreSQL avec l'acteur, le DID, le type d'événement, le résultat, l'administrateur responsable et un champ `metadata` pour le contexte structuré.
