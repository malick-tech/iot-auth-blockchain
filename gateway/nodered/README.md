# Gateway Node-RED

Gateway IoT Node-RED separee du backend Spring Boot.

Objectif :

- recevoir les messages des dispositifs IoT ;
- appeler le backend pour verifier les droits ;
- bloquer les dispositifs suspendus ou revoques ;
- router les donnees autorisees vers les services cibles.

## Lancement

Depuis la racine du projet :

```powershell
docker compose up -d nodered
```

Node-RED sera disponible sur `http://localhost:1880`.

Variables disponibles dans le conteneur :

- `BACKEND_BASE_URL=http://host.docker.internal:8080`
- `REDIS_HOST=redis`
- `REDIS_PORT=6379`
