# IoT Auth

Projet de memoire pour l'authentification IoT avec backend Spring Boot, gateway Node-RED et future interface admin.

## Structure

- `backend/` : API Spring Boot, domaine metier, services, controllers et tests.
- `frontend/admin-ui/` : future interface d'administration.
- `gateway/nodered/` : future gateway IoT basee sur Node-RED.
- `docs/` : conception, scripts utiles et collections Postman.
- `compose.yaml` : services partages de developpement, comme PostgreSQL, Redis, pgAdmin, Redis Commander et Node-RED.

## Backend

Depuis la racine :

```powershell
cd backend
.\mvnw.cmd test
.\mvnw.cmd spring-boot:run
```

## Services Docker

Depuis la racine :

```powershell
docker compose up -d
```

- pgAdmin : `http://localhost:5050`
- Redis Commander : `http://localhost:8081`
- Node-RED : `http://localhost:1880`
