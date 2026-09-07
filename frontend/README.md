# Frontend IoT Auth

Console d'administration React/Vite pour le système d'authentification IoT.

## Fonctionnalités

- tableau de bord des dispositifs ;
- état backend, PostgreSQL, Redis et Algorand ;
- pré-enregistrement des dispositifs ;
- consultation des DID et transactions Lora ;
- authentification admin ;
- journal d'audit avec filtres par admin, DID, événement et résultat ;
- affichage du contexte `metadata` pour comprendre les actions critiques.

## Démarrage

```powershell
npm install
npm run dev
```

URL locale :

```text
http://localhost:5173
```

Le backend doit être disponible sur `http://localhost:8083` avant d'utiliser la
console. Le flux MQTT ne doit pas être lancé directement depuis le frontend :
Node-RED reste la gateway unique entre les devices et l'API.

## Validation

```powershell
npm run lint
npm run build
```

Le frontend communique avec le backend Spring Boot sur `http://localhost:8083`. L'App ID Algorand affichee dans les liens DID/Lora est `1014` par defaut et peut etre surchargee par `VITE_ALGORAND_APP_ID`.
