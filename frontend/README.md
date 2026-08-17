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

## Validation

```powershell
npm run lint
npm run build
```

Le frontend communique avec le backend Spring Boot sur `http://localhost:8083`.
