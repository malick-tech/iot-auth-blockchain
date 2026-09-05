# Rapport LocalNet, Lora et integration Algorand

Date : 15 aout 2026

## Etat final

Le reseau Algorand LocalNet fonctionne et Lora est accessible.

- Interface Lora fonctionnelle : `https://lora.algokit.io/localnet`
- Alternative officielle AlgoKit : `https://explore.algokit.io/localnet`
- Smart contract deploye sur LocalNet
- Backend configure pour utiliser le nouvel App ID
- Tests backend valides

## Informations LocalNet

Etat observe avec `algokit localnet status` :

- `algod` : running
- Port `algod` : `4001`
- Version `algod` : `5.0.0`
- `indexer` : running
- Port `indexer` : `8980`
- Version `indexer` : `3.10.0`
- `kmd` : expose sur le port `4002`
- Genesis ID : `dockernet-v1`

Endpoints utilises :

```text
Algod   : http://localhost:4001
Indexer : http://localhost:8980
KMD     : http://localhost:4002
Token   : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## Smart contract deploye

Apres reset/update de LocalNet, l'ancien App ID `1019` n'etait plus valide.
Le contrat actif utilise par le projet est la version compatible ARC-4 alignee avec la specification `did:algo` app namespace :

```text
App ID      : 1014
App Address : VSFZF5BRBVJY7P5QQN73JQ27DX3RP6PWSHW4I3SFFFZYFNTGCM3ZC2DHLE
Deploy Tx   : FU7SDR5Z4W2GP5TGOEAYXEZ56PSSR2ZGHJE2JIVAPEQB2HAMUUYQ
```

Dans Lora, il faut donc rechercher :

```text
1014
```

## Alignement did:algo

Le format DID utilise par le projet a ete aligne sur la specification Algorand `did:algo` :

```text
did:algo:custom:app:<appId>:<hex-ed25519-key>
```

En LocalNet, le reseau est represente par `custom`.

Exemple :

```text
did:algo:custom:app:1014:983428fc4903fde334d77ae9bf4bc4a7d11bd478ff6d572979899529f3dcb678
```

La structure on-chain utilise maintenant :

```text
Metadata box key   = cle publique Ed25519 brute du sujet, 32 octets
Metadata box value = ARC4 tuple (uint64,uint64,uint8,uint64), 25 octets
Data box key       = uint64 derive de la cle publique
Data box value     = DID Document JSON UTF-8
```

Le statut de la metadata box suit la specification :

```text
0 = uploading / non resolvable
1 = ready / resolvable
2 = deleted / non resolvable
```

## Corrections appliquees

### Backend

Le fichier suivant a ete mis a jour :

```text
backend/src/main/resources/application-dev.properties
```

La configuration dev pointe maintenant vers le smart contract actif :

```properties
iot.auth.algorand.app-id=${ALGORAND_APP_ID:1014}
```

Un fichier d'interface ARC-4 a ete ajoute pour Lora App Lab :

```text
smart-contract/iot_auth_registry.arc4.json
```

Il expose les methodes :

```text
publish_did(byte[32],uint64,string)void
update_status(byte[32],uint8)void
```

Le fichier suivant a aussi ete corrige :

```text
backend/src/main/java/com/iotauth/iot_auth/config/AlgorandConfig.java
```

Correction principale :

- si le mnemonic Algorand est absent, le backend ne plante plus au demarrage ;
- un compte Algorand ephemere est genere pour permettre le demarrage local ;
- pour publier reellement sur Algorand, il faut fournir `ALGORAND_DEPLOYER_MNEMONIC`.

## Verification

Tests backend :

```text
Tests run: 19
Failures: 0
Errors: 0
BUILD SUCCESS
```

Verification de l'application dans indexer :

```text
GET http://localhost:8980/v2/applications/1014
Resultat : application id = 1014
```

Verification backend :

```text
GET http://localhost:8083/actuator/health
Resultat : UP
```

## Probleme Lora rencontre

Erreur observee :

```text
Subscription failed to retrieve data
Error: Block failed to load
```

Diagnostic :

- LocalNet repondait bien sur certains services ;
- `algod` et/ou l'abonnement cote navigateur etaient bloques ;
- apres `algokit localnet reset --update`, le reseau a ete restaure ;
- Lora a fonctionne apres correction des parametres/cache navigateur.

Parametres Lora a verifier dans `https://lora.algokit.io/settings` :

```text
Algod server  : http://localhost
Algod port    : 4001
Algod token   : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Indexer server: http://localhost
Indexer port  : 8980

KMD server    : http://localhost
KMD port      : 4002
KMD token     : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## Commandes utiles

Demarrer LocalNet :

```powershell
algokit localnet start
```

Verifier LocalNet :

```powershell
algokit localnet status
```

Ouvrir Lora/Explore :

```powershell
algokit localnet explore
```

Regenerer les fichiers TEAL :

```powershell
cd D:\Master\M2\ProjetDeMemoir\iot-auth\smart-contract
..\.venv\Scripts\python.exe contract.py
```

Deployer le contrat :

```powershell
cd D:\Master\M2\ProjetDeMemoir\iot-auth\smart-contract
..\.venv\Scripts\python.exe deploy.py
```

Lancer le backend en profil dev :

```powershell
cd D:\Master\M2\ProjetDeMemoir\iot-auth\backend
$env:SPRING_PROFILES_ACTIVE="dev"
.\mvnw.cmd spring-boot:run
```

Tester le backend :

```powershell
cd D:\Master\M2\ProjetDeMemoir\iot-auth\backend
.\mvnw.cmd test
```

## Attention importante

Si la commande suivante est executee :

```powershell
algokit localnet reset
```

ou :

```powershell
algokit localnet reset --update
```

alors l'etat blockchain local est efface. Dans ce cas :

1. l'App ID `1014` peut disparaitre ;
2. il faut redeployer le smart contract ;
3. il faut remplacer l'App ID dans `application-dev.properties` ;
4. il faut redemarrer le backend.

## Conclusion

Le projet est maintenant aligne avec l'environnement LocalNet actif :

- Lora fonctionne ;
- le smart contract actif est `1014` ;
- le backend dev pointe vers `1014` ;
- les tests backend passent ;
- l'erreur de mnemonic Algorand vide ne bloque plus le demarrage local.
