# Simulateurs de dispositifs IoT

Ce dossier contient des simulateurs de dispositifs qui tournent en continu.

Le pre-enregistrement reste une action administrateur dans la plateforme :

1. L'administrateur cree le dispositif dans la console avec un numero de serie unique.
2. Le simulateur est lance avec ce meme numero de serie, qui devient son identite materielle fixe.
3. Le simulateur genere ou recharge sa cle Ed25519 locale.
4. Il realise le protocole d'enrolement via la gateway MQTT.
5. Il publie periodiquement des preuves operationnelles vers la gateway MQTT.

Le simulateur ne communique jamais directement avec le backend. Tous les messages du dispositif passent par le broker MQTT et sont relayes par la gateway.

## Installation

Depuis la racine du projet, avec l'environnement Python active :

```powershell
pip install -r devices/requirements.txt
```

## Lancer un dispositif

Exemple apres pre-enregistrement admin du serial `IOT-TEMP-001` :

```powershell
python devices/device_simulator.py --serial IOT-TEMP-001 
```

## Lancer un nouveau device avec un nouveau serial number

Pour ajouter un nouveau dispositif, choisis un nouveau `serialNumber` qui n'existe pas encore dans la plateforme.

Exemple avec `IOT-HUM-002` :

1. Dans la console admin, clique sur `+ Pre-enregistrer`.
2. Renseigne le numero de serie :

```text
IOT-HUM-002
```

3. Complete les autres champs, puis valide le pre-enregistrement.
4. Lance ensuite le simulateur avec le meme serial :

```powershell
python devices/device_simulator.py --serial IOT-HUM-002 --type capteur-humidite --location Ziguinchor-Lab
```

Le simulateur va creer son fichier d'identite local :

```text
devices/state/IOT-HUM-002.json
```

Ce fichier contient la cle privee, la cle publique, le DID, le VC et le JWT du device. Il ne doit pas etre versionne dans Git.

Pour lancer plusieurs devices, ouvre plusieurs terminaux et utilise un serial different pour chaque device :

```powershell
python devices/device_simulator.py --serial IOT-TEMP-001 --type capteur-temperature
python devices/device_simulator.py --serial IOT-HUM-002 --type capteur-humidite
python devices/device_simulator.py --serial IOT-PRESS-003 --type capteur-pression
```

## Tester la suspension automatique par inactivite

1. Pre-enregistre un device dans la console admin.
2. Lance son simulateur.
3. Verifie qu'il passe en `ACTIVE`.
4. Arrete le simulateur avec `Ctrl+C`.
5. Attends le delai configure par le backend.

Par defaut, le backend suspend automatiquement un device `ACTIVE` apres 90 secondes sans communication operationnelle autorisee :

```properties
iot.auth.inactivity-monitor.timeout-seconds=90
```

Le statut devient `SUSPENDED` et un log `DEVICE_AUTO_SUSPENDED` est cree avec l'acteur `SYSTEM`.

Le simulateur garde une identite distincte par numero de serie dans `devices/state/`.

Exemple :

- `IOT-TEMP-001` utilise `devices/state/IOT-TEMP-001.json`
- `IOT-PRESS-002` utilise `devices/state/IOT-PRESS-002.json`

Le simulateur ne bloque pas l'utilisation simultanee d'un meme serial. C'est volontaire : cela permet de lancer des tests d'usurpation d'identite avec un serial deja connu par la plateforme.

Dans le cas normal, un serial correspond a une identite locale persistante. Pour simuler une attaque, lance un second simulateur avec le meme serial mais depuis un autre etat local ou apres regeneration de la cle : la plateforme doit detecter l'incoherence entre serial, DID, cle publique et statut.

## Options utiles

```powershell
python devices/device_simulator.py --serial IOT-TEMP-001 --interval 10 --permission device:read
```

- `--interval` : delai entre deux messages operationnels.
- `--permission` : permission demandee a la gateway.
- `--mqtt-host` / `--mqtt-port` : broker MQTT, par defaut `localhost:1883`.
