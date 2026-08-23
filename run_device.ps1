# run_device.ps1 — Lance le simulateur de dispositif IoT avec le venv activé.
# Usage : .\run_device.ps1 --serial IOT-TEMP-001 [--interval 15] [--permission device:read]

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Error "Venv introuvable : $venvPython"
    Write-Host "Crée le venv avec : python -m venv .venv"
    Write-Host "Puis installe les dépendances : .venv\Scripts\pip install -r devices/requirements.txt"
    exit 1
}

# Passer tous les arguments directement au simulateur
& $venvPython devices/device_simulator.py @args
