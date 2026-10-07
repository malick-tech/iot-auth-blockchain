<#
.SYNOPSIS
  Lance le diagnostic / le patch / le benchmark en verifiant et corrigeant les problemes courants.

.DESCRIPTION
  Depuis la racine du depot (ou n'importe ou) :
    .\experiments\run_all.ps1                 # diagnostic seul (par defaut)
    .\experiments\run_all.ps1 -Step patch     # applique le patch HIT natif + redemarre Node-RED + re-diagnostic
    .\experiments\run_all.ps1 -Step bench     # e2e securite + benchmark (rate limiting a desactiver avant)
    .\experiments\run_all.ps1 -Step all       # patch puis bench

  Corrections automatiques :
    - conteneurs gateway arretes            -> docker compose up -d
    - localhost (IPv6 ::1 vs IPv4)          -> 127.0.0.1 (diagnostic + mqtt_host des configs, sauvegarde .bak)
    - onglet de diagnostic Node-RED absent  -> importe par l'API d'administration
    - fichiers .py vides/tronques/invalides -> detectes et signales (a recopier)
  Un journal complet est ecrit dans experiments\results\run_all.log (a m'envoyer en cas de probleme).
#>
param(
    [ValidateSet("diag", "patch", "bench", "all")][string]$Step = "diag",
    [string]$Mqtt = "127.0.0.1",
    [string]$NodeRed = "http://localhost:1880",
    [string]$Patch = "",
    [switch]$KeepDiagTab
)

$ErrorActionPreference = "Continue"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root
$Results = Join-Path $PSScriptRoot "results"
if (-not (Test-Path $Results)) { New-Item -ItemType Directory -Path $Results | Out-Null }
try { Start-Transcript -Path (Join-Path $Results "run_all.log") -Force | Out-Null } catch { }

function Info($m) { Write-Host "[INFO]   $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[OK]     $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[ATTENTION] $m" -ForegroundColor Yellow }
function Stop-Run($m) {
    Write-Host "[ERREUR] $m" -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

function Run-Python {
    # Execute python et renvoie le code de sortie (la sortie s'affiche en direct).
    & python @args | Out-Host
    return $LASTEXITCODE
}

# ---------------------------------------------------------------- 1. fichiers Python
Info "Verification des fichiers Python..."
$required = @{ "benchmark.py" = 4000; "benchmark_stats.py" = 3000; "diagnose_gateway.py" = 3000; "nodered_admin.py" = 1500 }
foreach ($name in $required.Keys) {
    $path = Join-Path $PSScriptRoot $name
    if (-not (Test-Path $path)) { Stop-Run "$name est absent de experiments\ : copiez-le depuis les fichiers fournis." }
    $size = (Get-Item $path).Length
    if ($size -lt $required[$name]) { Stop-Run "$name est vide ou tronque ($size octets, attendu > $($required[$name])) : recopiez le fichier fourni." }
    $out = & python -m py_compile $path 2>&1
    if ($LASTEXITCODE -ne 0) { Stop-Run "Erreur de syntaxe dans $name :`n$out" }
}
if (-not (Select-String -Path (Join-Path $PSScriptRoot "diagnose_gateway.py") -Pattern "__main__" -Quiet)) {
    Stop-Run "diagnose_gateway.py est incomplet (pas de point d'entree) : recopiez le fichier fourni."
}
Ok "Fichiers Python presents et valides."

# ---------------------------------------------------------------- 2. Docker et conteneurs
Info "Verification de Docker..."
& docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-Run "Docker ne repond pas. Demarrez Docker Desktop, attendez qu'il soit 'running', puis relancez." }

function Test-Running($name) {
    $r = @(& docker ps --format "{{.Names}}" 2>$null)
    return ($r -contains $name)
}

$gatewayNames = @("iot-auth-mosquitto", "iot-auth-node-red")
$missing = @($gatewayNames | Where-Object { -not (Test-Running $_) })
if ($missing.Count -gt 0) {
    Warn "Conteneurs arretes : $($missing -join ', '). Demarrage de la passerelle..."
    $envFile = Join-Path $Root "gateway\.env"
    if (-not (Test-Path $envFile) -and -not (Test-Path (Join-Path $Root ".env"))) {
        Warn "Aucun fichier .env trouve : docker compose a besoin de IOT_AUTH_GATEWAY_SHARED_SECRET et REDIS_GATEWAY_PASSWORD (voir .env.example)."
    }
    $composeOut = & docker compose -f (Join-Path $Root "gateway\docker-compose.yml") up -d 2>&1
    Start-Sleep -Seconds 8
    $missing = @($gatewayNames | Where-Object { -not (Test-Running $_) })
    if ($missing.Count -gt 0) { Stop-Run "Impossible de demarrer : $($missing -join ', ').`n$($composeOut -join "`n")" }
}
Ok "Mosquitto et Node-RED sont demarres."

# ---------------------------------------------------------------- 3. Conflit de port 1883 (IPv4/IPv6)
try {
    $listeners = @(Get-NetTCPConnection -LocalPort 1883 -State Listen -ErrorAction Stop)
    $owners = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    $described = foreach ($procId in $owners) {
        try { "{0} (PID {1})" -f (Get-Process -Id $procId -ErrorAction Stop).ProcessName, $procId } catch { "PID $procId" }
    }
    if ($owners.Count -gt 1) {
        Warn "Plusieurs processus ecoutent sur le port 1883 : $($described -join ' ; ')."
        Warn "Correction appliquee : le client utilisera $Mqtt (IPv4) au lieu de 'localhost'."
        if ($described -match "(?i)^mosquitto") { Warn "Un Mosquitto Windows tourne : arretez-le (Stop-Service mosquitto) pour eviter toute confusion." }
    } else {
        Ok "Un seul processus sur le port 1883 : $($described -join '')."
    }
} catch {
    Info "Controle du port 1883 ignore ($($_.Exception.Message))."
}

# ---------------------------------------------------------------- 4. mqtt_host -> IPv4 dans les configs
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
foreach ($cfg in @("benchmark_config.json", "e2e_security_config.json")) {
    $p = Join-Path $PSScriptRoot $cfg
    if (-not (Test-Path $p)) { continue }
    $txt = [System.IO.File]::ReadAllText($p)
    if ($txt -match '"mqtt_host"\s*:\s*"localhost"') {
        Copy-Item $p "$p.bak" -Force
        $new = $txt -replace '"mqtt_host"\s*:\s*"localhost"', ('"mqtt_host": "{0}"' -f $Mqtt)
        [System.IO.File]::WriteAllText($p, $new, $utf8NoBom)
        Ok "$cfg : mqtt_host 'localhost' -> '$Mqtt' (sauvegarde : $cfg.bak)."
    }
}

# ---------------------------------------------------------------- fonctions d'etape
function Wait-NodeRed([int]$seconds = 60) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { Invoke-RestMethod "$NodeRed/flows" -TimeoutSec 3 | Out-Null; return $true } catch { Start-Sleep -Seconds 2 }
    }
    return $false
}

function Invoke-Diagnostic {
    if (-not (Wait-NodeRed 30)) { Stop-Run "Node-RED ne repond pas sur $NodeRed." }
    $flowFile = Join-Path $Root "gateway\node-red-data\diag_flow.json"
    if (-not (Test-Path $flowFile)) {
        $alt = Join-Path $PSScriptRoot "diag_flow.json"
        if (Test-Path $alt) { $flowFile = $alt } else { Stop-Run "diag_flow.json introuvable (placez-le dans gateway\node-red-data\ ou experiments\)." }
    }
    $code = Run-Python (Join-Path $PSScriptRoot "nodered_admin.py") ensure --flow $flowFile --url $NodeRed
    if ($code -ne 0) { Stop-Run "Import automatique de l'onglet de diagnostic impossible (voir message ci-dessus). Importez diag_flow.json a la main dans Node-RED." }
    Start-Sleep -Seconds 3   # laisse le temps aux noeuds de se connecter (Redis, MQTT)
    $code = Run-Python (Join-Path $PSScriptRoot "diagnose_gateway.py") --host $Mqtt
    if ($code -eq 2) {
        Warn "Aucune reponse des etages : nouvel essai apres 10 s (demarrage des noeuds)..."
        Start-Sleep -Seconds 10
        $code = Run-Python (Join-Path $PSScriptRoot "diagnose_gateway.py") --host $Mqtt
    }
    if ($code -ne 0) { Stop-Run "Le diagnostic a echoue (code $code). Envoyez-moi experiments\results\run_all.log." }
    Ok "Diagnostic termine : experiments\results\diagnose_gateway.csv"
}

function Invoke-PatchStep {
    $patchFile = $Patch
    if (-not $patchFile) {
        foreach ($c in @((Join-Path $Root "hit-native-ed25519.patch"), (Join-Path $PSScriptRoot "hit-native-ed25519.patch"))) {
            if (Test-Path $c) { $patchFile = $c; break }
        }
    }
    if (-not $patchFile -or -not (Test-Path $patchFile)) { Stop-Run "hit-native-ed25519.patch introuvable : placez-le a la racine du depot ou passez -Patch <chemin>." }

    & git apply --check -R $patchFile 2>$null
    if ($LASTEXITCODE -eq 0) {
        Ok "Patch deja applique : rien a faire."
    } else {
        & git apply --check $patchFile 2>$null
        $mode = ""
        if ($LASTEXITCODE -ne 0) {
            & git apply --check --ignore-whitespace $patchFile 2>$null
            if ($LASTEXITCODE -ne 0) {
                Stop-Run ("Le patch ne s'applique pas (flows.json a ete modifie localement ?). Details :`n" + ((& git apply --check $patchFile 2>&1) -join "`n") + "`nUtilisez le flows.json complet fourni si vous n'avez pas de modification locale a conserver.")
            }
            $mode = "--ignore-whitespace"
            Warn "Application avec --ignore-whitespace (fins de ligne Windows)."
        }
        if ($mode) { & git apply $mode $patchFile } else { & git apply $patchFile }
        if ($LASTEXITCODE -ne 0) { Stop-Run "git apply a echoue." }
        Ok "Patch applique a gateway\node-red-data\flows.json."
    }
    Info "Redemarrage de Node-RED..."
    & docker restart iot-auth-node-red 2>&1 | Out-Null
    if (-not (Wait-NodeRed 90)) { Stop-Run "Node-RED ne redemarre pas : docker logs iot-auth-node-red --tail 50" }
    Start-Sleep -Seconds 5
    Ok "Node-RED redemarre avec la verification Ed25519 native."
}

function Invoke-BenchStep {
    $e2eCfg = Get-Content (Join-Path $PSScriptRoot "e2e_security_config.json") -Raw
    if ($e2eCfg -match "CHANGE_ME") {
        Warn "e2e_security_config.json contient admin_password = CHANGE_ME : la suite de securite echouera. Renseignez le mot de passe admin."
    }
    Info "Suite de securite de bout en bout (rate limiting ACTIF attendu)..."
    $code = Run-Python (Join-Path $PSScriptRoot "e2e_security_suite.py")
    if ($code -ne 0) { Warn "La suite de securite a retourne le code $code : voir experiments\results\e2e_security_results.csv avant de continuer." }
    else { Ok "Suite de securite : OK." }

    Write-Host ""
    Write-Host "Le benchmark exige le backend lance avec la limitation de debit DESACTIVEE :" -ForegroundColor Yellow
    Write-Host "  .\mvnw.cmd spring-boot:run -Dspring-boot.run.jvmArguments=""-Diot.auth.rate-limit.enabled=false""" -ForegroundColor Yellow
    $answer = Read-Host "Backend relance avec rate limiting desactive ? (o/N)"
    if ($answer -notmatch "^[oOyY]") { Stop-Run "Benchmark annule : relancez le backend comme indique puis -Step bench." }
    $code = Run-Python (Join-Path $PSScriptRoot "benchmark.py")
    if ($code -ne 0) { Stop-Run "Le benchmark a echoue (code $code)." }
    Ok "Benchmark termine : experiments\results\ (summary, comparisons, raw, meta)."
    Warn "Reactivez le backend avec sa configuration normale (rate limiting actif) apres la mesure."
}

# ---------------------------------------------------------------- execution
switch ($Step) {
    "diag"  { Invoke-Diagnostic }
    "patch" { Invoke-Diagnostic; Invoke-PatchStep; Invoke-Diagnostic }
    "bench" { Invoke-BenchStep }
    "all"   { Invoke-PatchStep; Invoke-Diagnostic; Invoke-BenchStep }
}

if (-not $KeepDiagTab -and ($Step -ne "diag")) {
    Info "Suppression de l'onglet de diagnostic..."
    $null = Run-Python (Join-Path $PSScriptRoot "nodered_admin.py") remove --url $NodeRed
}

Ok "Termine. Journal : experiments\results\run_all.log"
try { Stop-Transcript | Out-Null } catch { }
