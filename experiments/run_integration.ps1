[CmdletBinding()]
param(
    [switch]$SkipUnitTests,
    [switch]$SkipContract,
    [switch]$SkipE2E,
    [switch]$SkipFrontend,
    [switch]$NoStartInfrastructure,
    [switch]$NoStartBackend,
    [switch]$KeepBackend,
    [int]$BackendTimeoutSeconds = 120,
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $Root "experiments\results\integration"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$StartedBackend = $false
$BackendProcess = $null
$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Step, [bool]$Passed, [string]$Detail)
    $Results.Add([pscustomobject]@{
        step = $Step
        result = if ($Passed) { "PASS" } else { "FAIL" }
        detail = $Detail
    })
    $tag = if ($Passed) { "PASS" } else { "FAIL" }
    Write-Host "[$tag] $Step — $Detail"
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Commande requise introuvable: $Name"
    }
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    try {
        & $Action
        Add-Result $Name $true "OK"
        return $true
    } catch {
        Add-Result $Name $false $_.Exception.Message
        return $false
    }
}

function Wait-Http {
    param([string]$Uri, [int]$TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
        } catch {}
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "Timeout en attendant $Uri"
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        return $task.Wait(3000) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

try {
    Write-Host "IoT Auth — test d'intégration système complet" -ForegroundColor Green
    Write-Host "Racine    : $Root"
    Write-Host "Rapports  : $OutputDir"

    Invoke-Step "Prérequis locaux" {
        Require-Command "docker"
        Require-Command "python"
        Require-Command "algokit"
        Require-Command "git"
        if (-not (Test-Path (Join-Path $Root "backend\mvnw.cmd"))) {
            throw "backend\mvnw.cmd introuvable"
        }
        if (-not (Test-Path (Join-Path $Root "experiments\e2e_security_suite.py"))) {
            throw "experiments\e2e_security_suite.py introuvable"
        }
    } | Out-Null

    if (-not $NoStartInfrastructure) {
        Invoke-Step "Démarrage PostgreSQL/Redis" {
            Push-Location (Join-Path $Root "backend")
            try {
                docker compose -f compose.yaml up -d postgres redis
                if ($LASTEXITCODE -ne 0) { throw "docker compose backend a échoué" }
            } finally { Pop-Location }
        } | Out-Null

        Invoke-Step "Démarrage Mosquitto/Node-RED" {
            Push-Location (Join-Path $Root "gateway")
            try {
                docker compose up -d --build
                if ($LASTEXITCODE -ne 0) { throw "docker compose gateway a échoué" }
            } finally { Pop-Location }
        } | Out-Null

        Invoke-Step "Démarrage/validation Algorand LocalNet" {
            algokit localnet start
            if ($LASTEXITCODE -ne 0) { throw "algokit localnet start a échoué" }
        } | Out-Null
    }

    Invoke-Step "Disponibilité infrastructure" {
        foreach ($p in @(
            @{h="127.0.0.1"; p=5432; n="PostgreSQL"},
            @{h="127.0.0.1"; p=6379; n="Redis"},
            @{h="127.0.0.1"; p=1883; n="Mosquitto"},
            @{h="127.0.0.1"; p=1880; n="Node-RED"},
            @{h="127.0.0.1"; p=4001; n="Algod"}
        )) {
            if (-not (Test-TcpPort $p.h $p.p)) {
                throw "$($p.n):$($p.p) indisponible"
            }
        }
    } | Out-Null

    if (-not $SkipUnitTests) {
        Invoke-Step "Tests Maven backend" {
            Push-Location (Join-Path $Root "backend")
            try {
                $logPath = Join-Path $OutputDir "maven-test.log"
                .\mvnw.cmd test *>&1 | Tee-Object -FilePath $logPath
                if ($LASTEXITCODE -ne 0) { throw "mvn test a échoué" }
            } finally { Pop-Location }
        } | Out-Null
    }

    if (-not $SkipContract) {
        Invoke-Step "Test d'irréversibilité du smart contract" {
            if ([string]::IsNullOrWhiteSpace($env:ALGORAND_DEPLOYER_MNEMONIC)) {
                throw "Définir ALGORAND_DEPLOYER_MNEMONIC pour le test LocalNet."
            }
            Push-Location (Join-Path $Root "smart-contract")
            try {
                $logPath = Join-Path $OutputDir "contract-test.log"
                python test_contract_irreversibility.py *>&1 | Tee-Object -FilePath $logPath
                if ($LASTEXITCODE -ne 0) { throw "test_contract_irreversibility.py a échoué" }
            } finally { Pop-Location }
        } | Out-Null
    }

    if (-not $NoStartBackend) {
        Invoke-Step "Démarrage backend Spring Boot" {
            if ([string]::IsNullOrWhiteSpace($env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD)) {
                throw "Définir IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD avant le lancement."
            }
            $logPath = Join-Path $OutputDir "backend.log"
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = "cmd.exe"
            $psi.Arguments = '/c ".\mvnw.cmd spring-boot:run -Dspring-boot.run.profiles=dev > "' + $logPath + '" 2>&1"'
            $psi.WorkingDirectory = Join-Path $Root "backend"
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $BackendProcess = [System.Diagnostics.Process]::Start($psi)
            $StartedBackend = $true
            try {
                Wait-Http "http://localhost:8083/actuator/health" $BackendTimeoutSeconds
            } catch {
                if (Test-Path $logPath) {
                    Write-Host "`n--- backend.log (fin) ---" -ForegroundColor Yellow
                    Get-Content $logPath -Tail 100
                }
                throw
            }
        } | Out-Null
    } else {
        Invoke-Step "Validation backend déjà démarré" {
            Wait-Http "http://localhost:8083/actuator/health" 10
        } | Out-Null
    }

    if (-not $SkipE2E) {
        Invoke-Step "Suite E2E cycle de vie + attaques" {
            if ([string]::IsNullOrWhiteSpace($env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD)) {
                throw "Définir IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD avant la suite E2E."
            }
            $baseConfigPath = Join-Path $Root "experiments\e2e_security_config.json"
            $config = Get-Content $baseConfigPath -Raw | ConvertFrom-Json
            $config.admin_password = $env:IOT_AUTH_ADMIN_BOOTSTRAP_PASSWORD
            $runtimeConfig = Join-Path $OutputDir "e2e_security_config.runtime.json"
            $config | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $runtimeConfig

            $logPath = Join-Path $OutputDir "e2e-security.log"
            Push-Location $Root
            try {
                python experiments\e2e_security_suite.py `
                    --config $runtimeConfig `
                    --output (Join-Path $Root "experiments\results") `
                    --phase all *>&1 | Tee-Object -FilePath $logPath
                if ($LASTEXITCODE -ne 0) { throw "La suite E2E a échoué" }
            } finally { Pop-Location }
        } | Out-Null
    }

    if (-not $SkipFrontend) {
        Invoke-Step "Lint + build frontend" {
            Push-Location (Join-Path $Root "frontend")
            try {
                if (-not (Test-Path "node_modules")) {
                    npm ci
                    if ($LASTEXITCODE -ne 0) { throw "npm ci a échoué" }
                }
                npm run lint
                if ($LASTEXITCODE -ne 0) { throw "npm run lint a échoué" }
                npm run build
                if ($LASTEXITCODE -ne 0) { throw "npm run build a échoué" }
            } finally { Pop-Location }
        } | Out-Null
    }

    $failed = @($Results | Where-Object { $_.result -eq "FAIL" })
    $summary = [pscustomobject]@{
        date_utc = (Get-Date).ToUniversalTime().ToString("o")
        git_commit = (& git -C $Root rev-parse HEAD).Trim()
        passed = @($Results | Where-Object { $_.result -eq "PASS" }).Count
        failed = $failed.Count
        status = if ($failed.Count -eq 0) { "PASS" } else { "FAIL" }
        checks = $Results
    }
    $summaryPath = Join-Path $OutputDir "integration_summary.json"
    $summary | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $summaryPath

    Write-Host "`n========================================" -ForegroundColor Cyan
    $color = if ($summary.status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "RÉSULTAT GLOBAL : $($summary.status)" -ForegroundColor $color
    Write-Host "Contrôles PASS  : $($summary.passed)"
    Write-Host "Contrôles FAIL  : $($summary.failed)"
    Write-Host "Rapport         : $summaryPath"
    Write-Host "========================================"

    if ($failed.Count -gt 0) { exit 1 }
}
finally {
    if ($StartedBackend -and -not $KeepBackend -and $BackendProcess -and -not $BackendProcess.HasExited) {
        Write-Host "`nArrêt du backend Spring Boot..."
        try {
            $BackendProcess.Kill($true)
            $BackendProcess.WaitForExit(10000) | Out-Null
        } catch {
            Write-Warning "Impossible d'arrêter le backend PID $($BackendProcess.Id): $($_.Exception.Message)"
        }
    }
}
