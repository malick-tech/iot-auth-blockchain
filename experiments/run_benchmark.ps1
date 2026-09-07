param(
    [string]$Config = "$PSScriptRoot\benchmark_config.json",
    [string]$Output = "$PSScriptRoot\results"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Verification des services..."
Invoke-RestMethod "http://localhost:8083/actuator/health" | Out-Null
Invoke-RestMethod "http://localhost:8980/health" | Out-Null

Write-Host "Lancement du benchmark..."
python "$PSScriptRoot\benchmark.py" --config $Config --output $Output
