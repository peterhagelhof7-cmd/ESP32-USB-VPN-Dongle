<#
  flash.ps1 — baut die Firmware und flasht den Wemos S2 Mini.

  WICHTIG: Nach dem ersten Flash meldet sich der S2 als USB-Netzwerkadapter,
  NICHT mehr als serieller COM-Port. Zum Neuflashen den S2 in den Download-Modus
  bringen: BOOT (GPIO0) gedrueckt halten, RST kurz tippen, BOOT loslassen —
  dann erscheint wieder ein serieller Port und dieses Skript flasht.

  Parameter:
    -Monitor     nach dem Flashen den seriellen Monitor oeffnen
    -Port <COMx> Port erzwingen (sonst Auto)
    -SkipBuild   nur flashen (vorhandenen Build nutzen)
#>
param(
    [switch]$Monitor,
    [string]$Port,
    [switch]$SkipBuild
)
$ErrorActionPreference = "Stop"
$env:PLATFORMIO_DISABLE_PROGRESSBAR = "true"
Set-Location (Join-Path $PSScriptRoot "..")   # -> firmware/

$envName = "lolin_s2_mini"
if (-not $SkipBuild) {
    Write-Host "== Baue Firmware ($envName) ==" -ForegroundColor Cyan
    pio run -e $envName
    if ($LASTEXITCODE -ne 0) { throw "Build fehlgeschlagen." }
}

$portArg = @()
if ($Port) { $portArg = @("--upload-port", $Port) }

Write-Host "== Flashe ==" -ForegroundColor Cyan
Write-Host "  (Falls kein Port gefunden: S2 in den Download-Modus bringen — BOOT halten, RST tippen.)" -ForegroundColor Yellow
pio run -e $envName -t upload @portArg
if ($LASTEXITCODE -ne 0) { throw "Flashen fehlgeschlagen." }

Write-Host "== Fertig. USB neu einstecken -> Netzwerkadapter + http://192.168.226.1/ ==" -ForegroundColor Green
if ($Monitor) { pio device monitor -e $envName }
