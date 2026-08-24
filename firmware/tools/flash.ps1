<#
  flash.ps1 — baut die Firmware und flasht sie auf das gewaehlte Board.

  Zwei Hardware-Varianten:
    -Board S2 : Wemos S2 Mini (ESP32-S2). Natives USB-OTG, KEIN Auto-Reset.
                Zum (Neu-)Flashen in den DOWNLOAD-MODUS bringen:
                BOOT (GPIO0) halten, RST tippen, BOOT loslassen -> serieller
                Port erscheint. Nach dem Flash meldet er sich als USB-Netzadapter
                (kein COM-Port mehr).
    -Board S3 : ESP32-S3-DevKitC-1 N16R8. Flashen ueber den UART-Port (CP210x,
                Auto-Reset) -> KEIN Download-Modus noetig. Der NCM-Netzadapter
                erscheint am separaten nativen USB-Port; serielle Logs am UART-Port.

  Parameter:
    -Board <S2|S3>  Zielboard (Pflicht)
    -Port <COMx>    Upload-Port erzwingen (sonst Auto)
    -SkipBuild      nur flashen (vorhandenen Build nutzen)
    -Monitor        nach dem Flashen den seriellen Monitor oeffnen
                    (nur S3 sinnvoll -> UART-Port; S2 ist NCM-only ohne Konsole)

  Beispiele:
    .\flash.ps1 -Board S3                 # S3 bauen + flashen (Port automatisch)
    .\flash.ps1 -Board S3 -Port COM19 -Monitor
    .\flash.ps1 -Board S2                 # S2 (vorher in den Download-Modus!)
    .\flash.ps1 -Board S3 -SkipBuild -Port COM19
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('S2', 'S3')]
    [string]$Board,
    [string]$Port,
    [switch]$SkipBuild,
    [switch]$Monitor
)
$ErrorActionPreference = "Stop"
$env:PLATFORMIO_DISABLE_PROGRESSBAR = "true"
Set-Location (Join-Path $PSScriptRoot "..")   # -> firmware/

# Board -> PlatformIO-Env
$envName = @{ 'S2' = 'lolin_s2_mini'; 'S3' = 'esp32-s3-devkitc-1' }[$Board]
Write-Host "== Board $Board  ->  Env $envName ==" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "== Baue Firmware ($envName) ==" -ForegroundColor Cyan
    pio run -e $envName
    if ($LASTEXITCODE -ne 0) { throw "Build fehlgeschlagen." }
}

$portArg = @()
if ($Port) { $portArg = @("--upload-port", $Port) }

Write-Host "== Flashe $Board ==" -ForegroundColor Cyan
if ($Board -eq 'S2') {
    Write-Host "  Falls kein Port gefunden: S2 in den DOWNLOAD-MODUS bringen" -ForegroundColor Yellow
    Write-Host "  (BOOT/GPIO0 halten, RST tippen, BOOT loslassen)." -ForegroundColor Yellow
} else {
    Write-Host "  S3: ueber den UART-Port flashen (Auto-Reset, kein Download-Modus)." -ForegroundColor Yellow
}
pio run -e $envName -t upload @portArg
if ($LASTEXITCODE -ne 0) { throw "Flashen fehlgeschlagen." }

Write-Host "== Fertig. Nativen USB-Port einstecken -> Netzwerkadapter + http://192.168.226.1/ ==" -ForegroundColor Green
if ($Monitor) {
    if ($Board -eq 'S2') {
        Write-Host "Hinweis: S2 ist NCM-only ohne serielle Konsole -> Monitor liefert nichts." -ForegroundColor Yellow
    }
    pio device monitor -e $envName
}
