# Web-Flasher aktualisieren: Builds beider Boards nach docs/fw/<board>/ kopieren und
# docs/manifest.json (esp-web-tools) mit Version, Offsets und SHA-256 schreiben.
#   .\tools\webflasher-update.ps1 -Version 1.0.1
#   .\tools\webflasher-update.ps1 -Version 1.0.1 -FirmwareDir <anderer firmware-Ordner>
# Vorher beide Envs bauen (pio run -e esp32-s3-devkitc-1 -e lolin_s2_mini), am besten
# aus einem sauberen Checkout des Tags, damit die App-Version "v<Version>" lautet.
# Prueft, dass jede App die erwartete Version enthaelt - so landet kein falscher Build
# im Flasher. Ausgaben nur ASCII (PowerShell 5.1).
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$FirmwareDir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $FirmwareDir) { $FirmwareDir = Join-Path $root 'firmware' }
$docs = Join-Path $root 'docs'
$utf8 = New-Object System.Text.UTF8Encoding($false)

# Bootloader-Offset: ESP32-S2 0x1000, ESP32-S3 0x0; Rest laut partitions*.csv
$boards = [ordered]@{
    s3 = @{ Env = 'esp32-s3-devkitc-1'; Chip = 'ESP32-S3'; Boot = 0x0 }
    s2 = @{ Env = 'lolin_s2_mini';      Chip = 'ESP32-S2'; Boot = 0x1000 }
}
$parts = @(
    @{ File = 'bootloader.bin';       Offset = $null },
    @{ File = 'partitions.bin';       Offset = 0x8000 },
    @{ File = 'ota_data_initial.bin'; Offset = 0xF000 },
    @{ File = 'firmware.bin';         Offset = 0x20000; Out = 'app.bin' }
)

function Get-Sha256([string]$path) {
    (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
}

$builds = @()
$info = [ordered]@{}
foreach ($b in $boards.Keys) {
    $cfg = $boards[$b]
    $src = Join-Path $FirmwareDir ".pio\build\$($cfg.Env)"
    $app = Join-Path $src 'firmware.bin'
    if (-not (Test-Path $app)) { throw "Build fehlt: $app (pio run -e $($cfg.Env))" }
    # App-Beschreibung (esp_app_desc_t) enthaelt die Version aus git describe
    $bytes = [IO.File]::ReadAllBytes($app)
    $text = [Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($bytes.Length, 4096))
    if ($text -notmatch [regex]::Escape("v$Version") -or $text -match [regex]::Escape("v$Version-")) {
        throw "$($cfg.Env): App traegt nicht genau die Version v$Version (dirty/anderer Stand?)"
    }
    $dst = Join-Path $docs "fw\$b"
    New-Item -ItemType Directory -Force $dst | Out-Null
    $list = @()
    $files = [ordered]@{}
    foreach ($p in $parts) {
        $in = Join-Path $src $p.File
        if (-not (Test-Path $in)) { throw "Datei fehlt: $in" }
        $outName = if ($p.Out) { $p.Out } else { $p.File }
        Copy-Item $in (Join-Path $dst $outName) -Force
        $off = if ($null -eq $p.Offset) { $cfg.Boot } else { $p.Offset }
        $list += [ordered]@{ path = "fw/$b/$outName"; offset = $off }
        $files[$outName] = [ordered]@{ size = (Get-Item $in).Length; sha256 = Get-Sha256 $in }
    }
    $builds += [ordered]@{ chipFamily = $cfg.Chip; parts = $list }
    $info[$b] = $files
    Write-Host ("{0}: {1} -> docs/fw/{0}/ ({2} Bytes App)" -f $b, $cfg.Env, $files['app.bin'].size)
}

$manifest = [ordered]@{
    name = 'ESP32-USB-VPN-Dongle'
    version = $Version
    new_install_prompt_erase = $true
    builds = $builds
}
[IO.File]::WriteAllText((Join-Path $docs 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6), $utf8)
[IO.File]::WriteAllText((Join-Path $docs 'fw\info.json'),
    ([ordered]@{ version = $Version; boards = $info } | ConvertTo-Json -Depth 6), $utf8)
Write-Host "docs/manifest.json + docs/fw/info.json geschrieben (Version $Version)"
