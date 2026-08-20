<#
  admin.ps1 — Konfig-Werkzeug fuer den ESP32-USB-VPN-Dongle.

  Erstellt gefuehrt eine gueltige Dongle-Konfig, verschluesselt sie mit dem
  20-stelligen Secret (identisches Format wie die Firmware) und kann eine
  verschluesselte Konfig wieder entschluesseln/ansehen.

  Container:  "BHVPN1." + base64( IV(16) || AES-256-CBC(PKCS7) || HMAC-SHA256(32) )
    encKey = SHA256("bhvpn-enc:" + secret)
    macKey = SHA256("bhvpn-mac:" + secret)
    HMAC   = HMAC-SHA256(macKey, IV || Ciphertext)   (Encrypt-then-MAC)
  Klartext = key=value-Zeilen (siehe firmware config_export/import).

  Aufruf:
    .\admin.ps1                      -> Menue (Erstellen / Entschluesseln)
    .\admin.ps1 -Mode create -Out cfg.bhvpn -Secret <20>
    .\admin.ps1 -Mode decrypt -In cfg.bhvpn -Secret <20>
#>
param(
    [ValidateSet('create', 'decrypt')] [string]$Mode,
    [string]$In,
    [string]$Out,
    [string]$Secret
)
$ErrorActionPreference = 'Stop'

function Get-Sha256([byte[]]$data) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($data) } finally { $sha.Dispose() }
}
function Get-Sha256Hex([string]$s) {
    ((Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($s))) | ForEach-Object { $_.ToString('x2') }) -join ''
}
function Derive-Key([string]$prefix, [string]$secret) {
    Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($prefix + $secret))
}

function Protect-Config([string]$plaintext, [string]$secret) {
    $encKey = Derive-Key 'bhvpn-enc:' $secret
    $macKey = Derive-Key 'bhvpn-mac:' $secret
    $iv = New-Object byte[] 16
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($iv)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey; $aes.IV = $iv
    $enc = $aes.CreateEncryptor()
    $pt = [Text.Encoding]::UTF8.GetBytes($plaintext)
    $ct = $enc.TransformFinalBlock($pt, 0, $pt.Length)
    $aes.Dispose()
    $ivct = New-Object byte[] (16 + $ct.Length)
    [Array]::Copy($iv, 0, $ivct, 0, 16); [Array]::Copy($ct, 0, $ivct, 16, $ct.Length)
    $hm = New-Object System.Security.Cryptography.HMACSHA256((, $macKey))
    $mac = $hm.ComputeHash($ivct); $hm.Dispose()
    $blob = New-Object byte[] ($ivct.Length + 32)
    [Array]::Copy($ivct, 0, $blob, 0, $ivct.Length); [Array]::Copy($mac, 0, $blob, $ivct.Length, 32)
    return 'BHVPN1.' + [Convert]::ToBase64String($blob)
}

function Unprotect-Config([string]$file, [string]$secret) {
    $file = $file.Trim()
    if (-not $file.StartsWith('BHVPN1.')) { throw 'Falsches Format (kein BHVPN1.)' }
    $blob = [Convert]::FromBase64String($file.Substring(7).Trim())
    if ($blob.Length -lt 64) { throw 'Zu kurz' }
    $ctlen = $blob.Length - 16 - 32
    $iv = $blob[0..15]
    $ct = $blob[16..(16 + $ctlen - 1)]
    $mac = $blob[(16 + $ctlen)..($blob.Length - 1)]
    $encKey = Derive-Key 'bhvpn-enc:' $secret
    $macKey = Derive-Key 'bhvpn-mac:' $secret
    $ivct = $blob[0..(16 + $ctlen - 1)]
    $hm = New-Object System.Security.Cryptography.HMACSHA256((, $macKey))
    $calc = $hm.ComputeHash($ivct); $hm.Dispose()
    if ([Convert]::ToBase64String($calc) -ne [Convert]::ToBase64String($mac)) {
        throw 'HMAC ungueltig -> falsches Secret oder beschaedigte Datei'
    }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey; $aes.IV = $iv
    $dec = $aes.CreateDecryptor()
    $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)
    $aes.Dispose()
    return [Text.Encoding]::UTF8.GetString($pt)
}

function Read-Def([string]$prompt, [string]$default) {
    $v = Read-Host ("{0}{1}" -f $prompt, $(if ($default) { " [$default]" } else { '' }))
    if ([string]::IsNullOrEmpty($v)) { return $default } else { return $v }
}

function New-ConfigGuided {
    Write-Host "== Dongle-Konfig erstellen ==" -ForegroundColor Cyan
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('schema=1')
    $lines.Add('version=' + (Read-Def 'Config-Version (Ganzzahl, hoeher = neuer)' '1'))
    $lines.Add('systemname=' + (Read-Def 'Systemname' 'Dongle'))
    Write-Host "-- WLANs (mehrere moeglich, Reihenfolge = Prioritaet; Enter bei SSID beendet) --"
    $wi = 0
    $wlanLines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $ws = Read-Host ("WLAN #{0} SSID (leer=fertig)" -f $wi)
        if ([string]::IsNullOrEmpty($ws)) { break }
        $wp = Read-Def '  Passwort' ''
        $wlanLines.Add("wlan.$wi.ssid=$ws"); $wlanLines.Add("wlan.$wi.pass=$wp")
        $wi++
    }
    $lines.Add("wlan.count=$wi")
    $lines.AddRange($wlanLines)
    Write-Host "-- WireGuard --"
    $lines.Add('wg.priv=' + (Read-Def 'WG Private Key' ''))
    $lines.Add('wg.pub=' + (Read-Def 'WG Peer Public Key' ''))
    $lines.Add('wg.psk=' + (Read-Def 'WG Preshared Key (optional)' ''))
    $lines.Add('wg.endpoint=' + (Read-Def 'WG Endpoint Host/IP' ''))
    $lines.Add('wg.port=' + (Read-Def 'WG Port' '51820'))
    $lines.Add('wg.addr=' + (Read-Def 'WG Tunnel-IP' ''))
    $lines.Add('wg.mask=' + (Read-Def 'WG Maske' '255.255.255.0'))
    $lines.Add('wg.keepalive=' + (Read-Def 'WG Keepalive s' '25'))
    $lines.Add('wg.fulltunnel=' + $(if ((Read-Def 'Volltunnel? (j/n)' 'j') -match '^[jJyY]') { '1' } else { '0' }))
    $lines.Add('wg.killswitch=' + $(if ((Read-Def 'Kill-Switch? (j/n)' 'n') -match '^[jJyY]') { '1' } else { '0' }))
    $lines.Add('wg.vpn_off=0')
    Write-Host "-- Admin --"
    $au = Read-Def 'Admin-Benutzer' 'admin'
    $ap = Read-Def 'Admin-Passwort (wird als SHA-256-Hash gespeichert)' 'admin'
    $lines.Add('admin.user=' + $au)
    $lines.Add('admin.phash=' + (Get-Sha256Hex $ap))
    Write-Host "-- Ressourcen (RDP/Link/SSH), Enter bei Name beendet --"
    $ri = 0
    $resLines = New-Object System.Collections.Generic.List[string]
    while ($true) {
        $rn = Read-Host ("Ressource #{0} Name (leer=fertig)" -f $ri)
        if ([string]::IsNullOrEmpty($rn)) { break }
        $rt = Read-Def '  Typ (rdp/link/ssh)' 'rdp'
        $ra = Read-Def '  Adresse/URL' ''
        $rp = Read-Def '  Port' '3389'
        $resLines.Add("res.$ri.name=$rn"); $resLines.Add("res.$ri.type=$rt")
        $resLines.Add("res.$ri.addr=$ra"); $resLines.Add("res.$ri.port=$rp")
        $ri++
    }
    $lines.Add("res.count=$ri")
    $lines.AddRange($resLines)
    return ($lines -join "`n") + "`n"
}

# --- Ablauf ---
if (-not $Mode) {
    Write-Host "1) Konfig erstellen + verschluesseln"
    Write-Host "2) Konfig entschluesseln/ansehen"
    $Mode = @{ '1' = 'create'; '2' = 'decrypt' }[(Read-Host 'Auswahl')]
}
if (-not $Secret) { $Secret = Read-Host 'Konfig-Secret (20 alphanumerisch)' }
if ($Secret -notmatch '^[A-Za-z0-9]{1,20}$') { Write-Warning 'Secret sollte 1-20 alphanumerische Zeichen sein.' }

if ($Mode -eq 'create') {
    $plain = New-ConfigGuided
    $enc = Protect-Config $plain $Secret
    if (-not $Out) { $Out = Read-Def 'Ausgabedatei' 'config.json' }
    Set-Content -Path $Out -Value $enc -Encoding ascii -NoNewline
    Write-Host ("Verschluesselt geschrieben: {0} ({1} Bytes)" -f $Out, $enc.Length) -ForegroundColor Green
    Write-Host "Auf den Config-Server legen unter:  <basis>/<SN>/config.json"
}
elseif ($Mode -eq 'decrypt') {
    if (-not $In) { $In = Read-Def 'Eingabedatei (.bhvpn/.json)' 'config.json' }
    $enc = (Get-Content -Path $In -Raw)
    $plain = Unprotect-Config $enc $Secret
    Write-Host "== Klartext-Konfig ==" -ForegroundColor Cyan
    Write-Output $plain
}
