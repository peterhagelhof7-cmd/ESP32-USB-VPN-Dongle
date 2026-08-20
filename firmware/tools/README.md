# admin.ps1 — Konfig-Werkzeug für den VPN-Dongle

`admin.ps1` erstellt geführt eine gültige Dongle-Konfiguration, verschlüsselt
sie mit dem Konfig-Secret (identisches Format wie die Firmware) und kann eine
verschlüsselte Konfig wieder entschlüsseln/ansehen. Läuft auf **Windows
PowerShell 5.1** (und neuer) ohne Zusatzmodule.

## Wozu

- **Backup/Provisionierung:** eine `.bhvpn`-Datei enthält die komplette Konfig
  (WLAN, WireGuard, Admin-Passwort-Hash, Ressourcen, Systemname, Version) —
  verschlüsselt, damit sie gefahrlos übers Netz/den Config-Server verteilt
  werden kann.
- **Config-Server-Rollout:** Datei je Dongle unter `<basis>/<SN>/config.json`
  ablegen; der Dongle erkennt über die **Version** eine neue Konfig.

## Voraussetzung: das Konfig-Secret

- 1–20 Zeichen, **nur alphanumerisch** (A–Z, a–z, 0–9), keine Umlaute/Sonder-
  zeichen.
- Muss auf dem Dongle (Einstellungen → System → „Konfig-Secret") **und** hier
  identisch sein. Ohne passendes Secret lässt sich weder ent- noch (sinnvoll)
  verschlüsseln.

## Aufruf

```powershell
# Menü (Erstellen / Entschlüsseln)
.\admin.ps1

# Konfig geführt erstellen und verschlüsselt schreiben
.\admin.ps1 -Mode create -Out config.json -Secret DEINSECRET20ZEICHEN

# Verschlüsselte Konfig entschlüsseln/ansehen
.\admin.ps1 -Mode decrypt -In config.json -Secret DEINSECRET20ZEICHEN
```

| Parameter | Bedeutung |
|---|---|
| `-Mode create` | Geführte Erstellung + Verschlüsselung |
| `-Mode decrypt` | Entschlüsseln und Klartext ausgeben |
| `-In <datei>` | Eingabedatei (decrypt) |
| `-Out <datei>` | Ausgabedatei (create), Default `config.json` |
| `-Secret <s>` | Konfig-Secret (sonst wird gefragt) |

Ohne Parameter fragt das Skript alles interaktiv ab.

## Typischer Workflow (Config-Server)

1. `.\admin.ps1 -Mode create` — Angaben eingeben, **Version hochzählen**
   (höher als die aktuell auf dem Dongle laufende → wird als „neu" erkannt).
2. Die erzeugte `config.json` auf den HTTP-Server legen, in ein Verzeichnis
   mit der **Seriennummer** des Ziel-Dongles:
   `http://<server>/<SN>/config.json`
   (SN = kompakte Modul-MAC, steht auf der Dongle-Seite unter „System").
3. Auf dem Dongle Einstellungen → System → **Config-Server-URL** = `http://<server>`
   (Basis ohne SN), Secret setzen.
4. Der Dongle prüft **einmalig 3 Minuten nach WLAN-Connect** (oder manuell über
   „Beim Server prüfen") und meldet „neue Konfig vorhanden" → **Einspielen**.

## Konfig-Format (Klartext, key=value)

Eine Zeile je Feld, Wert = alles nach dem **ersten** `=` (dadurch sind `=` in
WireGuard-Keys unkritisch). Auszug:

```
schema=1
version=5
systemname=Buero-Dongle
wlan.count=2
wlan.0.ssid=Arbeitsplatz-WLAN
wlan.0.pass=...
wlan.1.ssid=Handy-Hotspot
wlan.1.pass=...
wg.priv=...
wg.pub=...
wg.psk=...
wg.endpoint=host.example.org
wg.port=57436
wg.addr=10.10.0.2
wg.mask=255.255.255.0
wg.keepalive=25
wg.fulltunnel=1
wg.killswitch=0
admin.user=admin
admin.phash=<SHA-256-Hex des Admin-Passworts>
res.count=1
res.0.name=fritzbox
res.0.type=link
res.0.addr=10.10.0.1
res.0.port=80
```

Das Admin-Passwort wird **nie im Klartext** gespeichert — `admin.ps1` legt nur
den SHA-256-Hash ab.

## Krypto-Container (`.bhvpn`)

```
"BHVPN1." + base64( IV(16) || AES-256-CBC(PKCS7) || HMAC-SHA256(32) )
  encKey = SHA256("bhvpn-enc:" + secret)
  macKey = SHA256("bhvpn-mac:" + secret)
  HMAC   = HMAC-SHA256(macKey, IV || Ciphertext)      (Encrypt-then-MAC)
```

- **Encrypt-then-MAC:** ein falsches Secret oder eine manipulierte Datei wird
  am HMAC erkannt und abgelehnt (kein Entschlüsseln).
- Reine Standard-Kryptografie — identisch in Firmware (mbedtls) und diesem
  Skript (.NET `Aes`/`HMACSHA256`/`SHA256`).

## Sicherheit

- Die `.bhvpn`-Datei enthält **Secrets** (WireGuard-Private-Key, WLAN-Passwort,
  PSK) — nur verschlüsselt weitergeben. Plain-HTTP für den Config-Server ist ok,
  weil der **Inhalt** verschlüsselt ist; das **Secret** selbst wird nie übertragen.
- Secret sicher aufbewahren; wer es hat, kann jede Konfig für die passende SN
  lesen/erstellen.
