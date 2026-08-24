# admin.ps1 — Konfig-Werkzeug für den VPN-Dongle

`admin.ps1` erstellt geführt eine gültige Dongle-Konfiguration, verschlüsselt
sie mit dem Konfig-Secret (identisches Format wie die Firmware) und kann eine
verschlüsselte Konfig wieder entschlüsseln/ansehen. Läuft auf **Windows
PowerShell 5.1** (und neuer) ohne Zusatzmodule.

> Dieses Verzeichnis enthält zwei Werkzeuge: **`admin.ps1`** (Konfig erstellen/
> ver- & entschlüsseln, unten) und **`flash.ps1`** (Firmware bauen & flashen,
> siehe [Abschnitt „flash.ps1"](#flashps1--firmware-bauen--flashen) am Ende).

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

# Bearbeiteten Klartext (key=value) wieder verschlüsseln
.\admin.ps1 -Mode encrypt -In config.txt -Out config.json -Secret DEINSECRET20ZEICHEN
```

| Parameter | Bedeutung |
|---|---|
| `-Mode create` | Geführte Erstellung + Verschlüsselung |
| `-Mode encrypt` | Vorhandenen Klartext (`key=value`) verschlüsseln (z. B. nach dem Editieren eines `decrypt`-Ausdrucks) |
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

### Import-Verhalten (Merge)

Beim Einspielen gilt **Merge-Semantik**: Ein Bereich wird nur ersetzt, wenn die
Konfig ihn **enthält**. Fehlt er komplett, bleibt der bestehende Wert am Gerät.

- **WLAN-Liste**: nur ersetzt, wenn `wlan.count` oder `wlan.<n>.*` vorhanden.
  Fehlt der WLAN-Block → bestehende WLANs bleiben. Explizit leeren mit
  `wlan.count=0`.
- **Ressourcen**: analog über `res.count` / `res.<n>.*` (leeren mit `res.count=0`).
- **WireGuard / Systemname / Admin / Version**: pro Feld — vorhandene Zeilen
  überschreiben, fehlende bleiben unverändert.

So kann eine **Teil-Konfig** (z. B. nur ein VPN-Update über den Config-Server)
gefahrlos ausgerollt werden, ohne die WLANs des Geräts zu verlieren; ein
**vollständiges Backup** (das immer alle Bereiche enthält) wird weiterhin
komplett wiederhergestellt.

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

---

# flash.ps1 — Firmware bauen & flashen

`flash.ps1` baut die Dongle-Firmware (PlatformIO/ESP-IDF) und flasht sie auf das
gewählte Board. Läuft auf **Windows PowerShell 5.1** (und neuer); benötigt eine
installierte **PlatformIO Core** (`pio`) im PATH. Board-Vergleich:
[`../../docs/hardware-boards.md`](../../docs/hardware-boards.md).

## Wann brauche ich das?

- **Erstflash** eines leeren/neuen Moduls.
- **Recovery**, falls das Gerät nicht mehr per OTA erreichbar ist (z. B. nach
  einem Boot-Loop).

Im Normalbetrieb sind Updates **ohne** dieses Skript möglich: nach dem Erstflash
meldet sich der Dongle als USB-Netzwerkadapter und wird bequem **per OTA** über
`http://192.168.226.1/` (Einstellungen → OTA) aktualisiert.

## Aufruf

```powershell
# S3 (ESP32-S3-DevKitC-1): bauen + flashen, Port automatisch
.\flash.ps1 -Board S3

# S3 mit erzwungenem Port + seriellem Monitor
.\flash.ps1 -Board S3 -Port COM19 -Monitor

# S2 (Wemos S2 Mini): vorher in den Download-Modus bringen (siehe unten)
.\flash.ps1 -Board S2

# Nur flashen (vorhandenen Build wiederverwenden)
.\flash.ps1 -Board S3 -SkipBuild
```

| Parameter | Bedeutung |
|---|---|
| `-Board <S2\|S3>` | **Pflicht** — Zielboard (S2 = Wemos S2 Mini, S3 = ESP32-S3-DevKitC-1) |
| `-Port <COMx>` | Upload-Port erzwingen (sonst Auto-Erkennung) |
| `-SkipBuild` | Build überspringen, nur den vorhandenen Build flashen |
| `-Monitor` | nach dem Flashen `pio device monitor` öffnen (nur S3 sinnvoll) |

## Board-Besonderheiten beim Flashen

- **S3 (ESP32-S3-DevKitC-1):** über den **UART-Port** flashen (CP210x,
  **Auto-Reset** → kein Download-Modus). Der NCM-Netzadapter erscheint am
  **separaten nativen USB-Port**; serielle Logs am UART-Port.
- **S2 (Wemos S2 Mini):** natives USB-OTG reagiert **nicht** auf den esptool-
  Auto-Reset. Nach dem ersten Flash erscheint er als **Netzwerkadapter statt
  COM-Port**. Zum (Neu-)Flashen daher manuell in den **Download-Modus**:
  1. **BOOT (GPIO0)** halten, 2. **RST** tippen, 3. **BOOT** loslassen.
  Danach erscheint wieder ein serieller Port und das Skript flasht.

Nach dem Flashen **nativen USB-Port einstecken** → der Dongle meldet sich als
Netzwerkadapter, Web-UI unter `http://192.168.226.1/`.
