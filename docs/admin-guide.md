# ESP32-USB-VPN-Dongle — Admin-Guide

Für alle, die einen Dongle aufsetzen, einrichten und betreiben. Stand: Firmware **v1.0.1**.

Der Dongle meldet sich am PC als **USB-Netzwerkadapter** (NCM, ohne Treiber) und erledigt intern
alles Weitere: WLAN-Verbindung, DHCP/DNS, NAT, WireGuard-Tunnel, Kill-Switch, Captive-Portal und eine
Weboberfläche. Der PC muss nichts installieren und nichts konfigurieren.

```
 PC ──USB (NCM)──► Dongle 192.168.226.1 ──WLAN──► Internet
   192.168.226.2     DHCP · DNS · NAT          └─► WireGuard ──► Firmen-/Heimnetz
```

---

## 1. Hardware

Zwei Boards, gleiche Firmware-Funktionen:

| | **Wemos S2 Mini** | **ESP32-S3-DevKitC-1 N16R8** |
|---|---|---|
| SoC | ESP32-S2, 1 Kern | ESP32-S3, 2 Kerne |
| Flash / PSRAM | 4 MB / – | 16 MB / 8 MB |
| Freier RAM im Betrieb | ~50 KB (unter Last knapp) | ~8,4 MB |
| Status-LED | extern KY-016 an GPIO5/6/7 (R/G/B, gemeinsame Kathode) | intern WS2812 an GPIO48 |
| USB | nur der eine USB-C-Port | zwei Ports: **UART** (Flashen, Logs) und **USB** (Netzwerkadapter) |
| Erstes Flashen | Download-Modus von Hand (BOOT + RST) | über den UART-Port, automatisch |

**Empfehlung:** S3 – mehr Reserven, einfacher zu flashen. Der S2 ist kleiner und billiger und läuft
genauso, hat aber unter Volllast kaum freien RAM. Details: [hardware-boards.md](hardware-boards.md).

**LED:** rot = kein Internet-Uplink · blau = WLAN verbunden · grün = VPN-Tunnel steht.

---

## 2. Firmware installieren

### 2.1 Web-Flasher (empfohlen)

**https://peterhagelhof7-cmd.github.io/ESP32-USB-VPN-Dongle/** – in Chrome, Edge oder Opera am
Desktop (Web Serial; Firefox und Safari können das nicht). Der Flasher erkennt S2 oder S3 selbst.

- **S3:** Kabel an den Port **UART** (beim DevKitC-1 beschriftet), „Installieren“, Port wählen.
- **S2:** Erst in den **Download-Modus**: **BOOT** (GPIO0) gedrückt halten, **RST** kurz drücken,
  BOOT loslassen. Dann „Installieren“ und den neu erschienenen Port wählen. Nach dem Flashen einmal
  **RST** drücken – der S2 startet nicht von selbst neu.

„Gerät löschen“ beim ersten Mal anhaken (frischer Speicher); bei einer Neuinstallation gehen damit
alle Einstellungen verloren.

### 2.2 Mit PlatformIO (Entwickler)

```powershell
firmware\tools\flash.ps1 -Board S3            # bauen + flashen über den UART-Port
firmware\tools\flash.ps1 -Board S2            # vorher Download-Modus (BOOT + RST)
```

Parameter und Details: [firmware/tools/README.md](../firmware/tools/README.md).

### 2.3 Updates per OTA

Nach der ersten Installation geht jedes Update über die Weboberfläche: **Einstellungen →
Firmware-Update (OTA)** → `.bin` aus dem [Release](https://github.com/peterhagelhof7-cmd/ESP32-USB-VPN-Dongle/releases)
wählen (die Datei für **dein** Board, `…-S2-…` oder `…-S3-…`) → **Update einspielen**. Alle
Einstellungen bleiben. Startet die neue Firmware nicht sauber, kehrt der Dongle beim nächsten Start
automatisch zur vorigen Version zurück (Rollback).

---

## 3. Erste Einrichtung

1. Dongle an den PC stecken (S3: Port **USB**, nicht UART). Nach wenigen Sekunden erscheint ein neuer
   Netzwerkadapter, der PC bekommt per DHCP `192.168.226.2`.
2. Windows/macOS melden „Anmeldung im Netzwerk erforderlich“ – das ist das **Captive-Portal** des
   Dongles (solange kein WLAN verbunden ist). Draufklicken oder **http://192.168.226.1/** öffnen.
3. **WLAN:** „Netzwerke suchen“, Netz wählen, Passwort eingeben → **WLAN hinzufügen / verbinden**.
   Die LED wird blau, das Internet geht durch.
4. **Admin-Passwort ändern:** Einstellungen (Anmeldung `admin` / `admin`) → **Admin-Zugang** →
   neues Passwort. Solange das Standard-Passwort aktiv ist, steht oben eine rote Warnung.
5. **VPN** einrichten (Abschnitt 5), wenn gewünscht.

**Treiberlos geprüft** auf Windows 10/11, macOS und iPadOS. Windows braucht mindestens
Windows 10 Version 2004 (Inbox-NCM-Treiber).

---

## 4. Weboberfläche

**http://192.168.226.1/** – nur vom PC am Dongle aus gedacht (siehe 8. Sicherheit).

### 4.1 Startseite (ohne Anmeldung)

- **System-Status:** Uplink, WLAN mit Signalstärke, VPN-Status, Firmware.
- **WLAN:** suchen und verbinden. Ohne Anmeldung, damit ein neuer Dongle einrichtbar ist.
- **Ressourcen / Downloads:** die vom Admin angelegten Ziele (RDP-Verbindung als `.rdp`-Datei,
  Links, SSH) und hochgeladene Dateien.

### 4.2 Einstellungen (Anmeldung als Admin)

| Karte | Inhalt |
|---|---|
| **WLAN-Verwaltung** | bis zu **5 WLANs** mit Reihenfolge (= Priorität, „hoch“), löschen. Der Dongle verbindet sich mit dem besten verfügbaren und wechselt bei Verlust selbst. |
| **Internet-Zugang** | Captive-Portal: **Sperren/Freigeben** von Hand, oder **automatisch bei fehlendem WLAN** (Standard). |
| **WireGuard-VPN** | Tunnel-Daten (Abschnitt 5), **Volltunnel**, **Kill-Switch**; **VPN ein-/ausschalten** |
| **Ressourcenmanager** | Ziele anlegen (Name, Typ RDP/Link/SSH, Adresse, Port), Dateien hochladen, freier Speicher |
| **Admin-Zugang** | Benutzer und Passwort (gespeichert nur als SHA-256-Hash) |
| **System** | Systemname, Konfig-Secret, Config-Server-URL |
| **Konfiguration** | Export (verschlüsselt), Import, „Beim Server prüfen“, „Neue Konfig einspielen“ |
| **Firmware-Update (OTA)** | `.bin` hochladen, aktuelle Version und Partition |
| **Zurücksetzen** | nur WLAN, nur VPN, WLAN + VPN oder **alles (Werksreset)** |

---

## 5. WireGuard-VPN

### 5.1 Einrichten

Auf der Gegenstelle (z. B. FritzBox, WireGuard-Server) einen Peer für den Dongle anlegen und dessen
Konfiguration übernehmen:

| Feld im Dongle | aus der WireGuard-Konfiguration |
|---|---|
| Private Key | `[Interface] PrivateKey` |
| Tunnel-IP / Maske | `[Interface] Address`, z. B. `10.10.0.2` / `255.255.255.0` |
| Peer Public Key | `[Peer] PublicKey` |
| Preshared Key | `[Peer] PresharedKey` (falls vorhanden) |
| Endpoint Host/IP + Port | `[Peer] Endpoint`, z. B. `vpn.example.de` / `51820` |
| Keepalive | `PersistentKeepalive`, Empfehlung `25` |

→ **Tunnel speichern + verbinden**. Steht der Tunnel, wird die LED grün und die Startseite zeigt
„VPN verbunden“. Den Private Key zeigt der Dongle nach dem Speichern nie wieder an (Feld leer lassen =
unverändert).

### 5.2 Volltunnel, Split-Tunnel, Kill-Switch

- **Volltunnel an:** der gesamte Verkehr des PCs geht durch das VPN. Der Dongle gibt dem PC die
  Routen per DHCP mit (Option 121: `0.0.0.0/1` + `128.0.0.0/1`), es ist nichts am PC einzustellen.
- **Volltunnel aus:** nur das Netz der Tunnel-IP (z. B. `10.10.0.0/24`) wird dem PC als Route ins VPN
  gemeldet, der Rest geht direkt ins Internet. *Einschränkung v1.0.1:* Der Datenweg für dieses
  Split-Netz ist noch nicht vollständig umgesetzt – für den produktiven Einsatz den Volltunnel nutzen.
- **Kill-Switch an:** ohne stehenden Tunnel kein Internet – nichts geht am VPN vorbei.
- Nach dem Umschalten bekommt der PC die neuen Routen beim nächsten DHCP-Renew (Dongle kurz
  ab- und wieder anstecken).
- macOS beachtet Option 121 nicht immer zuverlässig; der Volltunnel ist dort die sichere Wahl.

### 5.3 Durchsatz

Durch den Tunnel schafft der Dongle **~1,5–1,7 Mbit/s** pro Verbindung und **~2,8 Mbit/s** in Summe,
ohne VPN ~3,6 Mbit/s – bei S2 und S3 gleich. Grenze ist die Software-Verschlüsselung (ChaCha20), für
die beide Chips keine Hardware haben. Gut für Verwaltung, RDP, Web und kleinere Dateien; große
Dateikopien dauern. Messungen: [smb-durchsatz-test.md](smb-durchsatz-test.md).

---

## 6. Ressourcen (RDP, Links, Dateien)

Für Nutzer, die über den Dongle auf interne Ziele zugreifen:

- **RDP:** Name, Adresse, Port (Standard 3389) → auf der Startseite erscheint ein Download, der eine
  fertige `.rdp`-Datei liefert. Doppelklick öffnet die Remotedesktop-Verbindung.
- **Link:** öffnet die Adresse im Browser (ohne `http://` wird es ergänzt).
- **SSH:** zeigt Adresse und Port für den SSH-Client.
- **Dateien:** im Ressourcenmanager hochladen (z. B. eine Anleitung), auf der Startseite herunterladen.
  Platz: ~190 KB (S2) bzw. ~7,7 MB (S3).

Bis zu 12 Ressourcen.

---

## 7. Konfiguration sichern und verteilen

- **Export:** Einstellungen → Konfiguration → Export. Die Datei ist mit dem **Konfig-Secret**
  verschlüsselt (AES-256 + HMAC) und enthält WLANs, VPN, Admin-Hash, Ressourcen und Systemnamen.
  Ohne gesetztes Secret ist kein Export möglich.
- **Import:** die Datei hochladen und einspielen. Es gilt **Merge**: Bereiche, die in der Datei fehlen
  (z. B. keine WLANs), bleiben am Gerät unverändert. Ein vollständiger Export stellt alles wieder her.
- **Config-Server (viele Dongles):** Konfig je Dongle unter `http://<server>/<SN>/config.json`
  ablegen (SN steht unter System). Der Dongle prüft 3 Minuten nach dem WLAN-Connect oder auf
  „Beim Server prüfen“ und bietet eine höhere **Version** zum Einspielen an.
- **Konfig erstellen / ansehen am PC:** `firmware\tools\admin.ps1` (PowerShell, ohne Zusatzmodule) –
  geführt erstellen, verschlüsseln, entschlüsseln. Format und Ablauf:
  [firmware/tools/README.md](../firmware/tools/README.md).

Das Secret (1–20 Zeichen, nur Buchstaben und Ziffern) muss im Dongle und im Werkzeug gleich sein.
Wer es kennt, kann Konfigurationen lesen und erstellen – sicher aufbewahren.

---

## 8. Sicherheit

- **Standard-Passwort `admin`/`admin` sofort ändern.** Es schützt Einstellungen, VPN-Schalter,
  Captive-Portal, OTA und Konfiguration (HTTP-Basic-Auth).
- **Ohne Anmeldung** erreichbar sind die Startseite, die WLAN-Suche und das Hinzufügen eines WLANs
  (für die Ersteinrichtung) sowie die Ressourcen-Downloads.
- Die Weboberfläche läuft per **HTTP ohne TLS** und lauscht auf allen Schnittstellen – auch aus dem
  WLAN, in dem der Dongle hängt, und aus dem VPN-Netz ist sie erreichbar. In fremden WLANs daher ein
  starkes Admin-Passwort verwenden.
- **DNS** des Dongles beantwortet nur Anfragen aus dem USB-Netz (kein offener Resolver).
- **Kein Port-Forwarding:** Von außen kommen nur Antworten auf Verbindungen, die der PC selbst
  aufgebaut hat – außer jemand setzt gezielt eine Route ins USB-Netz `192.168.226.0/29` (bewusst so,
  für Fernwartung des PCs über das VPN). Details: [netzwerk-sicherheit.md](netzwerk-sicherheit.md).
- WireGuard-Private-Key, Preshared Key und WLAN-Passwörter liegen im Flash (NVS) des Dongles,
  **unverschlüsselt**. Wer den Dongle in die Hand bekommt, kann sie auslesen – einen verlorenen
  Dongle auf der Gegenstelle sofort sperren (Peer löschen).

---

## 9. Fehlersuche

**Kein Netzwerkadapter am PC.** S3: am Port **USB**, nicht UART? Kabel mit Datenleitungen? Windows
älter als 10/2004 hat keinen NCM-Treiber. S2 nach dem Flashen: einmal RST drücken.

**Adapter da, aber keine IP.** Dongle ab- und wieder anstecken. Bleibt es bei 169.254.x.x, die
Firmware neu installieren (Web-Flasher, „Gerät löschen“).

**Kein Internet, LED rot.** WLAN nicht verbunden: Startseite → WLAN prüfen, Passwort neu eingeben.
Hotel-/Gast-WLAN mit eigener Anmeldeseite: diese erscheint erst, wenn der Dongle verbunden ist und
das Captive-Portal frei ist.

**LED blau, VPN kommt nicht hoch.** Endpoint und Port erreichbar? Keys vertauscht (beim Dongle steht
der **eigene** Private Key und der **Public Key der Gegenstelle**)? Uhrzeit spielt bei WireGuard keine
Rolle. Manche Gast-WLANs sperren UDP – dann geht kein WireGuard.

**VPN grün, interne Ziele nicht erreichbar.** Volltunnel an? Nach dem Umschalten den Dongle neu
anstecken (neue Routen). Prüfen vom Dongle selbst: `http://192.168.226.1/diag?ip=<ziel>&if=wg`
(Admin) – das Ergebnis steht im seriellen Log (S3: UART-Port, 115200 Baud).

**Kein Internet, obwohl WLAN verbunden.** Kill-Switch an und VPN aus? Dann ist das Absicht.

**Passwort vergessen.** Firmware per Web-Flasher mit „Gerät löschen“ neu installieren – danach gilt
wieder `admin`/`admin`, alle Einstellungen sind weg (vorher exportierte Konfig einspielen).

---

## 10. Lizenz

GPL-3.0 ([LICENSE](../LICENSE)). Enthaltene Fremdkomponenten: esp_wireguard (BSD-3-Clause,
`firmware/components/esp_wireguard/LICENSE`), libsodium (ISC), esp_tinyusb und ESP-IDF (Apache-2.0).
