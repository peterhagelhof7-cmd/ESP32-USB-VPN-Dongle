# ESP32-USB-VPN-Dongle

Kleiner USB-Dongle (ESP32-S2 **oder** ESP32-S3), der sich an Windows, macOS und iPadOS als
**USB-Netzwerkadapter** meldet – ohne Treiber – und intern alles übernimmt: WLAN-Verbindung,
DHCP/DNS, NAT, **WireGuard-VPN** mit Kill-Switch, Captive-Portal und eine Weboberfläche mit
Admin-Login. Der PC muss nichts installieren und nichts konfigurieren: einstecken, fertig.

**Aktuelle Version: v1.0.1** · Lizenz GPL-3.0

> **Loslegen:** Firmware direkt aus dem Browser installieren mit dem
> **[Web-Flasher](https://peterhagelhof7-cmd.github.io/ESP32-USB-VPN-Dongle/)** (Chrome/Edge),
> danach `http://192.168.226.1/` öffnen. Ausführliche Anleitung:
> **[docs/admin-guide.md](docs/admin-guide.md)**.

```
 PC ──USB (NCM)──► Dongle 192.168.226.1 ──WLAN──► Internet
   192.168.226.2     DHCP · DNS · NAT          └─► WireGuard ──► Firmen-/Heimnetz
```

## Funktionen

- **Treiberloser USB-Netzwerkadapter** (NCM) – geprüft auf Windows 10/11, macOS und iPadOS
- **WLAN-Client** mit bis zu 5 gespeicherten Netzen (Priorität, automatischer Wechsel), Suche und
  Signalstärke in der Weboberfläche
- **NAT/Routing, DHCP und DNS** für den PC
- **WireGuard-VPN** mit **Volltunnel** und **Kill-Switch**; die Routen bekommt der PC per DHCP
  (Option 121) automatisch mit, ohne Eingriff am PC
- **Captive-Portal:** ohne WLAN meldet der PC „Anmeldung erforderlich“ und landet direkt in der
  WLAN-Einrichtung; manuell sperren/freigeben möglich
- **Weboberfläche** mit Admin-Login (Passwort nur als Hash), Status-LED (rot/blau/grün)
- **Ressourcen:** RDP-Ziele als fertige `.rdp`-Datei, Links, SSH-Ziele und Datei-Downloads für die
  Nutzer des Dongles
- **Konfiguration** verschlüsselt exportieren/importieren (AES-256 + HMAC), zentral verteilen über
  einen Config-Server; Werkzeug `admin.ps1` für den PC
- **OTA-Update** übers Webinterface mit automatischem Rollback

## Hardware

| | **Wemos S2 Mini** | **ESP32-S3-DevKitC-1 N16R8** (empfohlen) |
|---|---|---|
| SoC | ESP32-S2, 1 Kern | ESP32-S3, 2 Kerne |
| Flash / PSRAM | 4 MB / – | 16 MB / 8 MB |
| Status-LED | KY-016 an GPIO5/6/7 | intern (WS2812, GPIO48) |
| Flashen | Download-Modus (BOOT + RST) | über den UART-Port, automatisch |

Gleiche Firmware-Funktionen auf beiden. Vergleich und Details:
[docs/hardware-boards.md](docs/hardware-boards.md), Verkabelung der LED am S2: [verkabelung.txt](verkabelung.txt).

## Grenzen

- **VPN-Durchsatz ~1,5–1,7 Mbit/s** pro Verbindung, ~2,8 Mbit/s in Summe (S2 und S3 gleich) – die
  WireGuard-Verschlüsselung läuft in Software. Für Verwaltung, RDP, Web und kleinere Dateien;
  große Dateikopien dauern. Messungen: [docs/smb-durchsatz-test.md](docs/smb-durchsatz-test.md).
- **Split-Tunnel** (nur das VPN-Netz durch den Tunnel): Die Route geht schon per DHCP an den PC, der
  Datenweg in der Firmware ist aber noch nicht vollständig – produktiv den Volltunnel nutzen.
- Weboberfläche per HTTP ohne TLS, lauscht auf allen Schnittstellen; Zugangsdaten liegen
  unverschlüsselt im Flash. Siehe Admin-Guide, Abschnitt 8, und
  [docs/netzwerk-sicherheit.md](docs/netzwerk-sicherheit.md).

## Installation

- **Web-Flasher:** https://peterhagelhof7-cmd.github.io/ESP32-USB-VPN-Dongle/ – erkennt S2/S3 selbst.
- **Update:** im Webinterface unter Firmware-Update (OTA) die `.bin` für das eigene Board aus den
  [Releases](https://github.com/peterhagelhof7-cmd/ESP32-USB-VPN-Dongle/releases) einspielen.
- **PlatformIO:** `firmware\tools\flash.ps1 -Board <S2|S3>` baut und flasht
  ([firmware/tools/README.md](firmware/tools/README.md)).

## Bauen

ESP-IDF über PlatformIO, Envs `lolin_s2_mini` und `esp32-s3-devkitc-1`:

```powershell
cd firmware
pio run -e esp32-s3-devkitc-1
pio run -e lolin_s2_mini
```

Web-Flasher-Dateien aus einem Build erzeugen: `tools\webflasher-update.ps1` (siehe Kopf des Skripts).

### Gotcha: `WIREGUARD_MAX_SRC_IPS`

esp_wireguard setzt die Zahl der Allowed-IPs pro Peer ohne `CONFIG_WIREGUARD_MAX_SRC_IPS` auf **1**.
Der einzige Slot ist schon von der eigenen Tunnel-IP (`/32`) belegt, `add_allowed_ip(0.0.0.0/0)`
findet keinen freien Slot → jeder Nutzdaten-Traffic läuft ins `ERR_RTE` (Handshake steht,
Datenebene tot). Fix in `platformio.ini`: `-DCONFIG_WIREGUARD_MAX_SRC_IPS=8`.

### Diagnose

`GET /diag?ip=<ziel>[&if=wg|any]` (Admin): ICMP-Ping **vom Dongle selbst** durch den Tunnel,
Ergebnis im seriellen Log – trennt Dongle- von Gegenstellen-Problemen.

## Entwicklung

Konzept: [`ESP32-USB-VPN-Dongle.txt`](ESP32-USB-VPN-Dongle.txt). Umgesetzt in Phasen: USB-NCM →
WLAN → DHCP/DNS/NAT → Captive-Portal → WireGuard → Kill-Switch/Firewall → Admin-Login und
verschlüsselte Konfig → Ressourcen-Manager → DHCP-Option-121-Routing → Performance (CPU 240 MHz,
`-O2`, lwIP-IRAM: VPN-Durchsatz von ~1,4 auf ~2,7 Mbit/s) → Port auf den ESP32-S3.
Konzept einer Dual-Core-Verschlüsselung (nicht umgesetzt):
[docs/dualcore-wg-krypto-konzept.md](docs/dualcore-wg-krypto-konzept.md).

## Lizenz

GPL-3.0, siehe [LICENSE](LICENSE). Enthalten bzw. genutzt: esp_wireguard (BSD-3-Clause,
[firmware/components/esp_wireguard/LICENSE](firmware/components/esp_wireguard/LICENSE)),
libsodium (ISC), esp_tinyusb und ESP-IDF (Apache-2.0).
