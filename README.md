# ESP32-USB-VPN-Dongle

Kleiner USB-Dongle (ESP32-S2 **oder** ESP32-S3), der sich gegenüber Windows/macOS
als **USB-Netzwerkadapter (NCM)** meldet und intern alles übernimmt: WLAN-Client,
DHCP/DNS, NAT/Routing, Captive-Portal-Zwangsanmeldung, WireGuard-Tunnel,
Kill-Switch/Firewall, Web-UI mit Admin-Login, RDP-/Ressourcen-Manager.
Der PC braucht keinen Treiber und keine Konfiguration – nur einstecken.

Vollständige Konzeptbeschreibung: `ESP32-USB-VPN-Dongle.txt`.

## Hardware (zwei unterstützte Boards)
Gleiche Codebasis + Funktionsumfang, Board-Auswahl über PlatformIO-Env bzw.
`flash.ps1 -Board`. **Details/Vergleich: [`docs/hardware-boards.md`](docs/hardware-boards.md).**

- **Wemos S2 Mini** (`lolin_s2_mini`) — ESP32-S2 Single-Core, 4 MB Flash, kein
  PSRAM; Status-LED **KY-016** an GPIO5/6/7; Flashen im Download-Modus.
- **ESP32-S3-DevKitC-1 N16R8** (`esp32-s3-devkitc-1`) — ESP32-S3 Dual-Core, 16 MB
  Flash, **8 MB PSRAM** (~8,4 MB freier Heap); interne **WS2812** an GPIO48;
  Flashen über den UART-Port (Auto-Reset, kein Download-Modus).

LED-Zustände (beide): rot = kein Uplink · blau = WLAN · grün = VPN-Tunnel aktiv.

## Entwicklungsphasen
1. ✅ **USB-NCM Proof-of-Life**: PC sieht Netzwerkadapter, bekommt DHCP
   (192.168.226.1/29, Lease 10 min), kann den ESP pingen + Testseite laden.
   Inkl. OTA-Update übers Webinterface.
2. ✅ **WLAN-Client**: STA mit NVS-Zugangsdaten, Scan + Auswahl im Webinterface,
   Reconnect-Automatik, LED blau bei Verbindung.
3. ✅ **DHCP + DNS + NAT** (USB ↔ WLAN): NAPT-Routing, DHCP nennt DNS-Server.
4. ✅ **Captive Portal** („Netzwerk erfordert Anmeldung"): DNS-Hijack +
   302-Redirect solange gesperrt, Anmelde-/Sperr-Zustand koppelt das Internet.
5. ✅ **WireGuard**: droscy/esp_wireguard, Config über Webinterface + NVS,
   Volltunnel-Schalter (ganzer PC-Verkehr durch VPN), admin-geschützter
   **VPN-AUS-Schalter**. Datenebene HW-verifiziert (PC→Dongle→Tunnel→Internet
   0 % Verlust). *(Fix: `WIREGUARD_MAX_SRC_IPS` – siehe unten.)*
6. ✅ **Kill-Switch + Firewall**: Kill-Switch (kein Internet ohne aktiven
   VPN-Tunnel) + DNS-Quellfilter. *(Offen: echte LAN-Isolation via lwIP-Drop-Hook,
   HTTP-UI nur aufs USB-Interface binden.)*
7. ✅ **Admin-Login + sichere Konfig**: HTTP-Basic-Auth auf allen Steuer-/
   Konfig-Endpunkten, Passwort nur als SHA-256-Hash, Secrets nie im Web/Code.
   *(Offen: NVS-at-rest-Verschlüsselung = Deployment-Härtung.)*
8. ✅ **RDP-/Ressourcen-Manager**: interne Ziele (RDP/Link/SSH) im Webinterface
   pflegen, dynamisch generierte `.rdp`-Datei pro Ziel herunterladen.
9. ✅ **Plug-and-Play-Routing (DHCP Option 121)**: der DHCP-Server des Dongles
   gibt dem PC via Classless Static Routes (RFC 3442) selbst die Routen mit –
   Volltunnel als `0.0.0.0/1`+`128.0.0.0/1` (spezifischer als jede Default-Route,
   gewinnt ohne Metrik-Gefummel), Split als WG-Remote-Subnetz. Kein manuelles
   `route add` mehr nötig; PC braucht nur einen DHCP-Renew (Neu-Einstecken).
   *(HW-verifiziert: PC routet automatisch durch den Tunnel, 0 % Verlust.)*
10. 🔧 Performance/Stabilität. VPN-Durchsatz optimiert von **~1,4 → ~2,7 Mbit/s**
    (SMB-Schreiben, +95 %) durch CPU 240 MHz + Compiler -O2 + lwIP-IRAM; Integrität
    einwandfrei. Grenze ist jetzt der **min-Heap unter Last (~0,5 KB)** plus die
    Software-ChaCha auf dem Single-Core-S2 – die sicheren Software-Hebel sind
    ausgereizt, für 5 Mbit VPN bräuchte es einen ESP32-S3 (mehr RAM + Rechenleistung).
    Details/Messverlauf: `docs/smb-durchsatz-test.md`.

**Treiberlos verifiziert auf Windows, macOS und iPadOS** (NCM-only, CDC-Konsole aus).

**Offen:** echter Split-Tunnel-Datenpfad (Option 121 pusht das WG-Subnetz bereits,
aber die Firmware muss es im Split-Modus noch als `allowed_ip` eintragen);
LAN-Isolation; NVS-Verschlüsselung; Durchsatz-Optimierung.

### Diagnose / Bordmittel
- `GET /diag?ip=<ziel>[&if=wg|any]` (Admin): ICMP-Ping **vom Gerät selbst** durch
  den Tunnel, Ergebnis im CDC-Log – trennt Dongle- von Gegenstellen-Problemen.

### Gotcha: `WIREGUARD_MAX_SRC_IPS`
esp_wireguard setzt die Zahl der Allowed-IPs pro Peer ohne `CONFIG_WIREGUARD_MAX_SRC_IPS`
auf **1**. Der einzige Slot ist schon von der eigenen Tunnel-IP (`/32`) belegt, sodass
`add_allowed_ip(0.0.0.0/0)` keinen freien Slot findet → jeglicher Nutzdaten-Traffic
läuft ins `ERR_RTE` (Handshake steht, Datenebene tot). Fix in `platformio.ini`:
`-DCONFIG_WIREGUARD_MAX_SRC_IPS=8`.

### Status-LED
rot = kein Uplink · blau = WLAN verbunden · grün = VPN-Tunnel aktiv.
S2: KY-016 an GPIO5/6/7. S3: interne WS2812 an GPIO48 (siehe `docs/hardware-boards.md`).

### Hinweis zum Flashen
- **S2:** natives USB reagiert nicht auf esptool-Auto-Reset → Erstflash/Recovery
  im **Download-Modus** (BOOT halten, RST tippen), dann `tools/flash.ps1 -Board S2`.
- **S3:** über den **UART-Port** (Auto-Reset, kein Download-Modus):
  `tools/flash.ps1 -Board S3`.
- **Beide:** danach laufen Updates bequem per **OTA** übers Webinterface.

## Bekannte Risiken (siehe Projekt-Review)
- Zero-Driver-NCM auf allen Windows-Versionen (Inbox-NCM erst ~Win10 2004).
- Single-Core-S2-Durchsatz bei USB+WLAN+WireGuard gleichzeitig (Ziel 5 Mbit VPN).
- Captive-Portal auf USB-Adapter (NCSI/Apple-Probes).
- macOS + DHCP-Option 121 (Split-Tunnel-Routing) evtl. unzuverlässig.

## Bauen / Flashen
ESP-IDF via PlatformIO. `firmware/tools/flash.ps1 -Board <S2|S3>` baut + flasht
direkt (Board-Vergleich + Details: [`docs/hardware-boards.md`](docs/hardware-boards.md));
ausführliche Anleitung (Parameter, Download-Modus, OTA) in
[`firmware/tools/README.md`](firmware/tools/README.md). Die Konfig-Verwaltung
(verschlüsselter Export/Import, Config-Server) beschreibt `admin.ps1` in derselben
README.
