# ESP32-USB-VPN-Dongle

Kleiner USB-Dongle (Wemos **S2 Mini** / ESP32-S2), der sich gegenüber Windows/macOS
als **USB-Netzwerkadapter (NCM)** meldet und intern alles übernimmt: WLAN-Client,
DHCP/DNS, NAT/Routing, Captive-Portal-Zwangsanmeldung, WireGuard-Tunnel,
Kill-Switch/Firewall, Web-UI mit Admin-Login, RDP-/Ressourcen-Manager.
Der PC braucht keinen Treiber und keine Konfiguration – nur einstecken.

Vollständige Konzeptbeschreibung: `ESP32-USB-VPN-Dongle.txt`.

## Hardware
- **Wemos S2 Mini** (ESP32-S2, natives USB-OTG, USB-C, 4 MB Flash).
- Status-LED **KY-016** (RGB): rot = WLAN+VPN aus, blau = WLAN, grün = VPN.

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
10. 🔧 Performance/Stabilität. Gemessener VPN-Durchsatz aktuell **~1,4–2,2 Mbit/s**
    (SMB durch den Tunnel, Datenintegrität einwandfrei) – unter dem Ziel von
    5 Mbit VPN; Grenze ist der Single-Core-S2 (USB+WLAN+ChaCha ohne Krypto-HW).
    Details: `docs/smb-durchsatz-test.md`.

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

### Status-LED (KY-016)
rot = kein Uplink · blau = WLAN verbunden · grün = VPN-Tunnel aktiv.

### Hinweis zum Flashen
Der S2 (natives USB) reagiert nicht auf esptool-Auto-Reset. Nach dem Erstflash
laufen Updates bequem per **OTA** übers Webinterface. Für den Erstflash bzw. zur
Recovery: Download-Modus (BOOT halten, RST tippen), dann `tools/flash.ps1`.

## Bekannte Risiken (siehe Projekt-Review)
- Zero-Driver-NCM auf allen Windows-Versionen (Inbox-NCM erst ~Win10 2004).
- Single-Core-S2-Durchsatz bei USB+WLAN+WireGuard gleichzeitig (Ziel 5 Mbit VPN).
- Captive-Portal auf USB-Adapter (NCSI/Apple-Probes).
- macOS + DHCP-Option 121 (Split-Tunnel-Routing) evtl. unzuverlässig.

## Bauen / Flashen
ESP-IDF via PlatformIO. `firmware/tools/flash.ps1` baut + flasht direkt;
ausführliche Anleitung (Parameter, Download-Modus, OTA) in
[`firmware/tools/README.md`](firmware/tools/README.md). Die Konfig-Verwaltung
(verschlüsselter Export/Import, Config-Server) beschreibt `admin.ps1` in derselben
README.
