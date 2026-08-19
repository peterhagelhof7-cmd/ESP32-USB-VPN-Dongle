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
5. 🔧 **WireGuard**: droscy/esp_wireguard, Config über Webinterface + NVS,
   Volltunnel-Schalter (ganzer PC-Verkehr durch VPN). *(HW-Verify offen.)*
6. 🔧 **Kill-Switch + Firewall**: Kill-Switch (kein Internet ohne aktiven
   VPN-Tunnel) + DNS-Quellfilter. LAN-Isolation (lwIP-Hook) folgt. *(HW-Verify offen.)*
7. 🔧 **Admin-Login + sichere Konfig**: HTTP-Basic-Auth auf allen Steuer-/
   Konfig-Endpunkten, Passwort nur als SHA-256-Hash, Secrets nie im Web/Code.
   *(HW-Verify offen; NVS-at-rest-Verschlüsselung = Deployment-Härtung.)*
8. 🔧 **RDP-/Ressourcen-Manager**: interne Ziele (RDP/Link/SSH) im Webinterface
   pflegen, dynamisch generierte `.rdp`-Datei pro Ziel herunterladen. *(HW-Verify offen.)*
9. ⬜ Automatischer Verbindungsaufbau (WLAN + WireGuard reconnecten bereits automatisch).
10. ⬜ Performance/Stabilität.

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
ESP-IDF via PlatformIO. Siehe `firmware/tools/flash.ps1` (flasht direkt).
