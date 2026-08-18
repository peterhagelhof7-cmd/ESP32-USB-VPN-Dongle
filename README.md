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
1. **USB-NCM Proof-of-Life** ← *aktuell*: PC sieht Netzwerkadapter, bekommt DHCP
   (192.168.226.1/29, Lease 10 min), kann den ESP pingen + Testseite laden.
2. WLAN-Client.
3. DHCP + DNS + NAT (USB ↔ WLAN).
4. Captive Portal („Netzwerk erfordert Anmeldung").
5. WireGuard (Split-/Full-Tunnel via DHCP Option 121).
6. Kill-Switch + Firewall.
7. Admin-Login + sichere Konfig-Speicherung (Keys nie im Web/Code).
8. RDP-/Ressourcen-Manager.
9. Automatischer Verbindungsaufbau.
10. Performance/Stabilität.

## Bekannte Risiken (siehe Projekt-Review)
- Zero-Driver-NCM auf allen Windows-Versionen (Inbox-NCM erst ~Win10 2004).
- Single-Core-S2-Durchsatz bei USB+WLAN+WireGuard gleichzeitig (Ziel 5 Mbit VPN).
- Captive-Portal auf USB-Adapter (NCSI/Apple-Probes).
- macOS + DHCP-Option 121 (Split-Tunnel-Routing) evtl. unzuverlässig.

## Bauen / Flashen
ESP-IDF via PlatformIO. Siehe `firmware/tools/flash.ps1` (flasht direkt).
