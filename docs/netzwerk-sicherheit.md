# Netzwerkverhalten & Sicherheit (erfasst 2026-08-20)

Kurzüberblick, was der Dongle Richtung Host-PC bzw. Richtung WLAN/VPN
durchlässt. Dient der Transparenz und der Wartung.

## Weiterleitung zum Host-PC

- **Kein aktives Port-Forwarding / DNAT.** Das NAT ist reines Masquerade
  (SNAT nach außen, `esp_netif_napt_enable` auf dem USB-Interface). Es kommt
  nur **Rückverkehr** zu Verbindungen zurück, die der Host **selbst**
  aufgebaut hat. Der Dongle exponiert von sich aus **keine** Ports des Hosts.
- **IP-Forwarding ist aktiv** (`CONFIG_LWIP_IP_FORWARD=y`) und es gibt derzeit
  **keine eingehende Firewall / LAN-Isolation**. Folge: Der Host-PC
  (Subnetz `192.168.226.0/29`, Host = `192.168.226.2`) ist von der WLAN- oder
  VPN-Seite **erreichbar, sobald jemand aktiv dorthin routet** (statische
  Route `192.168.226.0/29` via Dongle-STA-/Tunnel-IP). „Nur Rückverkehr" wird
  **nicht** erzwungen.
  - **Bewusst so belassen** — kann für **Fernwartung des Host-PCs** über den
    Dongle nützlich sein (z. B. RDP/SSH zum Host aus dem VPN-Netz, wenn eine
    Route gesetzt wird). Wer strikte Isolation will, siehe „Härtung" unten.

## Dienste des Dongles

- **Web-Interface (HTTP, Port 80):** lauscht auf **allen** Interfaces (USB +
  WLAN-STA + VPN-Tunnel). Damit ist die Oberfläche auch aus dem WLAN, in dem
  der Dongle hängt, und aus dem VPN-Gegenstellen-Netz erreichbar. Öffentliche
  Startseite + WLAN-Einrichtung ohne Login; Konfig-/OTA-Endpunkte per
  HTTP-Basic-Auth (Default `admin/admin` — ändern!).
- **DNS (Port 53):** lauscht zwar auf allen Interfaces, hat aber einen
  **Quellfilter** (`nur 192.168.226.0/29`) — von WLAN/VPN also **nicht**
  nutzbar. Kein offener Resolver.

## Optionale Härtung (derzeit NICHT umgesetzt, bewusst zurückgestellt)

1. **HTTP aufs USB-Interface beschränken** (Quell-IP-Check wie beim DNS) →
   Admin-Oberfläche nur noch vom Host-PC erreichbar.
2. **Eingangs-Firewall / echte LAN-Isolation** (lwIP-Forward-Drop-Hook) →
   von WLAN/VPN kommt nichts Neues Richtung `192.168.226.0/29` durch, nur
   Rückverkehr host-initiierter Flows.

Beides ist ohne funktionale Einbußen nachrüstbar, falls die Fernwartungs-
Erreichbarkeit nicht gewünscht ist.
