# Hardware-Boards: ESP32-S2 und ESP32-S3

Die Dongle-Firmware unterstützt **zwei Boards** aus derselben Codebasis (gleicher
Funktionsumfang). Die Board-Auswahl erfolgt über den PlatformIO-Env bzw.
`flash.ps1 -Board`.

| | **Wemos S2 Mini** (`S2`) | **ESP32-S3-DevKitC-1 N16R8** (`S3`) |
|---|---|---|
| PlatformIO-Env | `lolin_s2_mini` | `esp32-s3-devkitc-1` |
| SoC | ESP32-S2 (Single-Core) | ESP32-S3 (Dual-Core) |
| Takt | 240 MHz | 240 MHz |
| Flash | 4 MB | 16 MB |
| PSRAM | – | 8 MB Octal |
| Laufzeit-Heap (frei) | ~50 KB (min ~0,7 KB unter Last) | **~8,4 MB** |
| Status-LED | KY-016 (extern), GPIO5/6/7 = R/G/B | interne **WS2812** (GPIO48) |
| USB | nur natives USB-OTG | natives USB-OTG **+ separater UART-Port** |
| Flashen | Download-Modus (BOOT+RST) | **UART-Port, Auto-Reset** |
| Serielle Logs | – (NCM-only, keine Konsole) | UART-Port (z. B. COM19) |

Funktional identisch: USB-NCM, WLAN-Uplink, NAT/DNS, Captive-Portal, WireGuard
(inkl. Volltunnel/Kill-Switch), Web-UI, RDP-/Ressourcen-Manager, OTA,
DHCP-Option-121-Routing, Konfig-Export/Import, WLAN-Multiprofil + RSSI-Anzeige.

## Board-Unterschiede im Detail

### Status-LED
- **S2 – KY-016 (gemeinsame Kathode, HIGH = an):** R=GPIO5, G=GPIO6, B=GPIO7.
- **S3 – interne WS2812 an GPIO48:** angesteuert direkt über den RMT-Treiber
  (`driver/rmt_tx.h` + Bytes-Encoder). Die `led_strip`-Komponente wird **nicht**
  genutzt (ihr SPI-Backend kompiliert nicht mit ESP-IDF 6.0.1). **Farbreihenfolge
  dieses Boards ist RGB** (nicht das Standard-WS2812-GRB) → die Firmware sendet
  R,G,B (HW-Befund).

Zustände (beide): **rot** = kein Uplink · **blau** = WLAN verbunden · **grün** =
VPN-Tunnel aktiv.

### PSRAM (nur S3)
`sdkconfig.defaults.esp32s3` aktiviert Octal-PSRAM (8 MB) und legt WiFi-/lwIP-
Puffer ins PSRAM. Damit ist der interne-RAM-Engpass des S2 (min-Heap ~0,7 KB unter
Last) auf dem S3 vollständig entschärft.

### Flashen
- **S2:** natives USB reagiert **nicht** auf esptool-Auto-Reset → vor jedem Flash
  in den **Download-Modus** (BOOT/GPIO0 halten, RST tippen, BOOT loslassen). Nach
  dem Flash meldet sich der S2 als USB-Netzadapter (kein COM-Port mehr).
- **S3:** über den **UART-Port** flashen (CP210x, Auto-Reset) → **kein**
  Download-Modus nötig. Der NCM-Netzadapter erscheint am **separaten nativen
  USB-Port**; serielle Logs am UART-Port.
- **Beide:** nach dem Erstflash laufen Updates bequem per **OTA** über
  `http://192.168.226.1/` (Einstellungen → Firmware-Update).

## Bauen & Flashen

```powershell
# S3 bauen + flashen (Port automatisch; UART-Port, Auto-Reset)
firmware\tools\flash.ps1 -Board S3

# S3 mit erzwungenem Port und Monitor
firmware\tools\flash.ps1 -Board S3 -Port COM19 -Monitor

# S2 (vorher in den Download-Modus bringen!)
firmware\tools\flash.ps1 -Board S2
```

Reine PlatformIO-Befehle:

```powershell
pio run -e esp32-s3-devkitc-1            # S3 bauen
pio run -e lolin_s2_mini                 # S2 bauen
pio run -e esp32-s3-devkitc-1 -t upload  # S3 flashen
```

## Durchsatz

Beide Boards liefern durch den WireGuard-Volltunnel ~1,5–1,7 Mbit/s (Einzelstream)
bzw. ~2,8 Mbit/s aggregiert. Grenze ist die **Software-ChaCha20-Krypto** (kein
HW-Beschleuniger); esp_wireguard verschlüsselt single-core inline → der zweite
S3-Kern hilft hier nicht. Einzelstream ist zusätzlich fenster-/latenzbegrenzt.
Details + Konzept einer möglichen Dual-Core-Parallelisierung:
`docs/smb-durchsatz-test.md` und `docs/dualcore-wg-krypto-konzept.md`.

Der praktische Gewinn des S3 liegt daher **nicht** im VPN-Durchsatz, sondern im
**RAM-Headroom** (~8,4 MB Heap statt ~50 KB) und im **komfortableren Flashen**
(UART-Port statt Download-Modus).
