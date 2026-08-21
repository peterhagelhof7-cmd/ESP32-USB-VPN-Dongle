# SMB-Durchsatztest durch den WireGuard-Tunnel

**Datum:** 2026-08-21
**Aufbau:** PC → USB-VPN-Dongle (Wemos S2 Mini) → WLAN → WireGuard-Volltunnel → FritzBox-Remote-LAN
**Ziel:** SMB-Freigabe `\\10.10.0.10\temp`, Netz `10.10.0.0/24` (nur über den Tunnel erreichbar)
**Methode:** Zufällige (nicht komprimierbare) Testdateien lokal erzeugt, per `Copy-Item` auf die Freigabe geschrieben (SCHREIBEN) und wieder zurückgelesen (LESEN), Zeit per `Stopwatch`, Integrität per SHA-256-Vergleich (Original ↔ zurückgelesen).

## Vorprüfung

| Prüfung | Ergebnis |
|---|---|
| Route zu 10.10.0.10 | über den Dongle-Tunnel (nicht lokal erreichbar) |
| TCP 445 (SMB) | offen, Server antwortet |
| Anmeldung | erfolgreich |

## Ergebnisse

| Datei | Schreiben (MB/s) | Schreiben (Mbit/s) | Lesen (MB/s) | Lesen (Mbit/s) | Integrität |
|---|---|---|---|---|---|
| 10 MB  | 0,17 | 1,36 | 0,22 | 1,72 | OK (SHA-256 identisch) |
| 100 MB | 0,24 | 1,90 | 0,27 | 2,16 | OK (SHA-256 identisch) |

Rohwerte 10 MB:
- SCHREIBEN: 10,0 MB in 58,67 s = 0,17 MB/s (1,36 Mbit/s)
- LESEN: 10,0 MB in 46,49 s = 0,22 MB/s (1,72 Mbit/s)
- Integrität: OK (identisch)

Rohwerte 100 MB:
- SCHREIBEN: 100,0 MB in 421,06 s = 0,24 MB/s (1,90 Mbit/s)
- LESEN: 100,0 MB in 370,53 s = 0,27 MB/s (2,16 Mbit/s)
- Integrität: OK (identisch)

## Bewertung

- **Datenintegrität einwandfrei** – zurückgelesene Datei bit-genau identisch (SHA-256), der Tunnel überträgt fehlerfrei.
- **Durchsatz sehr niedrig (~1,4–1,7 Mbit/s)** und liegt deutlich unter dem Projektziel von 5 Mbit/s für VPN.
- Ursache ist die **Single-Core-Grenze des ESP32-S2**: USB-NCM + WLAN + WireGuard-ChaCha20 (ohne Krypto-Hardwarebeschleuniger) laufen gemeinsam auf einem Kern; SMB kommt zusätzlich mit vielen kleinen Round-Trips (latenzempfindlich über den Tunnel). Das ist der bekannte offene Punkt aus Phase 10 (Performance/Stabilität).
- Lesen durchgehend etwas schneller als Schreiben (RX-Pfad günstiger als der TX-/SNAT-Pfad).
- Die größere Datei ist minimal schneller (100 MB ~1,9–2,2 Mbit/s vs. 10 MB ~1,4–1,7 Mbit/s): der pro-Transfer-Overhead (SMB-Setup) amortisiert sich, die Rate bleibt aber im selben niedrigen Band – die Grenze ist der Dauerdurchsatz, nicht der Startaufwand.
- **Fazit (Baseline):** Für Verwaltungszugriffe/kleine Dateien und RDP-Steuerung nutzbar, aber **nicht für große SMB-Kopien** geeignet.

---

## Optimierung (Phase 10)

Analyse: Der Durchsatz ist **compute-/krypto-gebunden** – WireGuard ChaCha20-Poly1305
läuft rein in Software (der ESP32-S2 hat keinen ChaCha-Beschleuniger) und der Code
wird über den Instruction-Cache aus dem Flash ausgeführt. lwIP-TCP-Fenster sind
**irrelevant**, weil der Dongle kein TCP terminiert, sondern nur verschlüsselt/routet.

Angewandte Stellschrauben (alle ohne DRAM-Kosten – der min-Heap dippt unter Last
auf **~0,5 KB**, jede DRAM-fressende Maßnahme wie ein 16-KB-I-Cache würde einen
Boot-/Last-OOM auslösen):

1. **CPU 160 → 240 MHz** – voller Takt, ~linear mehr Krypto-Durchsatz.
2. **Compiler -Og (Debug) → -O2 (Performance)** – beschleunigt die ChaCha/Poly-
   Innenschleifen deutlich.
3. **lwIP-IRAM-Optimierung** – Forwarding-Hotpath (ip4_forward/NAPT) ins IRAM
   (separater Heap, kostet **kein** DRAM) → weniger Flash-Cache-Stalls je Paket.

Verworfen: 16-KB-Instruction-Cache (kostet ~8 KB DRAM → OOM-Risiko bei ~0,5 KB
min-Heap) und Flash-Modus DIO→QIO (kann den Boot des S2-Mini brechen, Recovery nur
physisch). WG-Krypto per Linker-Fragment ins IRAM: nicht umsetzbar, da esp_wireguard
als PlatformIO-lib außerhalb des IDF-Komponentengraphen gelinkt wird (`ldgen` erfasst
die Archiv-Objekte nicht).

### Messverlauf (10 MB, gleicher Aufbau)

| Build | CPU / Compiler | Schreiben | Lesen |
|---|---|---|---|
| Baseline (`cfg-merge`) | 160 MHz / -Og | 1,36 Mbit/s | 1,72 Mbit/s |
| `perf-240-o2` | 240 MHz / -O2 | 2,31 Mbit/s | 2,78 Mbit/s |
| `perf2-lwipiram` | 240 MHz / -O2 + lwIP-IRAM | **2,65 Mbit/s** | **2,89 Mbit/s** |
| **Gewinn gesamt** | | **+95 %** | **+68 %** |

Integrität in allen Läufen bit-genau (SHA-256).

### Wo die Grenze liegt

Der **min-Heap unter Last (~0,5 KB)** ist die harte Wand: Der Forwarding-Pfad
alloziert pro Paket (u. a. der USB-RX-`memcpy`), sodass größere Puffer oder ein
größerer Cache das Gerät ins OOM treiben würden. Damit sind die **sicheren
Software-Hebel auf dem S2 ausgereizt** (Schreibrate praktisch verdoppelt).

**Für das 5-Mbit-Ziel** ist ein **ESP32-S3** die realistische Option: mehr RAM
gegen die Heap-Wand *und* mehr Rechenleistung (höherer Takt / Dual-Core) für die
ChaCha-Software-Krypto. Der S2 ist auf ~2,5–3 Mbit/s praktisch am Limit.
