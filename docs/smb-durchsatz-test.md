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
- **Fazit:** Für Verwaltungszugriffe/kleine Dateien und RDP-Steuerung nutzbar, aber **nicht für große SMB-Kopien** geeignet. Für höheren Durchsatz wäre ein Dual-Core-Modul mit Krypto-Beschleunigung (ESP32-S3) die Option (im Konzept als Risiko 2 vermerkt).
