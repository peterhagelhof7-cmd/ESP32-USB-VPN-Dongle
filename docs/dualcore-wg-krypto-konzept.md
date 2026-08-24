# Konzept: Dual-Core-WireGuard-Krypto auf dem ESP32-S3

**Ziel:** den VPN-Durchsatz des Dongle auf dem ESP32-S3 anheben, indem die
WireGuard-Software-Krypto (ChaCha20-Poly1305) auf **beide CPU-Kerne** verteilt
wird. Stand: Konzept/Entscheidungsvorlage — noch keine Umsetzung.

## 1. Messgrundlage (S3-N16R8, 2026-08-24)

| Pfad | Durchsatz |
|---|---|
| Reiner NAT (ohne VPN), 1 Stream | ~3,6 Mbit/s |
| WG-Tunnel, 1 Stream | ~1,5–1,7 Mbit/s |
| WG-Tunnel, 4 Streams (aggregiert) | ~2,8 Mbit/s (harte Decke) |

**Deutung:** Der Tunnel halbiert den Durchsatz (3,6 → 1,7). Parallele Streams
holen mehr, laufen aber bei **~2,8 Mbit/s aggregiert** gegen eine Wand → das ist
die **ESP-Krypto-/Forwarding-Grenze**, nicht WLAN (3,6) oder USB (FullSpeed ~9–10).
Der ESP32-S3 hat **keinen HW-Beschleuniger für ChaCha20/Poly1305/BLAKE2s**; die
Krypto läuft rein in Software. S2 ≈ S3, weil esp_wireguard die Krypto **einkernig,
inline** im lwIP-Kontext macht — der zweite S3-Kern liegt brach.

## 2. Ist-Architektur (esp_wireguard, droscy-Fork)

Die Krypto steckt inline im Datenpfad in `wireguardif.c`:

- **TX (raus):** lwIP-Forward → `wireguardif_output` → Transport-Data-Message
  bauen, **`wireguardif_encrypt`** (ChaCha20-Poly1305, monoton steigende Nonce
  aus dem Sende-Keypair-Zähler) → UDP-Send über das STA-netif.
- **RX (rein):** UDP-Callback → `wireguardif_recv` → **`wireguardif_decrypt`** →
  Nonce gegen das **Replay-Fenster** prüfen → Klartext an netif-Input.

Alles im **tcpip-Task auf einem Kern**. Der teure Teil je Paket ist die
ChaCha20-Poly1305-Transformation über die Nutzlast (~1,4 KB); Nonce-Vergabe,
Header und UDP-Send sind billig.

## 3. Kernidee

WireGuard toleriert **Umsortierung** innerhalb eines Replay-Fensters (Default
~2000 Pakete). Das erlaubt es, die teure Krypto **parallel** auf mehreren Workern
zu rechnen, solange die **ordnungskritischen Mini-Schritte serialisiert** bleiben:

- **TX:** Nonce/Zähler unter Lock vergeben (billig, in Reihenfolge), dann
  `(pbuf, nonce, key)` an einen **Worker-Pool auf Core 1** geben. Worker rechnen
  ChaCha20-Poly1305 parallel; das fertige Paket wird per UDP gesendet
  (Reihenfolge unkritisch — Empfänger hat Replay-Fenster).
- **RX:** eingehende verschlüsselte Pakete an Worker verteilen; jeder
  entschlüsselt parallel und prüft/aktualisiert das **Replay-Fenster unter Lock**;
  gültiger Klartext → netif-Input.

→ Die ChaCha-Rechenzeit verteilt sich auf 2 Kerne, die Krypto-Decke steigt
theoretisch **~2×** (~2,8 → ~5 Mbit/s aggregiert).

## 4. Umsetzungsvarianten

**A) Worker-Pool (empfohlen für maximalen Durchsatz).**
1 Krypto-Worker-Task auf Core 1 (optional 2), Jobs über eine FreeRTOS-Queue.
TX+RX profitieren. Höchstes Potenzial, höchste Komplexität (Reihenfolge, Locking).

**B) Pipeline-Split (einfacher).**
RX-Decrypt fest auf Core 1, TX-Encrypt auf Core 0 (oder umgekehrt). Kein
Umsortier-/Reassembly-Problem je Richtung, TX und RX laufen echt nebenläufig.
Gewinn v.a. bei **bidirektionalem** Verkehr (SMB!); bei reinem Download arbeitet
nur der RX-Kern → ~kein Gewinn.

**C) Kombination:** Pipeline-Split als Basis, plus Worker-Pool je Richtung.

## 5. Empfehlung: gestuft

- **Stufe 1 — Optimierte ChaCha (single-core, geringes Risiko, ZUERST).**
  esp_wireguard nutzt die **Referenz-C-ChaCha** (`crypto/refc/chacha20.c`). Eine
  für Xtensa optimierte ChaCha/Poly1305-Implementierung (bzw. die aus libsodium,
  die ohnehin mitgebaut wird) hebt die Decke schätzungsweise **+20–40 %** — ohne
  Nebenläufigkeit, ohne Reihenfolge-/Locking-Risiko. Bester Aufwand/Nutzen als
  erster Schritt.
- **Stufe 2 — Dual-Core-Worker-Pool (Variante A/C).** Der eigentliche B-Schritt:
  ~2× Aggregat-Durchsatz, aber der große Eingriff.

## 6. Herausforderungen & Risiken

1. **esp_wireguard muss vendored/gepatcht werden** — die Krypto ist tief in
   `wireguardif.c` inline. Der „pristine lib via lib_deps"-Ansatz entfällt; die
   Lib muss ins Projekt kopiert und der Datenpfad refaktoriert werden.
2. **pbuf-Ownership über Task-/Kern-Grenzen** — Refcounting; der finale UDP-Send
   bzw. netif-Input muss unter **LOCK_TCPIP_CORE** laufen (lwIP ist außerhalb des
   tcpip-Tasks nicht thread-safe). Krypto parallel, Send/Input serialisiert unter
   Lock (billig).
3. **Reihenfolge/Replay:** TX-Nonce-Vergabe und RX-Replay-Fenster streng unter
   Lock; sonst Nonce-Reuse (fatal!) oder falsche Replay-Drops.
4. **Latenz vs. Durchsatz:** Worker-Dispatch kostet Latenz je Paket → hilft
   **Aggregat**-Durchsatz, aber der **Einzelstream** (SMB!) ist fenster-/latenz-
   begrenzt und profitiert evtl. wenig. Für Einzelstream separat **MSS-Clamping/
   Fenster** betrachten. Ggf. kleine Pakete auf dem schnellen Inline-Pfad lassen.
5. **Korrektheit/Sicherheit:** Krypto-Datenpfad — Bugs = korrumpierte Pakete oder
   Nonce-Reuse. Erfordert sorgfältige Tests (Integrität, Langlauf, Replay).
6. **Speicher:** Queues/Job-Puffer ins PSRAM (auf dem S3 reichlich).

## 7. Aufwand & erwarteter Gewinn

| | Aufwand | Erwarteter Gewinn (aggregiert) | Risiko |
|---|---|---|---|
| Stufe 1 (opt. ChaCha) | klein–mittel | +20–40 % | niedrig |
| Stufe 2 (Dual-Core) | groß (mehrere Tage) | bis ~2× | mittel–hoch (Krypto-Pfad) |

Einzelstream/SMB profitiert v.a. von zusätzlichem MSS-/Fenster-Tuning, nicht
allein von der Parallelisierung.

## 8. Vorgehen (wenn freigegeben)

1. esp_wireguard ins Projekt vendoren (aus dem lib_deps-Fork), Build umstellen.
2. **Stufe 1**: ChaCha/Poly1305 gegen optimierte Variante tauschen, HW-Test
   (Durchsatz + Integrität + Langlauf). Rollback = aktuelles OTA-Image.
3. **Stufe 2**: Krypto-Job-Queue + Worker auf Core 1, TX-Nonce-/RX-Replay-Locking,
   Send/Input unter Core-Lock. Schrittweise (erst TX, dann RX), je mit HW-Test.
4. Messreihe (1/2/4/8 Streams + SMB) vor/nach jeder Stufe; Integrität bei jedem
   Lauf per Hash prüfen.

**Jede Stufe wird einzeln gebaut, geflasht und gemessen — und nur auf deine
ausdrückliche Freigabe.**
