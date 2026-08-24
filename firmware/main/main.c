/*
 * ESP32-USB-VPN-Dongle — Phase 1: USB-NCM Proof-of-Life
 *
 * Der ESP32-S2 meldet sich als USB-Netzwerkadapter (NCM). Er stellt ein eigenes
 * kleines Subnetz 192.168.226.0/29 bereit (ESP = .1), verteilt per DHCP eine
 * Adresse an den PC (Lease 10 min) und liefert eine Testseite unter
 * http://192.168.226.1/. Damit ist das riskante Fundament (treiberloser
 * USB-Netzwerkadapter + DHCP + HTTP) validierbar, bevor WLAN/NAT/WireGuard folgen.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "ping/ping_sock.h"
#include "esp_wireguard.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS   // schaltet die mbedtls_aes_*-Deklarationen frei (IDF6/mbedtls4)
#include "mbedtls/private/aes.h"   // aes.h nur unter private/ (Include-Pfad in CMakeLists)
#include "esp_random.h"
#include "esp_http_client.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_core_dump.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_spiffs.h"
#include "driver/gpio.h"
#include <dirent.h>
#include <sys/stat.h>

#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_net.h"
#if defined(CONFIG_TINYUSB_CDC_ENABLED) && CONFIG_TINYUSB_CDC_ENABLED
#include "tinyusb_cdc_acm.h"
#include "tinyusb_console.h"
#endif

static const char *TAG = "usbvpn";

// DIAGNOSE: 1 = USB-Empfang NICHT an esp_netif weiterreichen (nur zaehlen).
#define DIAG_NO_NETIF_RX 0
// DIAGNOSE: 1 = TX verwerfen (send_sync nicht aufrufen) -> Deadlock-Test.
#define DIAG_TX_NOOP 0
// Sichtbarer Build-Marker (Beleg, welches Image nach OTA laeuft).
#define FW_BUILD_TAG "captive-auto"
static volatile uint32_t s_rx_count;

// Status-LED: board-abhaengig implementiert (siehe led_set/led_init weiter unten).
static esp_netif_t *s_usb_netif;

// --- WLAN-Uplink (STA) Zustand ---
static esp_netif_t   *s_sta_netif;
static char           s_wifi_ssid[33];   // aktuell angesteuerte SSID
static char           s_wifi_pass[64];
// Mehrere bekannte WLANs, Reihenfolge = Prioritaet (0 = hoechste). Der Manager
// verbindet mit dem hoechstprioren VERFUEGBAREN und wechselt bei Bedarf.
#define MAX_WLAN 5
typedef struct { char ssid[33]; char pass[64]; } wlan_t;
static wlan_t         s_wlans[MAX_WLAN];
static int            s_wlan_count;
static int            s_wlan_current = -1;    // Index der aktiven Verbindung
static int64_t        s_wlan_last_scan_us;    // letzter Manager-Scan
static volatile bool  s_wifi_connected;
static esp_ip4_addr_t s_wifi_ip;
static int            s_wifi_retry;
static bool           s_nat_on;
static volatile int64_t s_wifi_got_ip_us;  // Zeitpunkt GOT_IP (fuer Config-Poll 3 min danach)
static bool           s_cfg_checked_once;   // Config-Server-Poll nach WLAN einmalig erledigt
// Captive-Portal-Zustand: gesperrt (Default) -> kein Internet, DNS-Hijack aufs
// Dongle-Webinterface; entsperrt -> NAT an, DNS wird echt weitergeleitet.
static volatile bool  s_unlocked = true;   // Default: Internet AN (spaeter per Einstellung anpassbar)
// Kill-Switch (Phase 6): wenn scharf, gibt es Internet nur bei aktivem
// VPN-Tunnel -> faellt WireGuard weg, wird die Weiterleitung sofort geblockt.
static volatile bool  s_killswitch;

// Internet-Freigabe an-/ausschalten (NAPT auf dem USB-Interface).
static void set_internet(bool on)
{
    if (!s_usb_netif) return;
    if (on) {
        s_nat_on = (esp_netif_napt_enable(s_usb_netif) == ESP_OK);
    } else {
        esp_netif_napt_disable(s_usb_netif);
        s_nat_on = false;
    }
    ESP_LOGI(TAG, "Internet-Freigabe: %s", s_nat_on ? "AN (NAT)" : "AUS");
}

// ============================ Status-LED =====================================
// Gleiche Schnittstelle led_set(r,g,b) (0/1 je Kanal) fuer zwei Boards:
//  - ESP32-S3-DevKitC-1: interne adressierbare RGB-LED (WS2812) an GPIO48,
//    getrieben ueber die led_strip-Komponente (RMT). -DBOARD_LED_WS2812=48.
//  - Wemos S2 Mini: externe KY-016 (gemeinsame Kathode, HIGH = an) an GPIO5/6/7.
#if defined(BOARD_LED_WS2812)
// WS2812 direkt ueber den RMT-Treiber (kein externes led_strip -> dessen
// SPI-Backend ist mit IDF 6.0.1 nicht kompilierbar). Aufloesung 10 MHz
// (0,1 us/Tick); Bit-Timing 0=0,3us/0,9us, 1=0,9us/0,3us (WS2812-Standard).
#include "driver/rmt_tx.h"
#include "driver/rmt_encoder.h"
static rmt_channel_handle_t s_rmt_chan;
static rmt_encoder_handle_t s_rmt_enc;

static void led_set(int r, int g, int b)
{
    if (!s_rmt_chan || !s_rmt_enc) return;
    // 0/1 je Kanal -> gedimmte Vollfarbe (WS2812 waere voll aufgedreht grell).
    // HW-Befund an diesem DevKitC-1: die LED ist RGB-geordnet (R zuerst), NICHT
    // das Standard-WS2812-GRB -> Bytes in Reihenfolge R, G, B senden.
    uint8_t rgb[3] = { (uint8_t)(r ? 40 : 0), (uint8_t)(g ? 40 : 0), (uint8_t)(b ? 40 : 0) };
    rmt_transmit_config_t tx = { .loop_count = 0 };
    if (rmt_transmit(s_rmt_chan, s_rmt_enc, rgb, sizeof(rgb), &tx) == ESP_OK) {
        rmt_tx_wait_all_done(s_rmt_chan, 100);   // >50us Pause danach = Latch
    }
}

static void led_init(void)
{
    rmt_tx_channel_config_t chan_cfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .gpio_num          = BOARD_LED_WS2812,
        .mem_block_symbols = 64,
        .resolution_hz     = 10 * 1000 * 1000,   // 10 MHz
        .trans_queue_depth = 4,
    };
    if (rmt_new_tx_channel(&chan_cfg, &s_rmt_chan) != ESP_OK) { s_rmt_chan = NULL; return; }

    rmt_bytes_encoder_config_t enc_cfg = {
        .bit0 = { .level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9 },  // 0,3us / 0,9us
        .bit1 = { .level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3 },  // 0,9us / 0,3us
        .flags = { .msb_first = 1 },
    };
    if (rmt_new_bytes_encoder(&enc_cfg, &s_rmt_enc) != ESP_OK) { s_rmt_enc = NULL; return; }
    rmt_enable(s_rmt_chan);
    led_set(1, 0, 0);   // rot
}
#else
#define LED_R_PIN GPIO_NUM_5
#define LED_G_PIN GPIO_NUM_6
#define LED_B_PIN GPIO_NUM_7

static void led_set(int r, int g, int b)
{
    gpio_set_level(LED_R_PIN, r);
    gpio_set_level(LED_G_PIN, g);
    gpio_set_level(LED_B_PIN, b);
}

static void led_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << LED_R_PIN) | (1ULL << LED_G_PIN) | (1ULL << LED_B_PIN),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&io);
    led_set(1, 0, 0);   // rot
}
#endif

// --- USB-NCM <-> esp_netif Glue (dokumentiertes Custom-Driver-Muster) --------
typedef struct { esp_netif_driver_base_t base; } usb_driver_t;
static usb_driver_t s_usb_driver;

// esp_netif will senden -> ueber USB an den PC.
static volatile uint32_t s_tx_count;
static esp_err_t usb_driver_transmit(void *h, void *buffer, size_t len)
{
    (void)h; (void)buffer; (void)len;
    s_tx_count++;
#if DIAG_TX_NOOP
    return ESP_OK;   // DIAGNOSE: TX verwerfen (Deadlock-Test)
#else
    return tinyusb_net_send_sync(buffer, len, NULL, pdMS_TO_TICKS(200));
#endif
}

// esp_netif hat den RX-pbuf freigegeben -> unsere in usb_recv_cb gemachte Kopie loesen.
static void usb_driver_free_rx(void *h, void *buffer)
{
    (void)h;
    free(buffer);
}

// Beim Anhaengen des Treibers: netif merken + Transmit registrieren. Dieser
// Weg (esp_netif_attach + post_attach) verdrahtet den Netstack korrekt --
// anders als das direkte Setzen von config.driver.
static esp_err_t usb_driver_post_attach(esp_netif_t *netif, void *args)
{
    usb_driver_t *drv = args;
    drv->base.netif = netif;
    esp_netif_driver_ifconfig_t ifcfg = {
        .handle = drv,
        .transmit = usb_driver_transmit,
        .driver_free_rx_buffer = usb_driver_free_rx,
    };
    return esp_netif_set_driver_config(netif, &ifcfg);
}

// Vom PC empfangenes USB-Paket -> in den lwIP-Stack des USB-netif einspeisen.
static esp_err_t usb_recv_cb(void *buffer, uint16_t len, void *ctx)
{
    (void)ctx;
    s_rx_count++;
#if !DIAG_NO_NETIF_RX
    if (s_usb_netif) {
        // Der ETH-Netstack legt einen zero-copy PBUF_REF auf 'buffer' an und gibt
        // ihn erst spaeter im tcpip-Task frei (via driver_free_rx_buffer). Der
        // TinyUSB-Puffer wird aber nach diesem Callback wiederverwendet -> wir
        // muessen kopieren und die Kopie im free-Callback (usb_driver_free_rx) loesen.
        void *copy = malloc(len);
        if (copy) {
            memcpy(copy, buffer, len);
            // esp_netif_receive/ethernetif_input UEBERNIMMT 'copy' in ALLEN Faellen:
            // bei Erfolg gibt der Netstack den PBUF_REF spaeter frei, in JEDEM
            // Fehlerfall (netif down, pbuf-Alloc-Fehler, tcpip-Queue voll unter Last)
            // sofort via esp_netif_free_rx_buffer -> driver_free_rx_buffer -> free().
            // Also NIEMALS selbst freigeben -> sonst Double-Free (Heap-Korruption,
            // Crash im TinyUSB-Task unter Last). Rueckgabewert bewusst ignoriert.
            esp_netif_receive(s_usb_netif, copy, len, NULL);
        }
    }
#endif
    return ESP_OK;
}

// --- WireGuard-VPN-Tunnel ----------------------------------------------------
// esp_wireguard haelt nur Zeiger auf die Strings -> persistente Puffer noetig.
static char s_wg_priv[64];
static char s_wg_pub[64];
static char s_wg_psk[64];
static char s_wg_endpoint[80];
static char s_wg_addr[24];
static char s_wg_netmask[24];
static int  s_wg_port = 51820;
static int  s_wg_keepalive = 25;
static bool s_wg_fulltunnel;          // true: ganzen PC-Verkehr durch den Tunnel
static wireguard_ctx_t s_wg_ctx = ESP_WIREGUARD_CONTEXT_DEFAULT();
static volatile bool s_wg_up;
static bool s_wg_started;
static bool s_wg_default_set;          // WG ist aktuell Default-Route
static volatile bool s_wg_reconnect;   // Web-Form -> Reconnect im Main-Task
static volatile bool s_vpn_off;        // Admin-Schalter "VPN-AUS": Tunnel deaktiviert, kein Reconnect

static bool wg_configured(void)
{
    return s_wg_priv[0] && s_wg_pub[0] && s_wg_endpoint[0] && s_wg_addr[0];
}

// --- DHCP Option 121 (Classless Static Routes, RFC 3442) --------------------
// Der DHCP-Server des Dongles gibt dem PC gezielt Routen mit, damit er den
// Dongle OHNE manuelle Host-Routen/Metriken bevorzugt: Volltunnel -> 0.0.0.0/0,
// sonst (Split) das WG-Remote-Subnetz. Aufgerufen aus dem lwIP-DHCPS-Hook
// (dongle_lwip_hooks.h, via ESP_IDF_LWIP_HOOK_FILENAME). PC muss danach einen
// DHCP-Renew machen (Neu-Einstecken / ipconfig /renew), um die Routen zu ziehen.
static struct netif *s_usb_lwip_netif;

static uint8_t dongle_mask_to_prefix(uint32_t mask_be)
{
    uint32_t m = lwip_ntohl(mask_be);
    uint8_t n = 0;
    while (m & 0x80000000UL) { n++; m <<= 1; }
    return n;
}

void dongle_dhcps_append_opts(struct netif *netif, unsigned char state, unsigned char **pp_opts)
{
    // Nur echte Leases (DHCPOFFER=2 / DHCPACK=5), nicht NAK.
    if (state != 2 && state != 5) return;
    // Nur auf dem USB-Interface (DHCP-Server laeuft ohnehin nur dort).
    if (!s_usb_lwip_netif && s_usb_netif) s_usb_lwip_netif = esp_netif_get_netif_impl(s_usb_netif);
    if (s_usb_lwip_netif && netif != s_usb_lwip_netif) return;

    // Routenliste bestimmen (dest_be im Network-Byte-Order + Praefix).
    struct { uint32_t dest_be; uint8_t prefix; } routes[2];
    int nroutes = 0;
    if (s_wg_fulltunnel) {
        // Volltunnel: 0.0.0.0/1 + 128.0.0.0/1 statt 0.0.0.0/0 -> spezifischer als
        // jede Default-Route, gewinnt also OHNE Metrik-Gefummel gegen das WLAN.
        routes[0].dest_be = 0;                 routes[0].prefix = 1;   // 0.0.0.0/1
        routes[1].dest_be = lwip_htonl(0x80000000UL); routes[1].prefix = 1; // 128.0.0.0/1
        nroutes = 2;
    } else if (wg_configured()) {
        // Split: nur das WG-Remote-Subnetz ueber den Dongle (spezifisch -> gewinnt).
        esp_ip4_addr_t a = {0}, m = {0};
        if (esp_netif_str_to_ip4(s_wg_addr, &a) == ESP_OK &&
            esp_netif_str_to_ip4(s_wg_netmask[0] ? s_wg_netmask : "255.255.255.0", &m) == ESP_OK) {
            routes[0].dest_be = a.addr & m.addr;
            routes[0].prefix  = dongle_mask_to_prefix(m.addr);
            nroutes = 1;
        }
    }
    if (nroutes == 0) return;

    // Gateway = eigene USB-IP (192.168.226.1), aus dem netif.
    uint32_t gw_be = netif_ip4_addr(netif)->addr;

    // Gesamtlaenge vorab bestimmen (pro Route: 1 Praefix + Oktette + 4 GW).
    uint8_t total = 0;
    for (int r = 0; r < nroutes; r++) total += 1 + (routes[r].prefix + 7) / 8 + 4;

    uint8_t *p = *pp_opts;
    *p++ = 121;                                  // CLASSLESS_ROUTE
    *p++ = total;
    for (int r = 0; r < nroutes; r++) {
        uint8_t destlen = (routes[r].prefix + 7) / 8;    // signifikante Oktette
        *p++ = routes[r].prefix;
        for (uint8_t i = 0; i < destlen; i++) *p++ = (uint8_t)(routes[r].dest_be >> (8 * i)) & 0xFF; // MSB zuerst
        for (uint8_t i = 0; i < 4; i++)       *p++ = (uint8_t)(gw_be >> (8 * i)) & 0xFF;
    }
    *pp_opts = p;
}

// LED-Zustand: gruen=VPN, blau=WLAN, rot=nichts.
static void led_update(void)
{
    if (s_wg_up)              led_set(0, 1, 0);
    else if (s_wifi_connected) led_set(0, 0, 1);
    else                       led_set(1, 0, 0);
}

// Zentrale Internet-Freigabe: NAPT nur AN, wenn entsperrt UND (Kill-Switch aus
// ODER VPN-Tunnel steht). So blockt der Kill-Switch jeden Leak, wenn WG faellt.
static void update_internet_gate(void)
{
    bool allow = s_unlocked && (!s_killswitch || s_wg_up);
    if (allow != s_nat_on) set_internet(allow);
}

static void wg_creds_load(void)
{
    nvs_handle_t h;
    if (nvs_open("wg", NVS_READONLY, &h) != ESP_OK) return;
    size_t n;
    n = sizeof(s_wg_priv);     nvs_get_str(h, "priv", s_wg_priv, &n);
    n = sizeof(s_wg_pub);      nvs_get_str(h, "pub", s_wg_pub, &n);
    n = sizeof(s_wg_psk);      nvs_get_str(h, "psk", s_wg_psk, &n);
    n = sizeof(s_wg_endpoint); nvs_get_str(h, "ep", s_wg_endpoint, &n);
    n = sizeof(s_wg_addr);     nvs_get_str(h, "addr", s_wg_addr, &n);
    n = sizeof(s_wg_netmask);  nvs_get_str(h, "mask", s_wg_netmask, &n);
    int32_t v;
    if (nvs_get_i32(h, "port", &v) == ESP_OK) s_wg_port = v;
    if (nvs_get_i32(h, "ka", &v) == ESP_OK)   s_wg_keepalive = v;
    uint8_t b;
    if (nvs_get_u8(h, "full", &b) == ESP_OK)  s_wg_fulltunnel = b;
    if (nvs_get_u8(h, "ks", &b) == ESP_OK)    s_killswitch = b;
    if (nvs_get_u8(h, "off", &b) == ESP_OK)   s_vpn_off = b;
    nvs_close(h);
}

static void wg_creds_save(void)
{
    nvs_handle_t h;
    if (nvs_open("wg", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_str(h, "priv", s_wg_priv);
    nvs_set_str(h, "pub",  s_wg_pub);
    nvs_set_str(h, "psk",  s_wg_psk);
    nvs_set_str(h, "ep",   s_wg_endpoint);
    nvs_set_str(h, "addr", s_wg_addr);
    nvs_set_str(h, "mask", s_wg_netmask);
    nvs_set_i32(h, "port", s_wg_port);
    nvs_set_i32(h, "ka",   s_wg_keepalive);
    nvs_set_u8(h,  "full", s_wg_fulltunnel ? 1 : 0);
    nvs_set_u8(h,  "ks",   s_killswitch ? 1 : 0);
    nvs_set_u8(h,  "off",  s_vpn_off ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
}

// Tunnel initialisieren + verbinden (braucht aktives WLAN).
static void wg_start(void)
{
    if (!wg_configured() || !s_wifi_connected || s_wg_started) return;

    static wireguard_config_t cfg;
    cfg = (wireguard_config_t)ESP_WIREGUARD_CONFIG_DEFAULT();
    cfg.private_key   = s_wg_priv;
    cfg.public_key    = s_wg_pub;
    cfg.preshared_key = s_wg_psk[0] ? s_wg_psk : NULL;
    cfg.address       = s_wg_addr;
    cfg.netmask       = s_wg_netmask[0] ? s_wg_netmask : "255.255.255.255";
    cfg.endpoint      = s_wg_endpoint;
    cfg.port          = (uint16_t)s_wg_port;
    cfg.persistent_keepalive = (uint16_t)s_wg_keepalive;

    if (esp_wireguard_init(&cfg, &s_wg_ctx) != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init fehlgeschlagen"); return;
    }
    if (esp_wireguard_connect(&s_wg_ctx) != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect fehlgeschlagen"); return;
    }
    s_wg_started = true;
    ESP_LOGI(TAG, "WireGuard: init+connect -> %s:%d, Tunnel-IP %s",
             s_wg_endpoint, s_wg_port, s_wg_addr);
}

static void wg_stop(void)
{
    if (!s_wg_started) return;
    if (s_wg_default_set) { esp_wireguard_restore_default(&s_wg_ctx); s_wg_default_set = false; }
    esp_wireguard_disconnect(&s_wg_ctx);
    s_wg_started = false;
    s_wg_up = false;
    led_update();
}

// Periodischer Status-Check (aus dem Heartbeat) -> peer up? + LED.
static void wg_poll(void)
{
    if (!s_wg_started) return;
    bool up = (esp_wireguard_peer_is_up(&s_wg_ctx) == ESP_OK);
    if (up && !s_wg_up)  ESP_LOGI(TAG, "WireGuard: Peer UP (Handshake ok)");
    if (!up && s_wg_up)  ESP_LOGW(TAG, "WireGuard: Peer DOWN");
    if (up != s_wg_up) { s_wg_up = up; led_update(); update_internet_gate(); }

    // Volltunnel: WG als Default-Route setzen sobald Peer up (Schalter an),
    // sonst wiederherstellen. NAPT/Captive steuert weiterhin, OB PC-Verkehr fliesst.
    if (s_wg_up && s_wg_fulltunnel && !s_wg_default_set) {
        esp_wireguard_add_allowed_ip(&s_wg_ctx, "0.0.0.0", "0.0.0.0");
        if (esp_wireguard_set_default(&s_wg_ctx) == ESP_OK) {
            s_wg_default_set = true;
            ESP_LOGI(TAG, "Volltunnel aktiv: Default-Route -> WireGuard");
        }
    } else if ((!s_wg_up || !s_wg_fulltunnel) && s_wg_default_set) {
        esp_wireguard_restore_default(&s_wg_ctx);
        s_wg_default_set = false;
        ESP_LOGI(TAG, "Volltunnel aus: Default-Route wiederhergestellt");
    }
}

// --- WLAN-Uplink (STA-Client), mehrere bekannte WLANs -----------------------
static void wlan_list_save(void)
{
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, "list", s_wlans, sizeof(s_wlans));
    nvs_set_i32(h, "cnt", s_wlan_count);
    nvs_commit(h); nvs_close(h);
}
static void wlan_list_load(void)
{
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READONLY, &h) != ESP_OK) return;
    int32_t c = 0; size_t sz = sizeof(s_wlans);
    if (nvs_get_blob(h, "list", s_wlans, &sz) == ESP_OK && nvs_get_i32(h, "cnt", &c) == ESP_OK) {
        s_wlan_count = (c >= 0 && c <= MAX_WLAN) ? c : 0;
    } else {
        // Migration: frueheres einzelnes ssid/pass -> Liste[0].
        char ssid[33] = {0}, pass[64] = {0};
        size_t sl = sizeof(ssid), pl = sizeof(pass);
        if (nvs_get_str(h, "ssid", ssid, &sl) == ESP_OK && ssid[0]) {
            nvs_get_str(h, "pass", pass, &pl);
            strlcpy(s_wlans[0].ssid, ssid, sizeof(s_wlans[0].ssid));
            strlcpy(s_wlans[0].pass, pass, sizeof(s_wlans[0].pass));
            s_wlan_count = 1;
        }
    }
    nvs_close(h);
}
// Hinzufuegen/aktualisieren. Vorhandene SSID -> nur Passwort updaten. -> Index.
static int wlan_add(const char *ssid, const char *pass)
{
    if (!ssid || !ssid[0]) return -1;
    for (int i = 0; i < s_wlan_count; i++)
        if (strcmp(s_wlans[i].ssid, ssid) == 0) { strlcpy(s_wlans[i].pass, pass, sizeof(s_wlans[i].pass)); return i; }
    if (s_wlan_count >= MAX_WLAN) return -1;
    memset(&s_wlans[s_wlan_count], 0, sizeof(wlan_t));
    strlcpy(s_wlans[s_wlan_count].ssid, ssid, sizeof(s_wlans[s_wlan_count].ssid));
    strlcpy(s_wlans[s_wlan_count].pass, pass ? pass : "", sizeof(s_wlans[s_wlan_count].pass));
    return s_wlan_count++;
}
// Blockierender Scan -> Index des hoechstprioren (kleinster Index) verfuegbaren
// gespeicherten WLANs, oder -1.
static int wlan_scan_best(void)
{
    if (s_wlan_count == 0) return -1;
    wifi_scan_config_t sc = { .show_hidden = false };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) return -1;
    uint16_t n = 0; esp_wifi_scan_get_ap_num(&n);
    if (n == 0) return -1;
    if (n > 30) n = 30;
    wifi_ap_record_t *recs = calloc(n, sizeof(wifi_ap_record_t));
    if (!recs) return -1;
    esp_wifi_scan_get_ap_records(&n, recs);
    int best = -1;
    for (int w = 0; w < s_wlan_count && best < 0; w++)
        for (int a = 0; a < n; a++)
            if (strcmp((char *)recs[a].ssid, s_wlans[w].ssid) == 0) { best = w; break; }
    free(recs);
    return best;
}
// Auf gespeichertes WLAN i verbinden.
static void wlan_connect_to(int i)
{
    if (i < 0 || i >= s_wlan_count) return;
    strlcpy(s_wifi_ssid, s_wlans[i].ssid, sizeof(s_wifi_ssid));
    strlcpy(s_wifi_pass, s_wlans[i].pass, sizeof(s_wifi_pass));
    s_wlan_current = i;
    wifi_config_t wc = { 0 };
    memcpy(wc.sta.ssid, s_wifi_ssid, sizeof(wc.sta.ssid));
    memcpy(wc.sta.password, s_wifi_pass, sizeof(wc.sta.password));
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    s_wifi_retry = 0;
    esp_wifi_disconnect();
    esp_wifi_connect();
}
// Vom Main-Task aufgerufen: bei Ausfall auf ein anderes verfuegbares WLAN
// wechseln; im Verbundzustand periodisch auf ein hoeher priorisiertes wechseln
// (Szenario: temporaerer Hotspot -> Rueckkehr an den Arbeitsplatz).
static void wlan_manager(void)
{
    if (s_wlan_count == 0) return;
    int64_t now = esp_timer_get_time();
    if (!s_wifi_connected) {
        // Recovery per ROUND-ROBIN (KEIN Scan): esp_wifi_scan_start scheitert,
        // solange ein Verbindungsversuch laeuft. Nach mehreren Fehlversuchen das
        // naechste gespeicherte WLAN anvisieren -> jedes verfuegbare wird
        // gefunden, und ein "verwaistes" Ziel (geloeschtes WLAN) wird korrigiert.
        if (s_wifi_retry >= 5 && (now - s_wlan_last_scan_us) > 6000000LL) {
            s_wlan_last_scan_us = now;
            int next = s_wlan_current + 1;
            if (next >= s_wlan_count || next < 0) next = 0;
            ESP_LOGI(TAG, "WLAN-Recovery: probiere '%s' (Prio %d)", s_wlans[next].ssid, next);
            wlan_connect_to(next);
        }
    } else if (s_wlan_count > 1 && s_wlan_current > 0) {
        // Verbunden mit nicht-hoechster Prio: alle 60 s pruefen, ob ein hoeher
        // priorisiertes WLAN verfuegbar ist (Scan im Verbundzustand ist ok).
        if ((now - s_wlan_last_scan_us) > 60000000LL) {
            s_wlan_last_scan_us = now;
            int best = wlan_scan_best();
            if (best >= 0 && best < s_wlan_current) {
                ESP_LOGI(TAG, "WLAN-Switch (hoehere Prio verfuegbar) -> '%s'", s_wlans[best].ssid);
                wlan_connect_to(best);
            }
        }
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        if (s_wifi_ssid[0]) esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_wifi_connected = false;
        led_update();       // rot: keine WLAN-Verbindung
        if (s_wifi_ssid[0]) {
            s_wifi_retry++;
            if (s_wifi_retry <= 3 || (s_wifi_retry % 20) == 0)
                ESP_LOGW(TAG, "WLAN getrennt, erneuter Versuch #%d", s_wifi_retry);
            esp_wifi_connect();   // WLAN-Treiber ratenlimitiert selbst
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        s_wifi_ip = ev->ip_info.ip;
        s_wifi_connected = true;
        s_wifi_retry = 0;
        s_wifi_got_ip_us = esp_timer_get_time();   // Config-Poll 3 min danach
        s_cfg_checked_once = false;
        led_update();       // blau: WLAN verbunden
        ESP_LOGI(TAG, "WLAN verbunden, IP " IPSTR, IP2STR(&ev->ip_info.ip));
        // WireGuard NICHT hier starten: esp_wireguard_init (DNS+Krypto+netif_add)
        // ist zu schwer fuer den sys_evt-Task. Der Heartbeat (Main-Task) ruft
        // wg_start(), sobald WLAN verbunden ist.
    }
}

// Zugangsdaten aus Webinterface: in die Liste aufnehmen (Prioritaet = Reihen-
// folge) + sofort verbinden. Vorhandene SSID -> Passwort aktualisieren.
static void wifi_apply(const char *ssid, const char *pass)
{
    int idx = wlan_add(ssid, pass);
    if (idx < 0) { ESP_LOGW(TAG, "WLAN nicht gespeichert (Liste voll oder SSID leer)"); return; }
    wlan_list_save();
    wlan_connect_to(idx);
    ESP_LOGI(TAG, "WLAN '%s' gespeichert (Prio %d, %d gesamt) -> verbinde", ssid, idx, s_wlan_count);
}

static void start_wifi(void)
{
    s_sta_netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    wlan_list_load();
    if (s_wlan_count > 0) {
        // Startziel = hoechste Prioritaet (Index 0); Manager wechselt bei Bedarf.
        strlcpy(s_wifi_ssid, s_wlans[0].ssid, sizeof(s_wifi_ssid));
        strlcpy(s_wifi_pass, s_wlans[0].pass, sizeof(s_wifi_pass));
        s_wlan_current = 0;
        wifi_config_t wc = { 0 };
        memcpy(wc.sta.ssid, s_wifi_ssid, sizeof(wc.sta.ssid));
        memcpy(wc.sta.password, s_wifi_pass, sizeof(wc.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
        ESP_LOGI(TAG, "WLAN: %d gespeichert, Start mit '%s'", s_wlan_count, s_wifi_ssid);
    } else {
        ESP_LOGW(TAG, "Keine WLANs -> im Webinterface setzen");
    }
    ESP_ERROR_CHECK(esp_wifi_start());
}

// --- Interne Ressourcen (RDP/Link/SSH), Phase 8 ------------------------------
#define MAX_RES 12
typedef struct {
    char     name[40];
    char     type[6];   // "rdp" | "link" | "ssh"
    char     addr[96];  // Host oder URL
    uint16_t port;
} resource_t;
static resource_t s_res[MAX_RES];
static int        s_res_count;

static void res_load(void)
{
    nvs_handle_t nh;
    if (nvs_open("res", NVS_READONLY, &nh) != ESP_OK) return;
    size_t sz = sizeof(s_res);
    if (nvs_get_blob(nh, "list", s_res, &sz) == ESP_OK) {
        int32_t c = 0;
        nvs_get_i32(nh, "cnt", &c);
        s_res_count = (c >= 0 && c <= MAX_RES) ? c : 0;
    }
    nvs_close(nh);
}

static void res_save(void)
{
    nvs_handle_t nh;
    if (nvs_open("res", NVS_READWRITE, &nh) != ESP_OK) return;
    nvs_set_blob(nh, "list", s_res, sizeof(s_res));
    nvs_set_i32(nh, "cnt", s_res_count);
    nvs_commit(nh);
    nvs_close(nh);
}

// --- Admin-Login (HTTP Basic Auth) + sichere Konfig --------------------------
// Passwort wird NUR als SHA-256-Hash gespeichert (nie Klartext, nie im Code).
static char s_admin_user[24] = "admin";
static char s_admin_phash[65];       // SHA-256-Hex
static bool s_admin_is_default;      // Default-Passwort aktiv -> Warnung

static void sha256_hex(const char *in, char *out /*[65]*/)
{
    unsigned char h[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(info, (const unsigned char *)in, strlen(in), h);
    for (int i = 0; i < 32; i++) sprintf(out + i * 2, "%02x", h[i]);
    out[64] = 0;
}

static void admin_load(void)
{
    nvs_handle_t nh;
    if (nvs_open("admin", NVS_READONLY, &nh) == ESP_OK) {
        size_t n = sizeof(s_admin_user);
        nvs_get_str(nh, "user", s_admin_user, &n);
        n = sizeof(s_admin_phash);
        bool have = (nvs_get_str(nh, "phash", s_admin_phash, &n) == ESP_OK && s_admin_phash[0]);
        nvs_close(nh);
        if (have) return;
    }
    sha256_hex("admin", s_admin_phash);   // Default "admin" -> Warnung
    s_admin_is_default = true;
}

static void admin_save(const char *user, const char *pass)
{
    if (user[0]) snprintf(s_admin_user, sizeof(s_admin_user), "%s", user);
    sha256_hex(pass, s_admin_phash);
    s_admin_is_default = false;
    nvs_handle_t nh;
    if (nvs_open("admin", NVS_READWRITE, &nh) == ESP_OK) {
        nvs_set_str(nh, "user", s_admin_user);
        nvs_set_str(nh, "phash", s_admin_phash);
        nvs_commit(nh);
        nvs_close(nh);
    }
}

static bool check_basic_auth(httpd_req_t *req)
{
    char hdr[160];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK) return false;
    if (strncmp(hdr, "Basic ", 6) != 0) return false;
    unsigned char dec[128]; size_t dl = 0;
    if (mbedtls_base64_decode(dec, sizeof(dec) - 1, &dl,
                              (unsigned char *)hdr + 6, strlen(hdr + 6)) != 0) return false;
    dec[dl] = 0;
    char *colon = strchr((char *)dec, ':');
    if (!colon) return false;
    *colon = 0;
    if (strcmp((char *)dec, s_admin_user) != 0) return false;
    char h[65];
    sha256_hex(colon + 1, h);
    return strcmp(h, s_admin_phash) == 0;
}

// true = autorisiert; false = 401 gesendet (Handler soll ESP_OK zurueckgeben).
static bool require_auth(httpd_req_t *req)
{
    if (check_basic_auth(req)) return true;
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32-USB-VPN\"");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "Anmeldung erforderlich");
    return false;
}

// === Systemname / Seriennummer / verschluesselte Konfig ======================
// Seriennummer = kompakte Modul-MAC (efuse). Konfig-Datei = "BHVPN1." +
// base64(IV(16) || AES-256-CBC-Ciphertext || HMAC-SHA256(32)), Schluessel aus
// SHA256("bhvpn-enc:"+secret) bzw. "-mac:"; Encrypt-then-MAC (erkennt falsches
// Secret). Identisches Format in tools/admin.ps1. Secret = 20 alphanumerisch.
static char    s_systemname[40];
static char    s_cfg_secret[24];    // Konfig-Verschluesselungs-Secret (20 Zeichen)
static char    s_cfg_server[128];   // Config-Server-Basis-URL (plain http)
static int32_t s_cfg_version;       // Version der zuletzt eingespielten Konfig
static volatile bool s_cfg_update_available;
static int32_t s_cfg_available_version;

static void sn_string(char out[13])
{
    uint8_t m[6]; esp_efuse_mac_get_default(m);
    snprintf(out, 13, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Captive-Portal automatisch aktivieren, solange KEIN WLAN verbunden ist -> das
// OS-"Anmelden"-Popup fuehrt dann auf die WLAN-Konfigseite (Onboarding/Recovery).
// Einstellung (NVS "capauto"), Default an. Bei WLAN-Verbindung wieder frei.
static bool s_captive_auto = true;

static void sys_load(void)
{
    nvs_handle_t h;
    if (nvs_open("sys", NVS_READONLY, &h) != ESP_OK) return;
    size_t n;
    n = sizeof(s_systemname); nvs_get_str(h, "name", s_systemname, &n);
    n = sizeof(s_cfg_secret); nvs_get_str(h, "secret", s_cfg_secret, &n);
    n = sizeof(s_cfg_server); nvs_get_str(h, "server", s_cfg_server, &n);
    nvs_get_i32(h, "cfgver", &s_cfg_version);
    uint8_t cb; if (nvs_get_u8(h, "capauto", &cb) == ESP_OK) s_captive_auto = cb;
    nvs_close(h);
}
static void sys_save(void)
{
    nvs_handle_t h;
    if (nvs_open("sys", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_str(h, "name", s_systemname);
    nvs_set_str(h, "secret", s_cfg_secret);
    nvs_set_str(h, "server", s_cfg_server);
    nvs_set_i32(h, "cfgver", s_cfg_version);
    nvs_set_u8(h, "capauto", s_captive_auto ? 1 : 0);
    nvs_commit(h); nvs_close(h);
}

// SHA256(a || b) -> out[32]
static void cfg_kdf(const char *a, const char *b, uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t c; mbedtls_md_init(&c);
    mbedtls_md_setup(&c, info, 0);
    mbedtls_md_starts(&c);
    mbedtls_md_update(&c, (const unsigned char *)a, strlen(a));
    mbedtls_md_update(&c, (const unsigned char *)b, strlen(b));
    mbedtls_md_finish(&c, out);
    mbedtls_md_free(&c);
}

// SHA256(a[alen] || b[blen]) -> out[32]
static void sha256_raw(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t c; mbedtls_md_init(&c);
    mbedtls_md_setup(&c, info, 0);
    mbedtls_md_starts(&c);
    if (a && alen) mbedtls_md_update(&c, a, alen);
    if (b && blen) mbedtls_md_update(&c, b, blen);
    mbedtls_md_finish(&c, out);
    mbedtls_md_free(&c);
}
// HMAC-SHA256 (32-Byte-Key) manuell -> unabhaengig von mbedtls_md_hmac.
static void hmac_sha256(const uint8_t key[32], const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    uint8_t ipad[64], opad[64], inner[32];
    memset(ipad, 0, 64); memset(opad, 0, 64);
    memcpy(ipad, key, 32); memcpy(opad, key, 32);
    for (int i = 0; i < 64; i++) { ipad[i] ^= 0x36; opad[i] ^= 0x5c; }
    sha256_raw(ipad, 64, msg, mlen, inner);
    sha256_raw(opad, 64, inner, 32, out);
}

// Verschluesselt plain -> malloc'd "BHVPN1."+base64(...). NULL bei Fehler.
static char *config_encrypt(const char *plain)
{
    if (!s_cfg_secret[0]) return NULL;
    uint8_t encKey[32], macKey[32];
    cfg_kdf("bhvpn-enc:", s_cfg_secret, encKey);
    cfg_kdf("bhvpn-mac:", s_cfg_secret, macKey);
    size_t plen = strlen(plain);
    uint8_t pad = 16 - (plen % 16);            // PKCS7 (1..16)
    size_t ctlen = plen + pad;
    uint8_t *buf = malloc(16 + ctlen + 32);    // IV || CT || MAC
    uint8_t *pt = malloc(ctlen);
    if (!buf || !pt) { free(buf); free(pt); return NULL; }
    esp_fill_random(buf, 16);
    memcpy(pt, plain, plen);
    memset(pt + plen, pad, pad);
    mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, encKey, 256);
    uint8_t iv[16]; memcpy(iv, buf, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, ctlen, iv, pt, buf + 16);
    mbedtls_aes_free(&aes);
    free(pt);
    hmac_sha256(macKey, buf, 16 + ctlen, buf + 16 + ctlen);
    size_t blen = 16 + ctlen + 32, b64cap = ((blen + 2) / 3) * 4 + 1, olen = 0;
    char *out = malloc(7 + b64cap + 1);
    if (!out) { free(buf); return NULL; }
    memcpy(out, "BHVPN1.", 7);
    mbedtls_base64_encode((unsigned char *)out + 7, b64cap, &olen, buf, blen);
    out[7 + olen] = 0;
    free(buf);
    return out;
}

// Entschluesselt "BHVPN1."-Datei -> malloc'd Klartext-JSON. NULL bei falschem
// Secret / beschaedigt / falschem Format.
static char *config_decrypt(const char *file)
{
    if (!s_cfg_secret[0]) return NULL;
    while (*file == ' ' || *file == '\n' || *file == '\r' || *file == '\t') file++;
    if (strncmp(file, "BHVPN1.", 7) != 0) return NULL;
    const char *b64 = file + 7;
    size_t b64len = strlen(b64);
    while (b64len && (b64[b64len - 1] == '\n' || b64[b64len - 1] == '\r' ||
                      b64[b64len - 1] == ' '  || b64[b64len - 1] == '\t')) b64len--;
    size_t cap = (b64len / 4) * 3 + 4, blen = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;
    if (mbedtls_base64_decode(buf, cap, &blen, (const unsigned char *)b64, b64len) != 0
        || blen < 16 + 16 + 32 || ((blen - 48) % 16) != 0) { free(buf); return NULL; }
    size_t ctlen = blen - 16 - 32;
    uint8_t encKey[32], macKey[32], mac[32];
    cfg_kdf("bhvpn-enc:", s_cfg_secret, encKey);
    cfg_kdf("bhvpn-mac:", s_cfg_secret, macKey);
    hmac_sha256(macKey, buf, 16 + ctlen, mac);
    uint8_t diff = 0; for (int i = 0; i < 32; i++) diff |= mac[i] ^ buf[16 + ctlen + i];
    if (diff) { free(buf); return NULL; }      // falsches Secret / manipuliert
    uint8_t *pt = malloc(ctlen + 1);
    if (!pt) { free(buf); return NULL; }
    mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, encKey, 256);
    uint8_t iv[16]; memcpy(iv, buf, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ctlen, iv, buf + 16, pt);
    mbedtls_aes_free(&aes);
    free(buf);
    uint8_t pad = pt[ctlen - 1];
    if (pad < 1 || pad > 16 || pad > ctlen) { free(pt); return NULL; }
    pt[ctlen - pad] = 0;
    return (char *)pt;
}

// Aktuelle Gesamtkonfig als key=value-Text (malloc'd). Feste Reihenfolge; Werte
// enthalten kein '\n' (WG-Keys/base64 unkritisch, '=' im Wert erlaubt -> Split
// am ERSTEN '='). Gleiches Format in tools/admin.ps1.
static char *config_export_json(void)
{
    char sn[13]; sn_string(sn);
    size_t cap = 4096, o = 0;
    char *b = malloc(cap);
    if (!b) return NULL;
#define APP(...) do { o += snprintf(b + o, (o < cap ? cap - o : 0), __VA_ARGS__); } while (0)
    APP("schema=1\n");
    APP("version=%d\n", (int)s_cfg_version);
    APP("systemname=%s\n", s_systemname);
    APP("captive_auto=%d\n", s_captive_auto ? 1 : 0);
    APP("sn=%s\n", sn);
    APP("wlan.count=%d\n", s_wlan_count);
    for (int i = 0; i < s_wlan_count; i++) {
        APP("wlan.%d.ssid=%s\n", i, s_wlans[i].ssid);
        APP("wlan.%d.pass=%s\n", i, s_wlans[i].pass);
    }
    APP("wg.priv=%s\n", s_wg_priv);
    APP("wg.pub=%s\n", s_wg_pub);
    APP("wg.psk=%s\n", s_wg_psk);
    APP("wg.endpoint=%s\n", s_wg_endpoint);
    APP("wg.port=%d\n", s_wg_port);
    APP("wg.addr=%s\n", s_wg_addr);
    APP("wg.mask=%s\n", s_wg_netmask);
    APP("wg.keepalive=%d\n", s_wg_keepalive);
    APP("wg.fulltunnel=%d\n", s_wg_fulltunnel ? 1 : 0);
    APP("wg.killswitch=%d\n", s_killswitch ? 1 : 0);
    APP("wg.vpn_off=%d\n", s_vpn_off ? 1 : 0);
    APP("admin.user=%s\n", s_admin_user);
    APP("admin.phash=%s\n", s_admin_phash);
    APP("res.count=%d\n", s_res_count);
    for (int i = 0; i < s_res_count; i++) {
        APP("res.%d.name=%s\n", i, s_res[i].name);
        APP("res.%d.type=%s\n", i, s_res[i].type);
        APP("res.%d.addr=%s\n", i, s_res[i].addr);
        APP("res.%d.port=%d\n", i, s_res[i].port);
    }
#undef APP
    if (o >= cap) { free(b); return NULL; }   // Ueberlauf
    return b;
}

// key=value-Text einspielen (in-place tokenisiert): alle Zustaende + NVS.
// Wird direkt vor einem Neustart aufgerufen. true bei Erfolg.
static bool config_import_json(char *text)
{
    if (!text) return false;
    // Merge-Semantik: ein Bereich (WLAN / Ressourcen) wird NUR ersetzt, wenn die
    // Config ihn enthaelt (count- oder N.*-Schluessel gesehen). Fehlt er komplett
    // -> bestehende Werte bleiben. WG/Systemname/Admin sind ohnehin per-Key-Merge.
    bool has_wlan = false, has_res = false;
    char *line = text;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\r') line[ll - 1] = 0;
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = 0;
            const char *k = line, *v = eq + 1;
            if      (!strcmp(k, "version"))       s_cfg_version = atoi(v);
            else if (!strcmp(k, "systemname"))    strlcpy(s_systemname, v, sizeof(s_systemname));
            else if (!strcmp(k, "captive_auto"))  s_captive_auto = (atoi(v) != 0);
            else if (!strcmp(k, "wlan.count")) {
                if (!has_wlan) { memset(s_wlans, 0, sizeof(s_wlans)); s_wlan_count = 0; has_wlan = true; }
            }
            else if (!strncmp(k, "wlan.", 5) && k[5] >= '0' && k[5] <= '9') {
                if (!has_wlan) { memset(s_wlans, 0, sizeof(s_wlans)); s_wlan_count = 0; has_wlan = true; }
                int idx = atoi(k + 5);
                const char *dot = strchr(k + 5, '.');
                if (dot && idx >= 0 && idx < MAX_WLAN) {
                    const char *f = dot + 1;
                    if      (!strcmp(f, "ssid")) strlcpy(s_wlans[idx].ssid, v, sizeof(s_wlans[idx].ssid));
                    else if (!strcmp(f, "pass")) strlcpy(s_wlans[idx].pass, v, sizeof(s_wlans[idx].pass));
                }
            }
            else if (!strcmp(k, "wg.priv"))       strlcpy(s_wg_priv, v, sizeof(s_wg_priv));
            else if (!strcmp(k, "wg.pub"))        strlcpy(s_wg_pub, v, sizeof(s_wg_pub));
            else if (!strcmp(k, "wg.psk"))        strlcpy(s_wg_psk, v, sizeof(s_wg_psk));
            else if (!strcmp(k, "wg.endpoint"))   strlcpy(s_wg_endpoint, v, sizeof(s_wg_endpoint));
            else if (!strcmp(k, "wg.port"))       s_wg_port = atoi(v);
            else if (!strcmp(k, "wg.addr"))       strlcpy(s_wg_addr, v, sizeof(s_wg_addr));
            else if (!strcmp(k, "wg.mask"))       strlcpy(s_wg_netmask, v, sizeof(s_wg_netmask));
            else if (!strcmp(k, "wg.keepalive"))  s_wg_keepalive = atoi(v);
            else if (!strcmp(k, "wg.fulltunnel")) s_wg_fulltunnel = atoi(v) != 0;
            else if (!strcmp(k, "wg.killswitch")) s_killswitch = atoi(v) != 0;
            else if (!strcmp(k, "wg.vpn_off"))    s_vpn_off = atoi(v) != 0;
            else if (!strcmp(k, "admin.user"))    strlcpy(s_admin_user, v, sizeof(s_admin_user));
            else if (!strcmp(k, "admin.phash"))   strlcpy(s_admin_phash, v, sizeof(s_admin_phash));
            else if (!strcmp(k, "res.count")) {
                if (!has_res) { memset(s_res, 0, sizeof(s_res)); s_res_count = 0; has_res = true; }
            }
            else if (!strncmp(k, "res.", 4)) {
                if (!has_res) { memset(s_res, 0, sizeof(s_res)); s_res_count = 0; has_res = true; }
                int idx = atoi(k + 4);
                const char *dot = strchr(k + 4, '.');
                if (dot && idx >= 0 && idx < MAX_RES) {
                    const char *f = dot + 1;
                    resource_t *d = &s_res[idx];
                    if      (!strcmp(f, "name")) strlcpy(d->name, v, sizeof(d->name));
                    else if (!strcmp(f, "type")) strlcpy(d->type, v, sizeof(d->type));
                    else if (!strcmp(f, "addr")) strlcpy(d->addr, v, sizeof(d->addr));
                    else if (!strcmp(f, "port")) d->port = (uint16_t)atoi(v);
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (s_admin_phash[0]) {
        char def[65]; sha256_hex("admin", def);
        s_admin_is_default = (strcmp(s_admin_phash, def) == 0);
    }

    // Ressourcen NUR ersetzen, wenn die Config sie enthielt (sonst unveraendert).
    if (has_res) {
        int n = 0;
        for (int i = 0; i < MAX_RES; i++) {
            if (s_res[i].name[0] && s_res[i].addr[0]) {
                if (!s_res[i].type[0]) strcpy(s_res[i].type, "rdp");
                if (n != i) { s_res[n] = s_res[i]; memset(&s_res[i], 0, sizeof(s_res[i])); }
                n++;
            }
        }
        s_res_count = n;
        res_save();
    }
    // WLANs NUR ersetzen, wenn die Config sie enthielt (sonst unveraendert).
    if (has_wlan) {
        int wn = 0;
        for (int i = 0; i < MAX_WLAN; i++) {
            if (s_wlans[i].ssid[0]) {
                if (wn != i) { s_wlans[wn] = s_wlans[i]; memset(&s_wlans[i], 0, sizeof(s_wlans[i])); }
                wn++;
            }
        }
        s_wlan_count = wn;
        if (s_wlan_count > 0) {
            strlcpy(s_wifi_ssid, s_wlans[0].ssid, sizeof(s_wifi_ssid));
            strlcpy(s_wifi_pass, s_wlans[0].pass, sizeof(s_wifi_pass));
        }
        wlan_list_save();
    }

    wg_creds_save();
    nvs_handle_t nh;
    if (nvs_open("admin", NVS_READWRITE, &nh) == ESP_OK) {
        nvs_set_str(nh, "user", s_admin_user);
        nvs_set_str(nh, "phash", s_admin_phash);
        nvs_commit(nh); nvs_close(nh);
    }
    sys_save();
    return true;
}

// --- HTTP-Testseite + OTA-Update --------------------------------------------
// === Web-UI v2 ===============================================================
// Oeffentliche Startseite "/" (ohne Login): WLAN komplett, VPN nur Status,
// Ressourcen/Dateien zum Download. Einstellungsseite "/settings" (Login):
// System-Status, WireGuard-Konfig, Admin, Ressourcenmanager + Datei-Upload,
// Reset, OTA. Gerendert per Chunked-Response (kein Riesen-snprintf).

// --- Datei-Ablage (SPIFFS 'storage'-Partition, fuer Upload/Download) --------
#define SPIFFS_BASE "/spiffs"
static bool s_spiffs_ok;
static void storage_init(void)
{
    esp_vfs_spiffs_conf_t c = {
        .base_path = SPIFFS_BASE, .partition_label = "storage",
        .max_files = 4, .format_if_mount_failed = true,
    };
    s_spiffs_ok = (esp_vfs_spiffs_register(&c) == ESP_OK);
    if (!s_spiffs_ok) ESP_LOGW(TAG, "SPIFFS 'storage' mount fehlgeschlagen");
}
static void storage_usage(size_t *total, size_t *used)
{
    *total = 0; *used = 0;
    if (s_spiffs_ok) esp_spiffs_info("storage", total, used);
}
// Dateinamen auf sichere Zeichen beschraenken (kein Pfad-Traversal).
static bool sanitize_name(const char *in, char *out, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < n; i++) {
        char ch = in[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')
            out[o++] = ch;
    }
    out[o] = 0;
    return o > 0;
}

// Chunk-Helfer: formatiert + sendet ein HTML-Fragment.
#define SENDF(req, ...) do { char _sb[1600]; snprintf(_sb, sizeof(_sb), __VA_ARGS__); \
                             httpd_resp_sendstr_chunk((req), _sb); } while (0)

static const char PAGE_CSS[] =
    "<style>body{font-family:sans-serif;background:#0f1626;color:#e6e6e6;"
    "text-align:center;padding:24px}h1{color:#5cc8ff}.ok{color:#43d17a}"
    ".card{background:#16203c;border:1px solid #33406a;border-radius:10px;"
    "max-width:480px;margin:16px auto;padding:16px;text-align:left}"
    "h2{color:#5cc8ff;font-size:16px;margin:0 0 8px;border-bottom:1px solid #33406a;padding-bottom:4px}"
    "button{padding:8px 14px}a{color:#5cc8ff}.k{color:#8ab4f8;font-size:13px}.v{font-size:13px}"
    "input,select{padding:6px;border-radius:6px;border:1px solid #33406a;background:#0f1626;color:#e6e6e6}"
    "progress{width:100%;margin-top:8px}</style>";

static const char SCAN_JS[] =
    "<script>function scan(){var d=document.getElementById('nets');d.textContent='scanne ...';"
    "fetch('/scan').then(function(r){return r.json();}).then(function(a){d.innerHTML='';"
    "a.forEach(function(n){var b=document.createElement('button');b.type='button';"
    "b.style.cssText='display:block;width:92%;margin:2px auto';"
    "b.textContent=(n.lock?'* ':'  ')+n.ssid+' ('+n.rssi+' dBm)';"
    "b.onclick=function(){document.getElementsByName('ssid')[0].value=n.ssid;};"
    "d.appendChild(b);});if(!a.length){d.textContent='keine Netze gefunden';}"
    "}).catch(function(){d.textContent='Scan-Fehler';});}</script>";

static const char UPLOAD_JS[] =
    "<form id=uf style='margin-top:8px'><input type=file id=uff required> "
    "<button type=submit>Datei hochladen</button></form><div id=ust class=v></div>"
    "<script>uf.onsubmit=function(e){e.preventDefault();var f=uff.files[0];if(!f)return;"
    "var x=new XMLHttpRequest();x.open('POST','/upload?name='+encodeURIComponent(f.name));"
    "x.onload=function(){ust.textContent=x.responseText;if(x.status==200)setTimeout(function(){location.reload();},800);};"
    "x.onerror=function(){ust.textContent='Fehler';};x.send(f);};</script>";

static const char CONFIG_JS[] =
    "<script>"
    "cf.onsubmit=function(e){e.preventDefault();var f=cff.files[0];if(!f)return;"
    "var x=new XMLHttpRequest();x.open('POST','/config/import');"
    "x.onload=function(){cst.textContent=x.responseText;if(x.status==200)setTimeout(function(){location.href='/';},6000);};"
    "x.onerror=function(){cst.textContent='Fehler';};x.send(f);};"
    "function ccheck(){var s=document.getElementById('cchk');s.textContent='pruefe ...';"
    "fetch('/config/check').then(function(r){return r.json();}).then(function(j){"
    "var a=document.getElementById('capply');"
    "if(j.result<0){s.textContent='keine Datei / Server nicht erreichbar / Secret falsch';a.innerHTML='';return;}"
    "if(j.available){s.textContent='NEUE Konfig v'+j.server_version+' (aktuell v'+j.current_version+')';"
    "a.innerHTML='<button type=button onclick=\"capply()\">Neue Konfig einspielen</button>';}"
    "else{s.textContent='keine neue (Server v'+j.server_version+', aktuell v'+j.current_version+')';a.innerHTML='';}"
    "}).catch(function(){s.textContent='Fehler';});}"
    "function capply(){if(!confirm('Server-Konfig einspielen? Geraet startet neu.'))return;"
    "var x=new XMLHttpRequest();x.open('POST','/config/apply');"
    "x.onload=function(){document.getElementById('capply').textContent=x.responseText;"
    "if(x.status==200)setTimeout(function(){location.href='/';},6000);};x.send();}"
    "</script>";

static const char OTA_JS[] =
    "<script>f.onsubmit=function(e){e.preventDefault();var file=fw.files[0];if(!file)return;"
    "var x=new XMLHttpRequest();x.open('POST','/ota');p.hidden=false;"
    "x.upload.onprogress=function(ev){var v=Math.round(ev.loaded/ev.total*100);p.value=v;st.textContent=v+'%';};"
    "x.onload=function(){st.textContent=x.responseText;if(x.status==200)setTimeout(function(){location.reload();},5000);};"
    "x.onerror=function(){st.textContent='Fehler beim Upload';};x.send(file);};</script>";

static void send_head(httpd_req_t *req, const char *title)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'><title>");
    httpd_resp_sendstr_chunk(req, title);
    httpd_resp_sendstr_chunk(req, "</title>");
    httpd_resp_sendstr_chunk(req, PAGE_CSS);
    httpd_resp_sendstr_chunk(req, "</head><body>");
}

// Ressourcenliste (RDP/Link/SSH). admin=true -> mit Loeschen-Button.
// Gespeicherte WLANs (Prioritaet = Reihenfolge). admin=true -> hoch/loeschen.
static void send_wlan_list(httpd_req_t *req, bool admin)
{
    if (s_wlan_count == 0) { httpd_resp_sendstr_chunk(req, "<div class=k>keine gespeichert</div>"); return; }
    for (int i = 0; i < s_wlan_count; i++) {
        const char *cur = (i == s_wlan_current && s_wifi_connected) ? " &#10003;" : "";
        if (admin)
            SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>"
                "%d. <b>%s</b>%s &nbsp;"
                "<form method=post action=/wlanup style='display:inline'><input type=hidden name=i value=%d>"
                "<button style='font-size:11px'>hoch</button></form> "
                "<form method=post action=/wlandel style='display:inline'><input type=hidden name=i value=%d>"
                "<button style='font-size:11px'>löschen</button></form></div>",
                i + 1, s_wlans[i].ssid, cur, i, i);
        else
            SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>%d. <b>%s</b>%s</div>",
                  i + 1, s_wlans[i].ssid, cur);
    }
}

static void send_res_list(httpd_req_t *req, bool admin)
{
    if (s_res_count == 0) { httpd_resp_sendstr_chunk(req, "<div class=k>keine Ressourcen</div>"); return; }
    for (int i = 0; i < s_res_count; i++) {
        resource_t *r = &s_res[i];
        char action[200];
        if (strcmp(r->type, "link") == 0) {
            // Ohne Schema (kein "://") waere der Link relativ zur Dongle-Seite
            // -> http:// voranstellen, damit z.B. "10.10.0.1" korrekt oeffnet.
            const char *scheme = strstr(r->addr, "://") ? "" : "http://";
            snprintf(action, sizeof(action), "<a href='%s%s' target=_blank>Öffnen</a>", scheme, r->addr);
        } else if (strcmp(r->type, "ssh") == 0)
            snprintf(action, sizeof(action), "<a href='ssh://%s'>SSH</a>", r->addr);
        else
            snprintf(action, sizeof(action), "<a href='/rdp?i=%d'>RDP herunterladen</a>", i);
        if (admin)
            SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>"
                "<b>%s</b> <span class=k>[%s]</span><br>%s &nbsp; "
                "<form method=post action=/resdel style='display:inline'>"
                "<input type=hidden name=i value=%d><button style='font-size:11px'>löschen</button></form></div>",
                r->name, r->type, action, i);
        else
            SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>"
                "<b>%s</b> <span class=k>[%s]</span><br>%s</div>", r->name, r->type, action);
    }
}

// Hochgeladene Dateien. admin=true -> mit Loeschen-Button.
static void send_file_list(httpd_req_t *req, bool admin)
{
    DIR *d = opendir(SPIFFS_BASE);
    int n = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            char full[300]; struct stat stt; char sz[24] = "";
            snprintf(full, sizeof(full), SPIFFS_BASE "/%s", e->d_name);
            if (stat(full, &stt) == 0) {
                if (!S_ISREG(stt.st_mode)) continue;
                snprintf(sz, sizeof(sz), " (%ld B)", (long)stt.st_size);
            }
            n++;
            if (admin)
                SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>"
                    "<a href='/dl?name=%s'>%s</a>%s &nbsp; "
                    "<form method=post action=/delfile style='display:inline'>"
                    "<input type=hidden name=name value='%s'><button style='font-size:11px'>löschen</button></form></div>",
                    e->d_name, e->d_name, sz, e->d_name);
            else
                SENDF(req, "<div class=v style='border-top:1px solid #33406a;padding:4px'>"
                    "<a href='/dl?name=%s'>%s</a>%s</div>", e->d_name, e->d_name, sz);
        }
        closedir(d);
    }
    if (n == 0) httpd_resp_sendstr_chunk(req, "<div class=k>keine Dateien</div>");
}

// System-Status: Uptime, Heap, Task-Stacks, freier Datei-Speicher.
static void send_status(httpd_req_t *req)
{
    unsigned upt = (unsigned)(esp_timer_get_time() / 1000000LL);
    SENDF(req, "<div class=v>Uptime: %u s (%uh %02um %02us)</div>",
          upt, upt / 3600, (upt % 3600) / 60, upt % 60);
    SENDF(req, "<div class=v>Heap frei: %u B &nbsp; min. je frei: %u B</div>",
          (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size());
    SENDF(req, "<div class=v>größter freier Block: %u B</div>",
          (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    size_t tot = 0, used = 0; storage_usage(&tot, &used);
    SENDF(req, "<div class=v>Datei-Speicher: %u KB frei von %u KB</div>",
          (unsigned)((tot - used) / 1024), (unsigned)(tot / 1024));
    httpd_resp_sendstr_chunk(req, "<div class=k style='margin-top:6px'>Task-Stacks (kleinster freier Rest):</div>");
#if configUSE_TRACE_FACILITY
    UBaseType_t num = uxTaskGetNumberOfTasks();
    TaskStatus_t *arr = malloc(num * sizeof(TaskStatus_t));
    if (arr) {
        num = uxTaskGetSystemState(arr, num, NULL);
        for (UBaseType_t i = 0; i < num; i++)
            SENDF(req, "<div class=v>%-16s %6u B</div>", arr[i].pcTaskName,
                  (unsigned)(arr[i].usStackHighWaterMark * sizeof(StackType_t)));
        free(arr);
    }
#else
    httpd_resp_sendstr_chunk(req, "<div class=v>(Trace-Facility deaktiviert)</div>");
#endif
}

// --- Oeffentliche Startseite (ohne Login) -----------------------------------
static esp_err_t root_get(httpd_req_t *req)
{
    char ipbuf[16];
    if (s_wifi_connected) snprintf(ipbuf, sizeof(ipbuf), IPSTR, IP2STR(&s_wifi_ip));
    else                  snprintf(ipbuf, sizeof(ipbuf), "-");

    const esp_app_desc_t *app = esp_app_get_description();
    send_head(req, "ESP32 USB VPN");
    httpd_resp_sendstr_chunk(req, "<h1>ESP32-USB-VPN-Dongle</h1>"
        "<p class=ok>USB-NCM aktiv - PC per DHCP am Dongle (192.168.226.1).</p>");
    SENDF(req, "<div class=k style='margin:-8px auto 8px'>Firmware %s (%s) &middot; Konfig v%d</div>",
          app ? app->version : "?", FW_BUILD_TAG, (int)s_cfg_version);

    // WLAN-Signalstaerke (nur wenn verbunden).
    int rssi = 0; bool rssi_ok = false;
    if (s_wifi_connected) {
        wifi_ap_record_t apr;
        if (esp_wifi_sta_get_ap_info(&apr) == ESP_OK) { rssi = apr.rssi; rssi_ok = true; }
    }

    // WLAN-Karte (Status, Signal, gespeicherte WLANs, Scan, hinzufuegen) -- ohne Login.
    SENDF(req, "<div class=card><h2>WLAN</h2>"
        "<div class=v>Status: <b style='color:%s'>%s</b>%s%s</div>"
        "<div class=v>IP vom Router: %s</div>"
        "<div class=v>Internet-Routing: <b style='color:%s'>%s</b></div>",
        s_wifi_connected ? "#43d17a" : "#f0a35e",
        s_wifi_connected ? "verbunden" : (s_wifi_ssid[0] ? "verbinde ..." : "nicht konfiguriert"),
        s_wifi_connected ? " mit " : "", s_wifi_connected ? s_wifi_ssid : "",
        ipbuf,
        (s_nat_on && s_wifi_connected) ? "#43d17a" : "#f0a35e",
        (s_nat_on && s_wifi_connected) ? "aktiv (NAT)" : (s_nat_on ? "wartet auf WLAN" : "aus"));
    // Signalstaerke als dBm + Qualitaetslabel + Balken (0..100 % aus dBm).
    if (rssi_ok) {
        const char *ql, *qc;
        if      (rssi >= -55) { ql = "ausgezeichnet"; qc = "#43d17a"; }
        else if (rssi >= -67) { ql = "gut";           qc = "#43d17a"; }
        else if (rssi >= -75) { ql = "mittel";        qc = "#f0a35e"; }
        else                  { ql = "schwach";       qc = "#ef6b6b"; }
        int pct = 2 * (rssi + 100);
        if (pct < 0) pct = 0; else if (pct > 100) pct = 100;
        SENDF(req, "<div class=v style='margin-top:4px'>Signal: <b style='color:%s'>%d dBm &middot; %s</b></div>"
            "<div style='height:8px;background:#0f1626;border:1px solid #33406a;border-radius:4px;margin-top:3px'>"
            "<div style='height:100%%;width:%d%%;background:%s;border-radius:3px'></div></div>",
            qc, rssi, ql, pct, qc);
    }
    httpd_resp_sendstr_chunk(req, "<div class=k style='margin-top:6px'>Gespeicherte WLANs (Prioritaet):</div>");
    send_wlan_list(req, false);
    httpd_resp_sendstr_chunk(req,
        "<button type=button onclick='scan()' style='margin:6px'>Netzwerke suchen</button>"
        "<div id=nets class=v></div>"
        "<form method=post action=/wifi>"
        "<input name=ssid placeholder=SSID style='width:90%;margin:3px' required><br>"
        "<input name=pass type=password placeholder=Passwort style='width:90%;margin:3px'><br>"
        "<button type=submit>WLAN hinzufügen / verbinden</button></form></div>");

    // VPN nur Status (read-only).
    SENDF(req, "<div class=card><h2>VPN-Status</h2>"
        "<div class=v>Tunnel: <b style='color:%s'>%s</b></div>"
        "<div class=v>Endpoint: %s:%d</div>"
        "<div class=v>Routing: %s</div>"
        "<div class=v>Kill-Switch: %s</div></div>",
        s_wg_up ? "#43d17a" : "#f0a35e",
        s_wg_up ? "verbunden" : (wg_configured() ? (s_vpn_off ? "deaktiviert"
            : (s_wg_started ? "verbinde ..." : "wartet auf WLAN")) : "nicht konfiguriert"),
        s_wg_endpoint, s_wg_port,
        s_wg_default_set ? "Volltunnel aktiv" : (s_wg_fulltunnel ? "Volltunnel (wartet)" : "nur Tunnel"),
        s_killswitch ? "scharf" : "aus");

    // Ressourcen + Dateien zum Download (read-only).
    httpd_resp_sendstr_chunk(req, "<div class=card><h2>Ressourcen / Downloads</h2>");
    send_res_list(req, false);
    httpd_resp_sendstr_chunk(req, "<div class=k style='margin-top:6px'>Dateien:</div>");
    send_file_list(req, false);
    httpd_resp_sendstr_chunk(req, "</div>");

    httpd_resp_sendstr_chunk(req, "<div class=card><a href='/settings'>&#9881; Einstellungen (Anmeldung erforderlich)</a></div>");
    httpd_resp_sendstr_chunk(req, SCAN_JS);
    httpd_resp_sendstr_chunk(req, "</body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

// --- Einstellungsseite (Login) ----------------------------------------------
static esp_err_t settings_get(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    const esp_app_desc_t *app = esp_app_get_description();

    send_head(req, "Einstellungen");
    httpd_resp_sendstr_chunk(req, "<h1>Einstellungen</h1>"
        "<div class=card><a href='/'>&#8592; zur Startseite</a></div>");
    if (s_admin_is_default)
        httpd_resp_sendstr_chunk(req, "<div class=card style='color:#ff6b6b'>"
            "<b>Standard-Passwort aktiv (admin/admin) - bitte ändern!</b></div>");

    // System-Status.
    httpd_resp_sendstr_chunk(req, "<div class=card><h2>System-Status</h2>");
    send_status(req);
    httpd_resp_sendstr_chunk(req, "</div>");

    // System: Name + Seriennummer (MAC) + Konfig-Secret + Config-Server.
    { char sn[13]; sn_string(sn);
      SENDF(req, "<div class=card><h2>System</h2>"
        "<div class=v>Seriennummer (SN): <b>%s</b></div>"
        "<div class=v>Firmware: <b>%s</b> (%s)</div>"
        "<div class=v>Konfig-Version: <b>%d</b></div>"
        "<form method=post action=/sys style='font-size:13px'>"
        "<input name=name placeholder=Systemname value='%s' style='width:90%%;margin:2px'><br>"
        "<input name=secret type=password placeholder='Konfig-Secret (20 alphanum., leer=unveraendert)' style='width:90%%;margin:2px'><br>"
        "<input name=server placeholder='Config-Server-URL http://...' value='%s' style='width:90%%;margin:2px'><br>"
        "<button type=submit>Speichern</button></form></div>",
        sn, app ? app->version : "?", FW_BUILD_TAG, (int)s_cfg_version,
        s_systemname, s_cfg_server); }

    // Konfiguration: verschluesselter Export/Import + Config-Server-Abfrage.
    SENDF(req, "<div class=card><h2>Konfiguration</h2>"
        "<div class=v>Konfig-Secret: <b>%s</b></div>"
        "<div class=v style='margin-top:4px'><a href='/config/export'>&#11015; Konfig herunterladen (verschluesselt)</a></div>"
        "<form id=cf style='margin-top:6px;font-size:13px'><input type=file id=cff accept='.bhvpn' required> "
        "<button type=submit>Konfig hochladen + einspielen</button></form><div id=cst class=v></div>"
        "<div style='border-top:1px solid #33406a;margin-top:8px;padding-top:6px'>"
        "<div class=v>Config-Server: %s</div>"
        "<button type=button onclick='ccheck()' style='margin-top:4px'>Beim Server pruefen</button> "
        "<span id=cchk class=v></span><div id=capply style='margin-top:6px'></div></div></div>",
        s_cfg_secret[0] ? "gesetzt" : "NICHT gesetzt (fuer Up-/Download noetig)",
        s_cfg_server[0] ? s_cfg_server : "(keiner)");

    // Internet-Zugang (Captive) + Auto-Captive-Einstellung.
    SENDF(req, "<div class=card><h2>Internet-Zugang</h2>"
        "<div class=v>Status: <b style='color:%s'>%s</b></div>"
        "<form method=post action=/sys style='margin-top:6px;font-size:13px'>"
        "<input type=hidden name=capform value=1>"
        "<label><input type=checkbox name=capauto %s> Captive-Portal automatisch bei fehlendem WLAN</label> "
        "<button type=submit>Speichern</button></form>%s</div>",
        s_unlocked ? "#43d17a" : "#f0a35e", s_unlocked ? "frei" : "gesperrt",
        s_captive_auto ? "checked" : "",
        s_captive_auto
            ? "<div class=k style='margin-top:4px'>Automatik aktiv: WLAN steuert den Zustand (kein WLAN &rarr; Anmelde-Portal).</div>"
            : (s_unlocked ? "<form method=post action=/lock style='margin-top:4px'><button>Sperren</button></form>"
                          : "<form method=post action=/unlock style='margin-top:4px'><button>Freigeben</button></form>"));

    // WLAN-Verwaltung: gespeicherte WLANs (Prioritaet), hoch/loeschen + hinzufuegen.
    httpd_resp_sendstr_chunk(req, "<div class=card><h2>WLAN-Verwaltung</h2>"
        "<div class=k>Reihenfolge = Prioritaet. Der Dongle nutzt das hoechstpriore "
        "verfuegbare WLAN und wechselt automatisch (z. B. Hotspot &harr; Arbeitsplatz).</div>");
    send_wlan_list(req, true);
    httpd_resp_sendstr_chunk(req,
        "<form method=post action=/wifi style='font-size:13px;margin-top:6px'>"
        "<input name=ssid placeholder=SSID style='width:90%;margin:2px' required><br>"
        "<input name=pass type=password placeholder=Passwort style='width:90%;margin:2px'><br>"
        "<button type=submit>WLAN hinzufügen / verbinden</button></form></div>");

    // WireGuard-Konfig + VPN-Schalter (in 2 Chunks wegen Groesse).
    SENDF(req, "<div class=card><h2>WireGuard-VPN</h2>"
        "<div class=v>Tunnel: <b style='color:%s'>%s</b> &nbsp; VPN-Schalter: <b style='color:%s'>%s</b></div>%s",
        s_wg_up ? "#43d17a" : "#f0a35e", s_wg_up ? "verbunden" : "getrennt",
        s_vpn_off ? "#ff6b6b" : "#43d17a", s_vpn_off ? "AUS" : "AN",
        s_vpn_off ? "<form method=post action=/vpn><input type=hidden name=state value=on><button>VPN einschalten</button></form>"
                  : "<form method=post action=/vpn><input type=hidden name=state value=off><button>VPN ausschalten</button></form>");
    SENDF(req, "<form method=post action=/wg style='font-size:13px'>"
        "<input name=priv type=password placeholder='Private Key (leer=unverändert)' style='width:90%%;margin:2px'><br>"
        "<input name=pub placeholder='Peer Public Key' value='%s' style='width:90%%;margin:2px' required><br>"
        "<input name=psk type=password placeholder='Preshared Key (optional)' style='width:90%%;margin:2px'><br>"
        "<input name=ep placeholder='Endpoint Host/IP' value='%s' style='width:58%%;margin:2px' required>"
        "<input name=port placeholder=Port value='%d' style='width:28%%;margin:2px'><br>"
        "<input name=addr placeholder='Tunnel-IP' value='%s' style='width:58%%;margin:2px' required>"
        "<input name=mask placeholder=Maske value='%s' style='width:28%%;margin:2px'><br>"
        "<input name=ka placeholder='Keepalive s' value='%d' style='width:40%%;margin:2px'><br>"
        "<label><input type=checkbox name=full value=1 %s> Volltunnel</label><br>"
        "<label><input type=checkbox name=ks value=1 %s> Kill-Switch</label><br>"
        "<button type=submit>Tunnel speichern + verbinden</button></form></div>",
        s_wg_pub, s_wg_endpoint, s_wg_port, s_wg_addr, s_wg_netmask, s_wg_keepalive,
        s_wg_fulltunnel ? "checked" : "", s_killswitch ? "checked" : "");

    // Admin-Zugang.
    SENDF(req, "<div class=card><h2>Admin-Zugang</h2><div class=v>Benutzer: %s</div>"
        "<form method=post action=/admin style='font-size:13px'>"
        "<input name=user placeholder=Benutzer value='%s' style='width:90%%;margin:2px'><br>"
        "<input name=pass type=password placeholder='Neues Passwort' style='width:90%%;margin:2px' required><br>"
        "<button type=submit>Passwort speichern</button></form></div>",
        s_admin_user, s_admin_user);

    // Ressourcenmanager (anlegen/loeschen + Datei-Upload + freier Speicher).
    httpd_resp_sendstr_chunk(req, "<div class=card><h2>Ressourcenmanager</h2>");
    send_res_list(req, true);
    httpd_resp_sendstr_chunk(req,
        "<form method=post action=/res style='font-size:13px;margin-top:6px'>"
        "<input name=name placeholder=Name style='width:90%;margin:2px' required><br>"
        "<select name=type style='margin:2px'><option value=rdp>RDP</option>"
        "<option value=link>Link</option><option value=ssh>SSH</option></select> "
        "<input name=addr placeholder='Adresse / URL' style='width:50%;margin:2px' required>"
        "<input name=port placeholder=Port style='width:18%;margin:2px'><br>"
        "<button type=submit>Ressource hinzufügen</button></form>");
    { size_t tot = 0, used = 0; storage_usage(&tot, &used);
      SENDF(req, "<div class=k style='margin-top:8px'>Dateien (frei: %u / %u KB):</div>",
            (unsigned)((tot - used) / 1024), (unsigned)(tot / 1024)); }
    send_file_list(req, true);
    httpd_resp_sendstr_chunk(req, UPLOAD_JS);
    httpd_resp_sendstr_chunk(req, "</div>");

    // Zuruecksetzen.
    httpd_resp_sendstr_chunk(req, "<div class=card><h2>Zurücksetzen</h2>"
        "<form method=post action=/reset onsubmit=\"return confirm('Wirklich zurücksetzen? Das Gerät startet neu.')\">"
        "<button name=scope value=wifi>nur WLAN</button> "
        "<button name=scope value=wg>nur VPN</button><br><br>"
        "<button name=scope value=wifiwg>WLAN + VPN</button> "
        "<button name=scope value=all style='color:#ff6b6b'>ALLES (Werksreset)</button>"
        "</form></div>");

    // Firmware-Update (OTA).
    SENDF(req, "<div class=card><h2>Firmware-Update (OTA)</h2>"
        "<div class=k>Version: %s &nbsp; Build: %s &nbsp; Partition: %s</div>"
        "<form id=f><input type=file id=fw accept='.bin' required> "
        "<button type=submit>Update einspielen</button></form>"
        "<progress id=p max=100 value=0 hidden></progress><div id=st class=v></div></div>",
        app ? app->version : "?", FW_BUILD_TAG, esp_ota_get_running_partition()->label);
    httpd_resp_sendstr_chunk(req, CONFIG_JS);
    httpd_resp_sendstr_chunk(req, OTA_JS);
    httpd_resp_sendstr_chunk(req, "</body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

// OTA: roher .bin-Body in die inaktive Partition schreiben, dann Neustart.
// (Phase 1: ohne Auth — wird in Phase 7 auf Admin beschraenkt.)
static esp_err_t ota_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "keine OTA-Partition"); return ESP_FAIL; }

    esp_ota_handle_t h = 0;
    if (esp_ota_begin(part, OTA_SIZE_UNKNOWN, &h) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin fehlgeschlagen");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "OTA-Upload -> Partition '%s' (%d Bytes)", part->label, req->content_len);

    static char buf[1024];
    int remaining = req->content_len;
    while (remaining > 0) {
        int want = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, want);
        if (r <= 0) { esp_ota_abort(h); httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empfang abgebrochen"); return ESP_FAIL; }
        if (esp_ota_write(h, buf, r) != ESP_OK) { esp_ota_abort(h); httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Schreibfehler"); return ESP_FAIL; }
        remaining -= r;
    }
    if (esp_ota_end(h) != ESP_OK) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Image ungueltig"); return ESP_FAIL; }
    if (esp_ota_set_boot_partition(part) != ESP_OK) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Boot-Partition setzen fehlgeschlagen"); return ESP_FAIL; }

    httpd_resp_sendstr(req, "Update OK - Geraet startet neu ...");
    ESP_LOGI(TAG, "OTA erfolgreich, Neustart");
    vTaskDelay(pdMS_TO_TICKS(600));
    esp_restart();
    return ESP_OK;
}

// %XX / '+' aus x-www-form-urlencoded dekodieren (in-place-sicher: dst != src).
static void url_decode(char *dst, const char *src, size_t dst_size)
{
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 1 < dst_size; i++) {
        if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            char hex[3] = { src[i + 1], src[i + 2], 0 };
            dst[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            dst[o++] = ' ';
        } else {
            dst[o++] = src[i];
        }
    }
    dst[o] = 0;
}

// WLAN-Zugangsdaten aus dem Webformular uebernehmen (ssid=...&pass=...).
static esp_err_t wifi_post(httpd_req_t *req)
{
    // Oeffentlich (WLAN-Einrichtung ohne Login).
    char body[256];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int r = httpd_req_recv(req, body, len);
    if (r <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Body"); return ESP_FAIL; }
    body[r] = 0;

    char ssid_enc[96] = { 0 }, pass_enc[128] = { 0 };
    char ssid[33] = { 0 }, pass[64] = { 0 };
    if (httpd_query_key_value(body, "ssid", ssid_enc, sizeof(ssid_enc)) == ESP_OK)
        url_decode(ssid, ssid_enc, sizeof(ssid));
    if (httpd_query_key_value(body, "pass", pass_enc, sizeof(pass_enc)) == ESP_OK)
        url_decode(pass, pass_enc, sizeof(pass));

    if (!ssid[0]) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID fehlt"); return ESP_FAIL; }
    wifi_apply(ssid, pass);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req,
        "<!doctype html><meta charset=utf-8>"
        "<body style='font-family:sans-serif;background:#0f1626;color:#e6e6e6;"
        "text-align:center;padding:40px'><h2>Gespeichert - verbinde mit WLAN ...</h2>"
        "<p><a href='/' style='color:#5cc8ff'>Zurück zur Statusseite</a></p>"
        "<script>setTimeout(function(){location.href='/';},4000);</script></body>");
}

// Admin-Zugang aendern (Benutzer optional, Passwort erforderlich).
static esp_err_t admin_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[256];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int r = httpd_req_recv(req, body, len);
    if (r <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Body"); return ESP_FAIL; }
    body[r] = 0;
    char enc[128], user[24] = {0}, pass[64] = {0};
    if (httpd_query_key_value(body, "user", enc, sizeof(enc)) == ESP_OK) url_decode(user, enc, sizeof(user));
    if (httpd_query_key_value(body, "pass", enc, sizeof(enc)) == ESP_OK) url_decode(pass, enc, sizeof(pass));
    if (!pass[0]) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Passwort fehlt"); return ESP_FAIL; }
    admin_save(user[0] ? user : s_admin_user, pass);
    ESP_LOGI(TAG, "Admin-Zugang geaendert (User '%s')", s_admin_user);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// RDP-Datei fuer Ressource i dynamisch erzeugen + zum Download ausliefern.
// (offen: nutzerseitig; Adressliste ist ohnehin auf der Statusseite sichtbar)
static esp_err_t rdp_get(httpd_req_t *req)
{
    char q[24]; int idx = -1;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char v[8];
        if (httpd_query_key_value(q, "i", v, sizeof(v)) == ESP_OK) idx = atoi(v);
    }
    if (idx < 0 || idx >= s_res_count) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "unbekannt"); return ESP_FAIL; }
    resource_t *r = &s_res[idx];
    int port = r->port ? r->port : 3389;
    static char rdp[512];
    snprintf(rdp, sizeof(rdp),
        "full address:s:%s:%d\r\n"
        "prompt for credentials:i:1\r\n"
        "screen mode id:i:2\r\n"
        "administrative session:i:0\r\n",
        r->addr, port);
    char disp[96];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s.rdp\"", r->name);
    httpd_resp_set_type(req, "application/x-rdp");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    return httpd_resp_sendstr(req, rdp);
}

// Ressource hinzufuegen (Admin).
static esp_err_t res_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[320];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int rr = httpd_req_recv(req, body, len);
    if (rr <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Body"); return ESP_FAIL; }
    body[rr] = 0;
    char enc[128];
    resource_t r = {0};
    if (httpd_query_key_value(body, "name", enc, sizeof(enc)) == ESP_OK) url_decode(r.name, enc, sizeof(r.name));
    if (httpd_query_key_value(body, "type", enc, sizeof(enc)) == ESP_OK) url_decode(r.type, enc, sizeof(r.type));
    if (httpd_query_key_value(body, "addr", enc, sizeof(enc)) == ESP_OK) url_decode(r.addr, enc, sizeof(r.addr));
    if (httpd_query_key_value(body, "port", enc, sizeof(enc)) == ESP_OK) r.port = (uint16_t)atoi(enc);
    if (!r.type[0]) strcpy(r.type, "rdp");
    if (r.name[0] && r.addr[0] && s_res_count < MAX_RES) {
        s_res[s_res_count++] = r;
        res_save();
        ESP_LOGI(TAG, "Ressource hinzugefuegt: %s (%s)", r.name, r.type);
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// Ressource i loeschen (Admin).
static esp_err_t resdel_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[48];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int rr = httpd_req_recv(req, body, len);
    if (rr > 0) {
        body[rr] = 0;
        char v[8]; int idx = -1;
        if (httpd_query_key_value(body, "i", v, sizeof(v)) == ESP_OK) idx = atoi(v);
        if (idx >= 0 && idx < s_res_count) {
            for (int k = idx; k < s_res_count - 1; k++) s_res[k] = s_res[k + 1];
            s_res_count--;
            res_save();
        }
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// --- Reset (Admin): NVS-Namespaces loeschen + Neustart ----------------------
static void nvs_erase_ns(const char *ns)
{
    nvs_handle_t h;
    if (nvs_open(ns, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }
}
static esp_err_t reset_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[48] = {0};
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    if (len > 0) { int r = httpd_req_recv(req, body, len); if (r > 0) body[r] = 0; }
    char v[16] = {0};
    httpd_query_key_value(body, "scope", v, sizeof(v));
    const char *msg;
    if      (!strcmp(v, "all"))    { nvs_flash_erase();                       msg = "Werksreset (alles)"; }
    else if (!strcmp(v, "wifi"))   { nvs_erase_ns("wifi");                    msg = "WLAN zurueckgesetzt"; }
    else if (!strcmp(v, "wg"))     { nvs_erase_ns("wg");                      msg = "VPN zurueckgesetzt"; }
    else if (!strcmp(v, "wifiwg")) { nvs_erase_ns("wifi"); nvs_erase_ns("wg");msg = "WLAN+VPN zurueckgesetzt"; }
    else { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "scope?"); return ESP_FAIL; }
    ESP_LOGW(TAG, "RESET: %s -> Neustart", msg);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr(req, "<!doctype html><meta charset=utf-8><body style='font-family:sans-serif;"
        "background:#0f1626;color:#e6e6e6;text-align:center;padding:40px'>"
        "<h2>Zurückgesetzt - Gerät startet neu ...</h2></body>");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

// --- Datei-Upload (Admin) in die SPIFFS-Ablage ------------------------------
static esp_err_t upload_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    if (!s_spiffs_ok) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "kein Speicher"); return ESP_FAIL; }
    char q[160] = {0}, raw[80] = {0}, dec[80] = {0}, name[80] = {0};
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK)
        httpd_query_key_value(q, "name", raw, sizeof(raw));
    url_decode(dec, raw, sizeof(dec));
    if (!sanitize_name(dec, name, sizeof(name))) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Dateiname?"); return ESP_FAIL; }
    char path[160]; snprintf(path, sizeof(path), SPIFFS_BASE "/%s", name);
    FILE *f = fopen(path, "wb");
    if (!f) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "open fehlgeschlagen"); return ESP_FAIL; }
    static char buf[1024];
    int rem = req->content_len; bool ok = true;
    while (rem > 0) {
        int want = rem < (int)sizeof(buf) ? rem : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, want);
        if (r <= 0) { ok = false; break; }
        if (fwrite(buf, 1, r, f) != (size_t)r) { ok = false; break; }
        rem -= r;
    }
    fclose(f);
    if (!ok) { unlink(path); httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Schreibfehler (Speicher voll?)"); return ESP_FAIL; }
    ESP_LOGI(TAG, "Upload gespeichert: %s (%d B)", name, req->content_len);
    return httpd_resp_sendstr(req, "Upload OK");
}

// --- Datei-Download (oeffentlich) aus der SPIFFS-Ablage ---------------------
static esp_err_t dl_get(httpd_req_t *req)
{
    char q[160] = {0}, raw[80] = {0}, dec[80] = {0}, name[80] = {0};
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK)
        httpd_query_key_value(q, "name", raw, sizeof(raw));
    url_decode(dec, raw, sizeof(dec));
    if (!sanitize_name(dec, name, sizeof(name))) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Dateiname?"); return ESP_FAIL; }
    char path[160]; snprintf(path, sizeof(path), SPIFFS_BASE "/%s", name);
    FILE *f = fopen(path, "rb");
    if (!f) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "nicht gefunden"); return ESP_FAIL; }
    char disp[128]; snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", name);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    static char buf[1024]; size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, r) != ESP_OK) { fclose(f); return ESP_FAIL; }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

// --- Datei loeschen (Admin) -------------------------------------------------
static esp_err_t delfile_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[96] = {0};
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    if (len > 0) { int r = httpd_req_recv(req, body, len); if (r > 0) body[r] = 0; }
    char raw[80] = {0}, dec[80] = {0}, name[80] = {0};
    httpd_query_key_value(body, "name", raw, sizeof(raw));
    url_decode(dec, raw, sizeof(dec));
    if (sanitize_name(dec, name, sizeof(name))) {
        char path[160]; snprintf(path, sizeof(path), SPIFFS_BASE "/%s", name);
        unlink(path);
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// --- Config-Server (plain http, verschluesselte Datei je Seriennummer) ------
// GET <url>/<SN>/config.json -> malloc'd Body (NUL-terminiert) oder NULL.
static char *http_get_all(const char *url)
{
    esp_http_client_config_t cfg = { .url = url, .timeout_ms = 8000, .method = HTTP_METHOD_GET };
    esp_http_client_handle_t cl = esp_http_client_init(&cfg);
    if (!cl) return NULL;
    char *body = NULL;
    if (esp_http_client_open(cl, 0) == ESP_OK) {
        int clen = esp_http_client_fetch_headers(cl);
        if (esp_http_client_get_status_code(cl) == 200) {
            size_t cap = (clen > 0 && clen < 16384) ? (size_t)clen + 1 : 8192;
            body = malloc(cap);
            if (body) {
                int total = 0, r;
                while ((size_t)total < cap - 1 &&
                       (r = esp_http_client_read(cl, body + total, cap - 1 - total)) > 0) total += r;
                body[total] = 0;
            }
        }
        esp_http_client_close(cl);
    }
    esp_http_client_cleanup(cl);
    return body;
}
static void config_server_url(char *out, size_t n)
{
    char sn[13]; sn_string(sn);
    size_t l = strlen(s_cfg_server);
    while (l > 0 && s_cfg_server[l - 1] == '/') l--;
    snprintf(out, n, "%.*s/%s/config.json", (int)l, s_cfg_server, sn);
}
// -1 = Fehler/keine, 0 = keine neue, 1 = neue Version vorhanden.
static int config_server_check(void)
{
    s_cfg_update_available = false;
    if (!s_cfg_server[0] || !s_cfg_secret[0]) return -1;
    char url[208]; config_server_url(url, sizeof(url));
    char *ft = http_get_all(url);
    if (!ft) return -1;
    char *pt = config_decrypt(ft); free(ft);
    if (!pt) return -1;
    int ver = -1;
    for (char *p = pt; p; ) {
        if (!strncmp(p, "version=", 8)) { ver = atoi(p + 8); break; }
        char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : NULL;
    }
    free(pt);
    if (ver < 0) return -1;
    s_cfg_available_version = ver;
    if (ver > s_cfg_version) { s_cfg_update_available = true; return 1; }
    return 0;
}

// GET /config/export (Admin) -> verschluesselte Konfig als Download.
static esp_err_t config_export_get(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    if (!s_cfg_secret[0]) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Konfig-Secret gesetzt"); return ESP_FAIL; }
    char *json = config_export_json();
    char *enc = json ? config_encrypt(json) : NULL;
    free(json);
    if (!enc) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "export"); return ESP_FAIL; }
    char sn[13]; sn_string(sn);
    char disp[112];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s-%s.bhvpn\"",
             s_systemname[0] ? s_systemname : "dongle", sn);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_sendstr(req, enc);
    free(enc);
    return ESP_OK;
}
// POST /config/import (Admin): Datei -> entschluesseln + einspielen + Neustart.
static esp_err_t config_import_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    int len = req->content_len;
    if (len <= 0 || len > 16384) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Groesse"); return ESP_FAIL; }
    char *body = malloc(len + 1);
    if (!body) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "RAM"); return ESP_FAIL; }
    int total = 0, r;
    while (total < len && (r = httpd_req_recv(req, body + total, len - total)) > 0) total += r;
    body[total] = 0;
    char *pt = config_decrypt(body); free(body);
    if (!pt) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "falsches Secret oder ungueltige Datei"); return ESP_FAIL; }
    bool ok = config_import_json(pt); free(pt);
    if (!ok) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ungueltige Konfig"); return ESP_FAIL; }
    httpd_resp_sendstr(req, "Konfig eingespielt - Geraet startet neu ...");
    vTaskDelay(pdMS_TO_TICKS(600));
    esp_restart();
    return ESP_OK;
}
// POST /sys (Admin): Systemname / Config-Secret / Config-Server-URL.
static esp_err_t sys_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[512];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int r = httpd_req_recv(req, body, len);
    if (r <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Body"); return ESP_FAIL; }
    body[r] = 0;
    char enc[160], dec[160];
#define SYS_GETF(k, dst) do { if (httpd_query_key_value(body, k, enc, sizeof(enc)) == ESP_OK) { \
        url_decode(dec, enc, sizeof(dec)); strlcpy(dst, dec, sizeof(dst)); } } while (0)
    SYS_GETF("name", s_systemname);
    SYS_GETF("server", s_cfg_server);
    // Secret: nur bei Eingabe ueberschreiben; nur alphanumerisch, max 20 Zeichen.
    if (httpd_query_key_value(body, "secret", enc, sizeof(enc)) == ESP_OK) {
        url_decode(dec, enc, sizeof(dec));
        if (dec[0]) {
            char clean[24]; size_t o = 0;
            for (size_t i = 0; dec[i] && o < 20; i++) {
                char c = dec[i];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) clean[o++] = c;
            }
            clean[o] = 0;
            strlcpy(s_cfg_secret, clean, sizeof(s_cfg_secret));
        }
    }
#undef SYS_GETF
    // Captive-Auto nur anfassen, wenn DAS Captive-Formular gesendet wurde
    // (Marker capform) -> das System-Formular ohne Checkbox laesst es unberuehrt.
    if (httpd_query_key_value(body, "capform", enc, sizeof(enc)) == ESP_OK)
        s_captive_auto = (httpd_query_key_value(body, "capauto", enc, sizeof(enc)) == ESP_OK);
    sys_save();
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}
// GET /config/check (Admin): jetzt beim Config-Server nachsehen -> JSON-Status.
static esp_err_t config_check_get(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    int res = config_server_check();
    char out[160];
    snprintf(out, sizeof(out),
             "{\"result\":%d,\"available\":%s,\"server_version\":%d,\"current_version\":%d}",
             res, s_cfg_update_available ? "true" : "false",
             (int)s_cfg_available_version, (int)s_cfg_version);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, out);
}
// POST /config/apply (Admin): Konfig vom Server holen + einspielen + Neustart.
static esp_err_t config_apply_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    if (!s_cfg_server[0] || !s_cfg_secret[0]) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Server/Secret fehlt"); return ESP_FAIL; }
    char url[208]; config_server_url(url, sizeof(url));
    char *ft = http_get_all(url);
    if (!ft) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Server nicht erreichbar / keine Datei"); return ESP_FAIL; }
    char *pt = config_decrypt(ft); free(ft);
    if (!pt) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "falsches Secret / ungueltig"); return ESP_FAIL; }
    bool ok = config_import_json(pt); free(pt);
    if (!ok) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ungueltige Konfig"); return ESP_FAIL; }
    httpd_resp_sendstr(req, "Server-Konfig eingespielt - Neustart ...");
    vTaskDelay(pdMS_TO_TICKS(600));
    esp_restart();
    return ESP_OK;
}

// POST /wlandel (Admin): gespeichertes WLAN i loeschen.
static esp_err_t wlandel_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[32] = {0};
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    if (len > 0) { int r = httpd_req_recv(req, body, len); if (r > 0) body[r] = 0; }
    char v[8] = {0}; int idx = -1;
    if (httpd_query_key_value(body, "i", v, sizeof(v)) == ESP_OK) idx = atoi(v);
    if (idx >= 0 && idx < s_wlan_count) {
        bool was_current = (s_wlan_current == idx);
        for (int k = idx; k < s_wlan_count - 1; k++) s_wlans[k] = s_wlans[k + 1];
        memset(&s_wlans[s_wlan_count - 1], 0, sizeof(wlan_t));
        s_wlan_count--;
        if (s_wlan_current == idx) s_wlan_current = -1;
        else if (s_wlan_current > idx) s_wlan_current--;
        wlan_list_save();
        if (was_current) {
            // Aktives Ziel geloescht -> nicht auf verwaister Config haengen bleiben.
            if (s_wlan_count > 0) wlan_connect_to(0);
            else { esp_wifi_disconnect(); s_wifi_ssid[0] = 0; }
        }
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}
// POST /wlanup (Admin): WLAN i eine Prioritaet hoeher (mit i-1 tauschen).
static esp_err_t wlanup_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[32] = {0};
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    if (len > 0) { int r = httpd_req_recv(req, body, len); if (r > 0) body[r] = 0; }
    char v[8] = {0}; int idx = -1;
    if (httpd_query_key_value(body, "i", v, sizeof(v)) == ESP_OK) idx = atoi(v);
    if (idx > 0 && idx < s_wlan_count) {
        wlan_t tmp = s_wlans[idx - 1]; s_wlans[idx - 1] = s_wlans[idx]; s_wlans[idx] = tmp;
        if (s_wlan_current == idx) s_wlan_current = idx - 1;
        else if (s_wlan_current == idx - 1) s_wlan_current = idx;
        wlan_list_save();
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// Verfuegbare WLANs scannen -> JSON [{ssid,rssi,lock}]. Blockierender Scan (~3 s).
static esp_err_t scan_get(httpd_req_t *req)
{
    // Oeffentlich (WLAN-Scan gehoert zur WLAN-Einrichtung ohne Login).
    wifi_scan_config_t sc = { .show_hidden = false };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Scan fehlgeschlagen");
        return ESP_FAIL;
    }
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > 20) n = 20;
    wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(wifi_ap_record_t));
    if (!recs) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "kein RAM"); return ESP_FAIL; }
    esp_wifi_scan_get_ap_records(&n, recs);

    static char json[2048];
    size_t o = 0;
    o += snprintf(json + o, sizeof(json) - o, "[");
    for (uint16_t i = 0; i < n && o < sizeof(json) - 96; i++) {
        char esc[66]; size_t eo = 0;
        for (const char *p = (const char *)recs[i].ssid; *p && eo < sizeof(esc) - 2; p++) {
            if (*p == '"' || *p == '\\') esc[eo++] = '\\';
            esc[eo++] = *p;
        }
        esc[eo] = 0;
        if (esc[0] == 0) continue;   // versteckte SSID ueberspringen
        int locked = recs[i].authmode != WIFI_AUTH_OPEN;
        o += snprintf(json + o, sizeof(json) - o,
                      "%s{\"ssid\":\"%s\",\"rssi\":%d,\"lock\":%d}",
                      (o > 1 ? "," : ""), esc, recs[i].rssi, locked);
    }
    snprintf(json + o, sizeof(json) - o, "]");
    free(recs);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

// --- DNS-Server: Captive-Hijack (gesperrt) / Weiterleitung (entsperrt) --------
static uint32_t upstream_dns_addr(void)
{
    // Volltunnel aktiv: der STA-DNS liegt im lokalen WLAN und ist ueber die
    // WG-Default-Route nicht erreichbar -> oeffentlichen Resolver nehmen, der
    // durch den Tunnel geht.
    if (s_wg_default_set) return esp_ip4addr_aton("1.1.1.1");
    esp_netif_dns_info_t d;
    if (s_sta_netif && esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &d) == ESP_OK
        && d.ip.u_addr.ip4.addr != 0) {
        return d.ip.u_addr.ip4.addr;
    }
    return esp_ip4addr_aton("8.8.8.8");
}

static void dns_forward(int sock, uint8_t *q, int qlen, struct sockaddr_in *cli, socklen_t clen)
{
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0) return;
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in ups = { .sin_family = AF_INET, .sin_port = htons(53) };
    ups.sin_addr.s_addr = upstream_dns_addr();
    if (sendto(up, q, qlen, 0, (struct sockaddr *)&ups, sizeof(ups)) == qlen) {
        uint8_t resp[512];
        int rl = recv(up, resp, sizeof(resp), 0);
        if (rl > 0) sendto(sock, resp, rl, 0, (struct sockaddr *)cli, clen);
    }
    close(up);
}

// gesperrt: A-Anfragen -> 192.168.226.1, sonst leere Antwort (erzwingt Portal/IPv4)
static void dns_hijack(int sock, uint8_t *q, int qlen, struct sockaddr_in *cli, socklen_t clen)
{
    int i = 12;
    while (i < qlen && q[i] != 0) i += q[i] + 1;   // Frage-Name ueberspringen
    if (i + 5 > qlen) return;
    uint16_t qtype = (q[i + 1] << 8) | q[i + 2];
    int qsec_end = i + 5;

    uint8_t r[600];
    memcpy(r, q, qsec_end);
    r[2] = 0x81; r[3] = 0x80;                 // QR=1, RD kopiert, RA=1
    r[6] = 0; r[7] = (qtype == 1) ? 1 : 0;    // ANCOUNT (nur A beantworten)
    r[8] = r[9] = r[10] = r[11] = 0;
    int o = qsec_end;
    if (qtype == 1) {
        r[o++] = 0xC0; r[o++] = 0x0C;         // Zeiger auf Frage-Name
        r[o++] = 0x00; r[o++] = 0x01;         // TYPE A
        r[o++] = 0x00; r[o++] = 0x01;         // CLASS IN
        r[o++] = 0; r[o++] = 0; r[o++] = 0; r[o++] = 30;   // TTL 30s
        r[o++] = 0x00; r[o++] = 0x04;         // RDLENGTH
        r[o++] = 192; r[o++] = 168; r[o++] = 226; r[o++] = 1;
    }
    sendto(sock, r, o, 0, (struct sockaddr *)cli, clen);
}

static void dns_server_task(void *arg)
{
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = { .sin_family = AF_INET, .sin_port = htons(53),
                              .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (sock < 0 || bind(sock, (struct sockaddr *)&me, sizeof(me)) < 0) {
        ESP_LOGE(TAG, "DNS-Server bind fehlgeschlagen");
        if (sock >= 0) close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "DNS-Server auf :53 aktiv");
    uint8_t buf[512];
    while (1) {
        struct sockaddr_in cli; socklen_t cl = sizeof(cli);
        int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &cl);
        if (len < 12) continue;
        // Firewall: nur Clients aus dem USB-Subnetz 192.168.226.0/29 bedienen
        // (kein offener Resolver Richtung WLAN-Netz).
        if ((ntohl(cli.sin_addr.s_addr) & 0xFFFFFFF8u) != 0xC0A8E200u) continue;
        if (s_unlocked) dns_forward(sock, buf, len, &cli, cl);
        else            dns_hijack(sock, buf, len, &cli, cl);
    }
}

static void start_dns(void)
{
    xTaskCreate(dns_server_task, "dns_srv", 4096, NULL, 5, NULL);
}

// Catch-all: im gesperrten Zustand jede unbekannte URL auf die Portalseite
// umleiten -> loest die Captive-Erkennung von Windows/macOS/Android aus.
static esp_err_t captive_redirect(httpd_req_t *req)
{
    if (!s_unlocked) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://192.168.226.1/");
        httpd_resp_set_type(req, "text/html; charset=utf-8");
        return httpd_resp_sendstr(req,
            "<meta http-equiv=refresh content='0;url=http://192.168.226.1/'>"
            "Netzwerk erfordert Anmeldung");
    }
    httpd_resp_set_status(req, "404 Not Found");
    return httpd_resp_sendstr(req, "not found");
}

// --- DIAGNOSE (Phase-5-Data-Plane) ------------------------------------------
// ICMP-Ping vom Geraet SELBST durch den Tunnel. Quelle = WG-Tunnel-IP
// (10.10.0.2), NAPT der weitergeleiteten PC-Pakete ist dabei NICHT im
// Spiel -> trennt "FritzBox verwirft Data-Plane" (dann auch dieser Ping tot)
// von "Dongle-SNAT der Forward-Pakete falsch" (dann antwortet dieser Ping).
// GET /diag?ip=<ziel>[&if=wg|any] -> Ergebnis im CDC-Log.
static void diag_ping_success(esp_ping_handle_t hdl, void *args)
{
    uint8_t ttl = 0; uint16_t seqno = 0; uint32_t elapsed = 0; ip_addr_t addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO,  &seqno,   sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TTL,    &ttl,     sizeof(ttl));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &addr,    sizeof(addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP,&elapsed, sizeof(elapsed));
    ESP_LOGI(TAG, "DIAG-PING: REPLY von %s seq=%u ttl=%u zeit=%ums",
             ipaddr_ntoa(&addr), seqno, ttl, (unsigned)elapsed);
}
static void diag_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    uint16_t seqno = 0; ip_addr_t addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO,  &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &addr,  sizeof(addr));
    ESP_LOGW(TAG, "DIAG-PING: TIMEOUT %s seq=%u", ipaddr_ntoa(&addr), seqno);
}
static void diag_ping_end(esp_ping_handle_t hdl, void *args)
{
    uint32_t tx = 0, rx = 0, dur = 0;
    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST,  &tx,  sizeof(tx));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY,    &rx,  sizeof(rx));
    esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &dur, sizeof(dur));
    ESP_LOGI(TAG, "DIAG-PING: FERTIG %u/%u empfangen (%ums)",
             (unsigned)rx, (unsigned)tx, (unsigned)dur);
    esp_ping_delete_session(hdl);
}

static esp_err_t diag_get(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char q[96] = {0}, ips[48] = "10.10.0.1", ifs[8] = "wg";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char v[48];
        if (httpd_query_key_value(q, "ip", v, sizeof(v)) == ESP_OK) strlcpy(ips, v, sizeof(ips));
        if (httpd_query_key_value(q, "if", v, sizeof(v)) == ESP_OK) strlcpy(ifs, v, sizeof(ifs));
    }
    ip_addr_t target;
    if (ipaddr_aton(ips, &target) != 1) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ungueltige IP");
        return ESP_FAIL;
    }

    // WG-netif-Beleg: da? Adresse? Index? (Quelle des Diag-Pings)
    uint8_t wgidx = 0; char wgaddr[24] = "-";
    if (s_wg_ctx.netif) {
        wgidx = netif_get_index(s_wg_ctx.netif);
        strlcpy(wgaddr, ip4addr_ntoa(netif_ip4_addr(s_wg_ctx.netif)), sizeof(wgaddr));
    }
    ESP_LOGI(TAG, "DIAG: Ziel=%s if=%s wg_netif=%s(idx %u) wg_up=%d default_set=%d nat=%d",
             ips, ifs, wgaddr, wgidx, (int)s_wg_up, (int)s_wg_default_set, (int)s_nat_on);

    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr = target;
    cfg.count       = 4;
    cfg.interval_ms = 500;
    cfg.timeout_ms  = 1200;
    if (strcmp(ifs, "wg") == 0 && s_wg_ctx.netif) cfg.interface = wgidx;  // an WG-netif binden

    esp_ping_callbacks_t cbs = {
        .on_ping_success = diag_ping_success,
        .on_ping_timeout = diag_ping_timeout,
        .on_ping_end     = diag_ping_end,
        .cb_args         = NULL,
    };
    esp_ping_handle_t ping = NULL;
    if (esp_ping_new_session(&cfg, &cbs, &ping) != ESP_OK || esp_ping_start(ping) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Ping-Session fehlgeschlagen");
        return ESP_FAIL;
    }
    char msg[176];
    snprintf(msg, sizeof(msg),
             "DIAG-Ping -> %s (if=%s, wg=%s idx%u, wg_up=%d) gestartet. Ergebnis im CDC-Log.\n",
             ips, ifs, wgaddr, wgidx, (int)s_wg_up);
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, msg);
}

// Admin-Schalter "VPN-AUS": Tunnel komplett deaktivieren (trennen + kein
// Reconnect) bzw. wieder aktivieren. POST /vpn?state=off|on (Feld im Body);
// ohne Feld = umschalten. Persistent in NVS. Trennen/Starten macht der
// Main-Task (HTTPD-Stack ist klein) -> hier nur Flag + Gate.
static esp_err_t vpn_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[64] = {0};
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    if (len > 0) { int r = httpd_req_recv(req, body, len); if (r > 0) body[r] = 0; }
    char v[8] = {0};
    if (httpd_query_key_value(body, "state", v, sizeof(v)) == ESP_OK)
        s_vpn_off = (strcmp(v, "off") == 0);   // "on" -> VPN an
    else
        s_vpn_off = !s_vpn_off;                // ohne Feld: umschalten
    wg_creds_save();
    update_internet_gate();                    // Kill-Switch ggf. sofort schliessen
    ESP_LOGI(TAG, "VPN-Schalter (Admin): %s", s_vpn_off ? "AUS" : "AN");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

static esp_err_t unlock_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    s_unlocked = true;
    update_internet_gate();
    ESP_LOGI(TAG, "Captive-Portal ENTSPERRT");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

static esp_err_t lock_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    s_unlocked = false;
    update_internet_gate();
    ESP_LOGI(TAG, "Captive-Portal GESPERRT");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

// WireGuard-Konfiguration aus dem Webformular uebernehmen + neu verbinden.
static esp_err_t wg_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    char body[512];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len : (int)sizeof(body) - 1;
    int r = httpd_req_recv(req, body, len);
    if (r <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "kein Body"); return ESP_FAIL; }
    body[r] = 0;

    char enc[128], dec[96];
#define WG_GETF(key, dst) do { \
        if (httpd_query_key_value(body, key, enc, sizeof(enc)) == ESP_OK) { \
            url_decode(dec, enc, sizeof(dec)); strlcpy(dst, dec, sizeof(dst)); } \
    } while (0)
    // Secrets (priv/psk) NUR ueberschreiben, wenn eingegeben -> leeres Feld
    // behaelt den bestehenden Key (Toggles ohne Key-Neueingabe moeglich).
#define WG_GETSEC(key, dst) do { \
        if (httpd_query_key_value(body, key, enc, sizeof(enc)) == ESP_OK) { \
            url_decode(dec, enc, sizeof(dec)); if (dec[0]) strlcpy(dst, dec, sizeof(dst)); } \
    } while (0)
    WG_GETSEC("priv", s_wg_priv);
    WG_GETF("pub",  s_wg_pub);
    WG_GETSEC("psk",  s_wg_psk);
    WG_GETF("ep",   s_wg_endpoint);
    WG_GETF("addr", s_wg_addr);
    WG_GETF("mask", s_wg_netmask);
    if (httpd_query_key_value(body, "port", enc, sizeof(enc)) == ESP_OK) s_wg_port = atoi(enc);
    if (httpd_query_key_value(body, "ka",   enc, sizeof(enc)) == ESP_OK) s_wg_keepalive = atoi(enc);
    // Checkboxen: nur im Body, wenn angehakt.
    s_wg_fulltunnel = (httpd_query_key_value(body, "full", enc, sizeof(enc)) == ESP_OK);
    s_killswitch    = (httpd_query_key_value(body, "ks",   enc, sizeof(enc)) == ESP_OK);
#undef WG_GETF
#undef WG_GETSEC
    wg_creds_save();
    ESP_LOGI(TAG, "WireGuard-Config gespeichert -> reconnect angefordert");

    // Reconnect NICHT hier (HTTPD-Task, kleiner Stack) -> Main-Task erledigt es.
    s_wg_reconnect = true;
    update_internet_gate();   // Kill-Switch-Aenderung sofort anwenden

    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/settings");
    return httpd_resp_sendstr(req, "");
}

static void start_http(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.stack_size = 12288;  // OTA + chunked Rendering (SENDF-Puffer) brauchen Stack
    cfg.max_uri_handlers = 32;
    cfg.uri_match_fn = httpd_uri_match_wildcard;   // fuer Catch-all "/*"
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &cfg) == ESP_OK) {
        httpd_uri_t root   = { .uri = "/",       .method = HTTP_GET,  .handler = root_get };
        httpd_uri_t ota    = { .uri = "/ota",    .method = HTTP_POST, .handler = ota_post };
        httpd_uri_t wifi   = { .uri = "/wifi",   .method = HTTP_POST, .handler = wifi_post };
        httpd_uri_t scan   = { .uri = "/scan",   .method = HTTP_GET,  .handler = scan_get };
        httpd_uri_t vpn    = { .uri = "/vpn",    .method = HTTP_POST, .handler = vpn_post };
        httpd_uri_t unlock = { .uri = "/unlock", .method = HTTP_POST, .handler = unlock_post };
        httpd_uri_t lock   = { .uri = "/lock",   .method = HTTP_POST, .handler = lock_post };
        httpd_uri_t wg     = { .uri = "/wg",      .method = HTTP_POST, .handler = wg_post };
        httpd_uri_t admin  = { .uri = "/admin",   .method = HTTP_POST, .handler = admin_post };
        httpd_uri_t rdp    = { .uri = "/rdp",     .method = HTTP_GET,  .handler = rdp_get };
        httpd_uri_t res    = { .uri = "/res",     .method = HTTP_POST, .handler = res_post };
        httpd_uri_t resdel = { .uri = "/resdel",  .method = HTTP_POST, .handler = resdel_post };
        httpd_uri_t diag   = { .uri = "/diag",    .method = HTTP_GET,  .handler = diag_get };
        httpd_uri_t setti  = { .uri = "/settings",.method = HTTP_GET,  .handler = settings_get };
        httpd_uri_t reset  = { .uri = "/reset",   .method = HTTP_POST, .handler = reset_post };
        httpd_uri_t upl    = { .uri = "/upload",  .method = HTTP_POST, .handler = upload_post };
        httpd_uri_t dl     = { .uri = "/dl",      .method = HTTP_GET,  .handler = dl_get };
        httpd_uri_t delf   = { .uri = "/delfile", .method = HTTP_POST, .handler = delfile_post };
        httpd_uri_t sys    = { .uri = "/sys",     .method = HTTP_POST, .handler = sys_post };
        httpd_uri_t cexp   = { .uri = "/config/export", .method = HTTP_GET,  .handler = config_export_get };
        httpd_uri_t cimp   = { .uri = "/config/import", .method = HTTP_POST, .handler = config_import_post };
        httpd_uri_t cchk   = { .uri = "/config/check",  .method = HTTP_GET,  .handler = config_check_get };
        httpd_uri_t capl   = { .uri = "/config/apply",  .method = HTTP_POST, .handler = config_apply_post };
        httpd_uri_t wldel  = { .uri = "/wlandel", .method = HTTP_POST, .handler = wlandel_post };
        httpd_uri_t wlup   = { .uri = "/wlanup",  .method = HTTP_POST, .handler = wlanup_post };
        httpd_uri_t any    = { .uri = "/*",      .method = HTTP_GET,  .handler = captive_redirect };
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &ota);
        httpd_register_uri_handler(server, &wifi);
        httpd_register_uri_handler(server, &scan);
        httpd_register_uri_handler(server, &vpn);
        httpd_register_uri_handler(server, &unlock);
        httpd_register_uri_handler(server, &lock);
        httpd_register_uri_handler(server, &wg);
        httpd_register_uri_handler(server, &admin);
        httpd_register_uri_handler(server, &rdp);
        httpd_register_uri_handler(server, &res);
        httpd_register_uri_handler(server, &resdel);
        httpd_register_uri_handler(server, &diag);
        httpd_register_uri_handler(server, &setti);
        httpd_register_uri_handler(server, &reset);
        httpd_register_uri_handler(server, &upl);
        httpd_register_uri_handler(server, &dl);
        httpd_register_uri_handler(server, &delf);
        httpd_register_uri_handler(server, &sys);
        httpd_register_uri_handler(server, &cexp);
        httpd_register_uri_handler(server, &cimp);
        httpd_register_uri_handler(server, &cchk);
        httpd_register_uri_handler(server, &capl);
        httpd_register_uri_handler(server, &wldel);
        httpd_register_uri_handler(server, &wlup);
        httpd_register_uri_handler(server, &any);   // muss ZULETZT registriert werden
        ESP_LOGI(TAG, "HTTP-Server auf 192.168.226.1 gestartet");
    } else {
        ESP_LOGE(TAG, "HTTP-Server-Start fehlgeschlagen");
    }
}

// SCHRITT 1: TinyUSB + NCM zuerst starten, damit USB IMMER enumeriert (auch wenn
// das netif-Setup spaeter Probleme macht -> wir sehen wenigstens den Adapter).
static void start_usb(void)
{
    uint8_t base[6]; esp_efuse_mac_get_default(base);
    uint8_t host_mac[6];
    memcpy(host_mac, base, 6);
    host_mac[0] = (host_mac[0] | 0x02) & 0xFE;   // lokal verwaltet, unicast

    const tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
    tinyusb_net_config_t net_cfg = {
        .on_recv_callback = usb_recv_cb,
        .free_tx_buffer = NULL,
        .user_context = NULL,
    };
    memcpy(net_cfg.mac_addr, host_mac, 6);
    ESP_ERROR_CHECK(tinyusb_net_init(&net_cfg));

    // CDC-ACM + Log-Konsole ueber USB (Composite) -> Logs auf zweitem COM-Port.
    // ABSCHALTBAR: macOS' NCM-Treiber bindet bei einem NCM+CDC-ACM-Composite oft
    // NICHT (CDC-ACM als Interface 0 vor NCM) -> Geraet wird nur als rohes
    // Espressif-USB-Device erkannt. CONFIG_TINYUSB_CDC_ENABLED=n -> NCM-Einzel-
    // funktion, maximal macOS-kompatibel (kostet die serielle Log-Konsole).
#if defined(CONFIG_TINYUSB_CDC_ENABLED) && CONFIG_TINYUSB_CDC_ENABLED
    tinyusb_config_cdcacm_t acm = { .cdc_port = TINYUSB_CDC_ACM_0 };
    if (tinyusb_cdcacm_init(&acm) == ESP_OK) {
        tinyusb_console_init(TINYUSB_CDC_ACM_0);   // stdout/ESP_LOG -> USB-CDC
    }
    ESP_LOGI(TAG, "USB-NCM + CDC-Konsole installiert");
#else
    ESP_LOGI(TAG, "USB-NCM (NCM-only, keine CDC-Konsole)");
#endif
}

// SCHRITT 2: USB-netif als Router mit eigenem Subnetz + DHCP-Server. NICHT-fatal:
// falls hier etwas schiefgeht, bleibt USB trotzdem oben (nur ohne DHCP/IP).
static esp_netif_ip_info_t s_ip;   // static: esp_netif haelt ggf. den Zeiger
static void start_usb_netif(void)
{
    uint8_t base[6]; esp_efuse_mac_get_default(base);
    uint8_t dev_mac[6];
    memcpy(dev_mac, base, 6);
    dev_mac[0] = (dev_mac[0] | 0x02) & 0xFE;
    dev_mac[5] ^= 0x01;                           // Geraeteseite abweichend vom Host

    esp_netif_str_to_ip4("192.168.226.1", &s_ip.ip);
    esp_netif_str_to_ip4("192.168.226.1", &s_ip.gw);
    esp_netif_str_to_ip4("255.255.255.248", &s_ip.netmask);

    esp_netif_inherent_config_t base_cfg = {
        .flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP,
        .ip_info = &s_ip,
        .if_key = "usb_ncm",
        .if_desc = "usb",
        .route_prio = 10,
    };
    esp_netif_config_t cfg = {
        .base = &base_cfg,
        .driver = NULL,                            // Treiber ueber attach (post_attach)
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH,   // NCM liefert Ethernet-Frames
    };
    s_usb_netif = esp_netif_new(&cfg);
    if (!s_usb_netif) { ESP_LOGE(TAG, "esp_netif_new (USB) fehlgeschlagen"); return; }
    esp_netif_set_mac(s_usb_netif, dev_mac);

    s_usb_driver.base.post_attach = usb_driver_post_attach;
    if (esp_netif_attach(s_usb_netif, &s_usb_driver) != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_attach (USB) fehlgeschlagen"); return;
    }

    esp_netif_dhcps_stop(s_usb_netif);
    uint32_t lease_min = 10;   // DHCP-Lease 10 min
    esp_netif_dhcps_option(s_usb_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_IP_ADDRESS_LEASE_TIME, &lease_min, sizeof(lease_min));

    // DHCP-Server nennt dem PC den DONGLE selbst als DNS (192.168.226.1) -> unser
    // DNS-Server faengt Anfragen ab (Captive-Portal) bzw. leitet sie weiter.
    esp_netif_dns_info_t dns = {
        .ip = { .type = ESP_IPADDR_TYPE_V4, .u_addr.ip4.addr = esp_ip4addr_aton("192.168.226.1") },
    };
    esp_netif_set_dns_info(s_usb_netif, ESP_NETIF_DNS_MAIN, &dns);
    uint8_t offer_dns = 0x02;   // OFFER_DNS -> DNS-Option im DHCP-Angebot aktiv
    esp_netif_dhcps_option(s_usb_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_DOMAIN_NAME_SERVER, &offer_dns, sizeof(offer_dns));

    esp_netif_action_start(s_usb_netif, NULL, 0, NULL);       // netif hoch
    esp_netif_action_connected(s_usb_netif, NULL, 0, NULL);   // Link up (ESP-Seite)
    esp_netif_dhcps_start(s_usb_netif);                       // DHCP-Server an

    // NAPT bleibt zunaechst AUS (Captive-Portal gesperrt). Wird beim Entsperren
    // via set_internet(true) aktiviert (NAPT-Muster: inp->napt auf USB, SNAT
    // ausgehend auf die WLAN-STA-Adresse).

    // WICHTIG: dem HOST "Link up" signalisieren, sonst bleibt der Adapter
    // "Dormant" und Windows/macOS schickt gar kein DHCP.
    tud_network_link_state(0, true);
    ESP_LOGI(TAG, "USB-netif aktiv: 192.168.226.1/29, DHCP + DNS(Captive), NAT gesperrt, Link=up");
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    led_init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    start_usb();         // USB-NCM zuerst -> enumeriert immer

    // DIAGNOSE: Core-Dump des letzten Crashs ueber CDC (COM10) ausgeben.
    vTaskDelay(pdMS_TO_TICKS(1500));  // CDC/Host-Enum abwarten, sonst Log verloren
    {
        esp_core_dump_summary_t *sum = malloc(sizeof(esp_core_dump_summary_t));
        if (sum && esp_core_dump_get_summary(sum) == ESP_OK) {
            ESP_LOGE(TAG, "==== CORE-DUMP vom letzten Crash ====");
            ESP_LOGE(TAG, "PANIC-Task: %s", sum->exc_task);
            ESP_LOGE(TAG, "exc_pc = 0x%08x", (unsigned)sum->exc_pc);
            ESP_LOGE(TAG, "Backtrace (depth=%u, corrupted=%d):",
                     (unsigned)sum->exc_bt_info.depth, (int)sum->exc_bt_info.corrupted);
            for (uint32_t k = 0; k < sum->exc_bt_info.depth; k++) {
                ESP_LOGE(TAG, "  #%u  0x%08x", (unsigned)k,
                         (unsigned)sum->exc_bt_info.bt[k]);
            }
            ESP_LOGE(TAG, "==== ENDE CORE-DUMP (wird geloescht) ====");
            esp_core_dump_image_erase();
        } else {
            ESP_LOGI(TAG, "Kein Core-Dump gespeichert.");
        }
        free(sum);
    }

    wg_creds_load();      // Phase 5: WireGuard-Config aus NVS (vor WLAN-GOT_IP)
    admin_load();          // Phase 7: Admin-Zugang aus NVS (Default admin/admin)
    res_load();            // Phase 8: interne Ressourcen aus NVS
    sys_load();            // Systemname / Config-Secret / Config-Server aus NVS
    storage_init();        // SPIFFS 'storage' fuer Datei-Upload/Download mounten
    start_usb_netif();    // dann Subnetz + DHCP (nicht-fatal)
    start_wifi();          // Phase 2: WLAN-Uplink (STA)
    start_dns();           // Phase 4: DNS-Server (Captive-Hijack / Weiterleitung)
    start_http();

    // Diese App gilt jetzt als lauffaehig -> Rollback abbrechen (fuer OTA).
    esp_ota_mark_app_valid_cancel_rollback();

    ESP_LOGI(TAG, "Phase 8 bereit: + Kill-Switch + Admin-Login + Ressourcen. netif-RX %s.",
             DIAG_NO_NETIF_RX ? "ABGESCHALTET (nur zaehlen)" : "aktiv");

    // Diagnose-Heartbeat: solange das hier laeuft, lebt das Geraet.
    for (int i = 0;; i++) {
        if (s_wg_reconnect) { s_wg_reconnect = false; wg_stop(); }  // Config-Wechsel
        // Admin-Schalter "VPN-AUS": laufenden Tunnel trennen + Gate nachziehen.
        if (s_vpn_off && s_wg_started) { wg_stop(); update_internet_gate(); }
        wlan_manager();     // Mehrere WLANs: Ausfall-/Prioritaets-Umschaltung
        wg_poll();          // WireGuard-Peer-Status pruefen (+ LED)
        // Captive-Auto: solange kein WLAN verbunden ist -> gesperrt (Captive-Portal,
        // "Anmelden"-Popup zeigt die WLAN-Seite); mit WLAN -> frei. Wenn die
        // Einstellung aus ist, gilt nur die manuelle Sperren/Freigeben-Wahl.
        if (s_captive_auto && s_unlocked != s_wifi_connected) s_unlocked = s_wifi_connected;
        update_internet_gate();  // idempotent: NAPT-Gate an Zustand angleichen (Default entsperrt)
        // Config-Server: EINMALIG 3 min nach WLAN-Connect nachsehen (sonst manuell).
        if (s_wifi_connected && !s_cfg_checked_once && s_cfg_server[0] && s_cfg_secret[0]
            && s_wifi_got_ip_us && (esp_timer_get_time() - s_wifi_got_ip_us) > 180000000LL) {
            s_cfg_checked_once = true;
            int rc = config_server_check();
            ESP_LOGI(TAG, "Config-Server-Poll: rc=%d neue=%d (Server v%d / aktuell v%d)",
                     rc, (int)s_cfg_update_available, (int)s_cfg_available_version, (int)s_cfg_version);
        }
        // WLAN da, WG noch nicht gestartet, Schalter AN? -> starten.
        if (s_wifi_connected && wg_configured() && !s_wg_started && !s_vpn_off) wg_start();
        ESP_LOGI(TAG, "alive #%d | rx=%u tx=%u | wlan=%s vpn=%s | heap=%u B",
                 i, (unsigned)s_rx_count, (unsigned)s_tx_count,
                 s_wifi_connected ? "up" : "down", s_wg_up ? "up" : "down",
                 (unsigned)esp_get_free_heap_size());
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
