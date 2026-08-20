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
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "ping/ping_sock.h"
#include "esp_wireguard.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_core_dump.h"
#include "driver/gpio.h"

#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_net.h"
#include "tinyusb_cdc_acm.h"
#include "tinyusb_console.h"

static const char *TAG = "usbvpn";

// DIAGNOSE: 1 = USB-Empfang NICHT an esp_netif weiterreichen (nur zaehlen).
#define DIAG_NO_NETIF_RX 0
// DIAGNOSE: 1 = TX verwerfen (send_sync nicht aufrufen) -> Deadlock-Test.
#define DIAG_TX_NOOP 0
// Sichtbarer Build-Marker (Beleg, welches Image nach OTA laeuft).
#define FW_BUILD_TAG "wg-fixed"
static volatile uint32_t s_rx_count;

// KY-016 RGB-Status-LED (gemeinsame Kathode -> HIGH = an). Pins ggf. an die
// Verdrahtung anpassen. Phase 1: rot (noch nichts verbunden).
#define LED_R_PIN GPIO_NUM_5
#define LED_G_PIN GPIO_NUM_6
#define LED_B_PIN GPIO_NUM_7

static esp_netif_t *s_usb_netif;

// --- WLAN-Uplink (STA) Zustand ---
static esp_netif_t   *s_sta_netif;
static char           s_wifi_ssid[33];
static char           s_wifi_pass[64];
static volatile bool  s_wifi_connected;
static esp_ip4_addr_t s_wifi_ip;
static int            s_wifi_retry;
static bool           s_nat_on;
// Captive-Portal-Zustand: gesperrt (Default) -> kein Internet, DNS-Hijack aufs
// Dongle-Webinterface; entsperrt -> NAT an, DNS wird echt weitergeleitet.
static volatile bool  s_unlocked;
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
            if (esp_netif_receive(s_usb_netif, copy, len, NULL) != ESP_OK) {
                free(copy);
            }
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

// --- WLAN-Uplink (STA-Client) -----------------------------------------------
static void wifi_creds_load(void)
{
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READONLY, &h) != ESP_OK) return;
    size_t sl = sizeof(s_wifi_ssid), pl = sizeof(s_wifi_pass);
    nvs_get_str(h, "ssid", s_wifi_ssid, &sl);
    nvs_get_str(h, "pass", s_wifi_pass, &pl);
    nvs_close(h);
}

static esp_err_t wifi_creds_save(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open("wifi", NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    nvs_set_str(h, "ssid", ssid);
    nvs_set_str(h, "pass", pass);
    e = nvs_commit(h);
    nvs_close(h);
    return e;
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
        led_update();       // blau: WLAN verbunden
        ESP_LOGI(TAG, "WLAN verbunden, IP " IPSTR, IP2STR(&ev->ip_info.ip));
        // WireGuard NICHT hier starten: esp_wireguard_init (DNS+Krypto+netif_add)
        // ist zu schwer fuer den sys_evt-Task. Der Heartbeat (Main-Task) ruft
        // wg_start(), sobald WLAN verbunden ist.
    }
}

// Zugangsdaten uebernehmen (aus Webinterface): speichern + neu verbinden.
static void wifi_apply(const char *ssid, const char *pass)
{
    snprintf(s_wifi_ssid, sizeof(s_wifi_ssid), "%s", ssid);
    snprintf(s_wifi_pass, sizeof(s_wifi_pass), "%s", pass);
    wifi_creds_save(s_wifi_ssid, s_wifi_pass);

    wifi_config_t wc = { 0 };
    memcpy(wc.sta.ssid, s_wifi_ssid, sizeof(wc.sta.ssid));
    memcpy(wc.sta.password, s_wifi_pass, sizeof(wc.sta.password));
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    s_wifi_retry = 0;
    esp_wifi_disconnect();
    esp_wifi_connect();
    ESP_LOGI(TAG, "Neue WLAN-Config: SSID '%s' -> verbinde", s_wifi_ssid);
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

    wifi_creds_load();
    if (s_wifi_ssid[0]) {
        wifi_config_t wc = { 0 };
        memcpy(wc.sta.ssid, s_wifi_ssid, sizeof(wc.sta.ssid));
        memcpy(wc.sta.password, s_wifi_pass, sizeof(wc.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
        ESP_LOGI(TAG, "WLAN-Config geladen: SSID '%s'", s_wifi_ssid);
    } else {
        ESP_LOGW(TAG, "Keine WLAN-Zugangsdaten -> im Webinterface setzen");
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

// --- HTTP-Testseite + OTA-Update --------------------------------------------
static esp_err_t root_get(httpd_req_t *req)
{
    const esp_app_desc_t *app = esp_app_get_description();
    char ipbuf[16];
    if (s_wifi_connected) snprintf(ipbuf, sizeof(ipbuf), IPSTR, IP2STR(&s_wifi_ip));
    else                  snprintf(ipbuf, sizeof(ipbuf), "-");
    const char *wstat = s_wifi_connected ? "verbunden"
                        : (s_wifi_ssid[0] ? "verbinde ..." : "nicht konfiguriert");
    const char *wcol  = s_wifi_connected ? "#43d17a" : "#f0a35e";
    bool routing = s_nat_on && s_wifi_connected;
    const char *rstat = routing ? "aktiv (NAT)" : (s_nat_on ? "wartet auf WLAN" : "aus");
    const char *rcol  = routing ? "#43d17a" : "#f0a35e";
    const char *lockbanner = s_unlocked ? ""
        : "<p style='color:#f0a35e;font-weight:bold'>Netzwerk erfordert Anmeldung</p>";
    const char *zcol  = s_unlocked ? "#43d17a" : "#f0a35e";
    const char *ztext = s_unlocked ? "entsperrt (Internet frei)" : "gesperrt (kein Internet)";
    const char *zbtn  = s_unlocked
        ? "<form method=post action=/lock><button type=submit>Sperren</button></form>"
        : "<form method=post action=/unlock><button type=submit>Anmelden (Internet freigeben)</button></form>";
    const char *wgcol  = s_wg_up ? "#43d17a" : "#f0a35e";
    const char *wgstat = s_wg_up ? "verbunden (Handshake ok)"
        : (wg_configured() ? (s_wg_started ? "verbinde ..." : "wartet auf WLAN") : "nicht konfiguriert");
    const char *wgmode = s_wg_default_set ? "Volltunnel aktiv (Default-Route)"
        : (s_wg_fulltunnel ? "Volltunnel gewuenscht (wartet auf Peer)" : "nur Tunnel (kein Routing)");
    const char *wgfull_chk = s_wg_fulltunnel ? "checked" : "";
    const char *ks_chk  = s_killswitch ? "checked" : "";
    const char *ksstat  = s_killswitch ? "scharf (Internet nur mit VPN)" : "aus";
    const char *kscol   = s_killswitch ? "#43d17a" : "#8ab4f8";
    const char *vpncol  = s_vpn_off ? "#ff6b6b" : "#43d17a";
    const char *vpntext = s_vpn_off ? "AUS (Tunnel deaktiviert)" : "AN";
    const char *vpnbtn  = s_vpn_off
        ? "<form method=post action=/vpn><input type=hidden name=state value=on>"
          "<button type=submit>VPN einschalten</button></form>"
        : "<form method=post action=/vpn><input type=hidden name=state value=off>"
          "<button type=submit>VPN ausschalten</button></form>";
    const char *pwwarn  = s_admin_is_default
        ? "<p style='color:#ff6b6b;font-weight:bold'>Standard-Passwort aktiv (admin/admin) - bitte aendern!</p>"
        : "";

    // Ressourcenliste (RDP/Link/SSH) rendern.
    static char reslist[2400];
    size_t ro = 0; reslist[0] = 0;
    for (int i = 0; i < s_res_count; i++) {
        resource_t *r = &s_res[i];
        char action[160];
        if (strcmp(r->type, "link") == 0)
            snprintf(action, sizeof(action), "<a href='%s' target=_blank style='color:#5cc8ff'>Oeffnen</a>", r->addr);
        else if (strcmp(r->type, "ssh") == 0)
            snprintf(action, sizeof(action), "<a href='ssh://%s' style='color:#5cc8ff'>SSH</a>", r->addr);
        else
            snprintf(action, sizeof(action), "<a href='/rdp?i=%d' style='color:#5cc8ff'>RDP herunterladen</a>", i);
        ro += snprintf(reslist + ro, sizeof(reslist) - ro,
            "<div style='border-top:1px solid #33406a;padding:4px;font-size:13px'>"
            "<b>%s</b> <span style='color:#8ab4f8'>[%s]</span><br>%s &nbsp; %s "
            "<form method=post action=/resdel style='display:inline'>"
            "<input type=hidden name=i value=%d><button style='font-size:11px'>loeschen</button></form></div>",
            r->name, r->type, r->addr, action, i);
    }
    if (s_res_count == 0)
        snprintf(reslist, sizeof(reslist), "<div style='font-size:13px;color:#8ab4f8'>keine Ressourcen</div>");

    static char page[9800];
    snprintf(page, sizeof(page),
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>ESP32 USB VPN</title>"
        "<style>body{font-family:sans-serif;background:#0f1626;color:#e6e6e6;"
        "text-align:center;padding:32px}h1{color:#5cc8ff}.ok{color:#43d17a}"
        ".card{background:#16203c;border:1px solid #33406a;border-radius:10px;"
        "max-width:460px;margin:18px auto;padding:18px}button{padding:8px 16px}"
        "input{padding:6px;border-radius:6px;border:1px solid #33406a;"
        "background:#0f1626;color:#e6e6e6}progress{width:100%%;margin-top:8px}"
        "</style></head><body>"
        "<h1>ESP32-USB-VPN-Dongle</h1>"
        "<p class=ok>USB-NCM aktiv - PC per DHCP am Dongle (192.168.226.1).</p>"
        "%s"   /* Sperr-Banner */
        "%s"   /* Passwort-Warnung */
        "<div class=card><b>Zugang</b>"
        "<div style='font-size:13px'>Status: <b style='color:%s'>%s</b></div>"
        "%s</div>"
        "<div class=card><b>WLAN-Uplink</b>"
        "<div style='font-size:13px'>Status: <b style='color:%s'>%s</b></div>"
        "<div style='font-size:13px'>IP vom Router: %s</div>"
        "<div style='font-size:13px'>Internet-Routing: <b style='color:%s'>%s</b></div>"
        "<button type=button onclick='scan()' style='margin:6px'>Netzwerke suchen</button>"
        "<div id=nets style='font-size:13px;margin:4px 0'></div>"
        "<form method=post action=/wifi>"
        "<input name=ssid placeholder=SSID value='%s' style='width:90%%;margin:3px' required><br>"
        "<input name=pass type=password placeholder=Passwort style='width:90%%;margin:3px'><br>"
        "<button type=submit>Verbinden / Speichern</button></form></div>"
        "<div class=card><b>WireGuard-VPN</b>"
        "<div style='font-size:13px'>Tunnel: <b style='color:%s'>%s</b></div>"
        "<div style='font-size:13px'>Endpoint: %s:%d</div>"
        "<div style='font-size:13px'>Routing: %s</div>"
        "<div style='font-size:13px'>Kill-Switch: <b style='color:%s'>%s</b></div>"
        "<div style='font-size:13px'>VPN-Schalter: <b style='color:%s'>%s</b></div>"
        "%s"   /* VPN an/aus (nur Admin) */
        "<form method=post action=/wg style='font-size:13px'>"
        "<input name=priv type=password placeholder='Private Key (leer=unveraendert)' style='width:90%%;margin:2px'><br>"
        "<input name=pub placeholder='Peer Public Key' value='%s' style='width:90%%;margin:2px' required><br>"
        "<input name=psk type=password placeholder='Preshared Key (optional)' style='width:90%%;margin:2px'><br>"
        "<input name=ep placeholder='Endpoint Host/IP' value='%s' style='width:58%%;margin:2px' required>"
        "<input name=port placeholder=Port value='%d' style='width:28%%;margin:2px'><br>"
        "<input name=addr placeholder='Tunnel-IP z.B. 10.0.0.2' value='%s' style='width:58%%;margin:2px' required>"
        "<input name=mask placeholder=Maske value='%s' style='width:28%%;margin:2px'><br>"
        "<input name=ka placeholder='Keepalive s' value='%d' style='width:40%%;margin:2px'><br>"
        "<label><input type=checkbox name=full value=1 %s> Volltunnel (ganzer PC-Verkehr durch VPN)</label><br>"
        "<label><input type=checkbox name=ks value=1 %s> Kill-Switch (kein Internet ohne VPN)</label><br>"
        "<button type=submit>Tunnel speichern + verbinden</button></form></div>"
        "<div class=card><b>Admin-Zugang</b>"
        "<div style='font-size:13px'>Benutzer: %s</div>"
        "<form method=post action=/admin style='font-size:13px'>"
        "<input name=user placeholder='Benutzer (optional)' value='%s' style='width:90%%;margin:2px'><br>"
        "<input name=pass type=password placeholder='Neues Passwort' style='width:90%%;margin:2px' required><br>"
        "<button type=submit>Passwort speichern</button></form></div>"
        "<div class=card><b>Interne Ressourcen</b>"
        "%s"
        "<form method=post action=/res style='font-size:13px'>"
        "<input name=name placeholder=Name style='width:90%%;margin:2px' required><br>"
        "<select name=type style='margin:2px'>"
        "<option value=rdp>RDP</option><option value=link>Link</option><option value=ssh>SSH</option>"
        "</select> "
        "<input name=addr placeholder='Adresse / URL' style='width:50%%;margin:2px' required>"
        "<input name=port placeholder=Port style='width:18%%;margin:2px'><br>"
        "<button type=submit>Ressource hinzufuegen</button></form></div>"
        "<div class=card><b>Firmware-Update (OTA)</b>"
        "<div style='font-size:13px;color:#8ab4f8'>Version: %s</div>"
        "<div style='font-size:13px;color:#8ab4f8'>Build: %s</div>"
        "<div style='font-size:13px;color:#8ab4f8'>Aktive Partition: %s</div>"
        "<form id=f><input type=file id=fw accept='.bin' required>"
        "<button type=submit>Update einspielen</button></form>"
        "<progress id=p max=100 value=0 hidden></progress>"
        "<div id=st style='font-size:13px'></div></div>"
        "<script>"
        "function scan(){var d=document.getElementById('nets');d.textContent='scanne ...';"
        "fetch('/scan').then(function(r){return r.json();}).then(function(a){d.innerHTML='';"
        "a.forEach(function(n){var b=document.createElement('button');b.type='button';"
        "b.style.cssText='display:block;width:92%%;margin:2px auto';"
        "b.textContent=(n.lock?'* ':'  ')+n.ssid+' ('+n.rssi+' dBm)';"
        "b.onclick=function(){document.getElementsByName('ssid')[0].value=n.ssid;};"
        "d.appendChild(b);});if(!a.length){d.textContent='keine Netze gefunden';}"
        "}).catch(function(){d.textContent='Scan-Fehler';});}"
        "f.onsubmit=function(e){e.preventDefault();var file=fw.files[0];"
        "if(!file)return;var x=new XMLHttpRequest();x.open('POST','/ota');"
        "p.hidden=false;x.upload.onprogress=function(ev){var v=Math.round("
        "ev.loaded/ev.total*100);p.value=v;st.textContent=v+'%%';};"
        "x.onload=function(){st.textContent=x.responseText;"
        "if(x.status==200)setTimeout(function(){location.reload();},5000);};"
        "x.onerror=function(){st.textContent='Fehler beim Upload';};"
        "x.send(file);};</script></body></html>",
        lockbanner, pwwarn, zcol, ztext, zbtn,
        wcol, wstat, ipbuf, rcol, rstat, s_wifi_ssid,
        wgcol, wgstat, s_wg_endpoint, s_wg_port, wgmode, kscol, ksstat,
        vpncol, vpntext, vpnbtn, s_wg_pub,
        s_wg_endpoint, s_wg_port, s_wg_addr, s_wg_netmask, s_wg_keepalive, wgfull_chk, ks_chk,
        s_admin_user, s_admin_user, reslist,
        app ? app->version : "?", FW_BUILD_TAG,
        esp_ota_get_running_partition()->label);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, page);
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
    if (!require_auth(req)) return ESP_OK;
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
        "<p><a href='/' style='color:#5cc8ff'>Zurueck zur Statusseite</a></p>"
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
    httpd_resp_set_hdr(req, "Location", "/");
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
    httpd_resp_set_hdr(req, "Location", "/");
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
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_sendstr(req, "");
}

// Verfuegbare WLANs scannen -> JSON [{ssid,rssi,lock}]. Blockierender Scan (~3 s).
static esp_err_t scan_get(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
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
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_sendstr(req, "");
}

static esp_err_t unlock_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    s_unlocked = true;
    update_internet_gate();
    ESP_LOGI(TAG, "Captive-Portal ENTSPERRT");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_sendstr(req, "");
}

static esp_err_t lock_post(httpd_req_t *req)
{
    if (!require_auth(req)) return ESP_OK;
    s_unlocked = false;
    update_internet_gate();
    ESP_LOGI(TAG, "Captive-Portal GESPERRT");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
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
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_sendstr(req, "");
}

static void start_http(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;   // OTA-Handler braucht mehr Stack
    cfg.max_uri_handlers = 16;
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
    tinyusb_config_cdcacm_t acm = { .cdc_port = TINYUSB_CDC_ACM_0 };
    if (tinyusb_cdcacm_init(&acm) == ESP_OK) {
        tinyusb_console_init(TINYUSB_CDC_ACM_0);   // stdout/ESP_LOG -> USB-CDC
    }
    ESP_LOGI(TAG, "USB-NCM + CDC-Konsole installiert");
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
        wg_poll();          // WireGuard-Peer-Status pruefen (+ LED)
        // WLAN da, WG noch nicht gestartet, Schalter AN? -> starten.
        if (s_wifi_connected && wg_configured() && !s_wg_started && !s_vpn_off) wg_start();
        ESP_LOGI(TAG, "alive #%d | rx=%u tx=%u | wlan=%s vpn=%s | heap=%u B",
                 i, (unsigned)s_rx_count, (unsigned)s_tx_count,
                 s_wifi_connected ? "up" : "down", s_wg_up ? "up" : "down",
                 (unsigned)esp_get_free_heap_size());
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
