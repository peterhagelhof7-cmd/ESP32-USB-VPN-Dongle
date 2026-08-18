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
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_netif.h"
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
static volatile uint32_t s_rx_count;

// KY-016 RGB-Status-LED (gemeinsame Kathode -> HIGH = an). Pins ggf. an die
// Verdrahtung anpassen. Phase 1: rot (noch nichts verbunden).
#define LED_R_PIN GPIO_NUM_5
#define LED_G_PIN GPIO_NUM_6
#define LED_B_PIN GPIO_NUM_7

static esp_netif_t *s_usb_netif;

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

// --- HTTP-Testseite + OTA-Update --------------------------------------------
static esp_err_t root_get(httpd_req_t *req)
{
    const esp_app_desc_t *app = esp_app_get_description();
    static char page[1600];
    snprintf(page, sizeof(page),
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>ESP32 USB VPN</title>"
        "<style>body{font-family:sans-serif;background:#0f1626;color:#e6e6e6;"
        "text-align:center;padding:32px}h1{color:#5cc8ff}.ok{color:#43d17a}"
        ".card{background:#16203c;border:1px solid #33406a;border-radius:10px;"
        "max-width:460px;margin:18px auto;padding:18px}button{padding:8px 16px}"
        "progress{width:100%%;margin-top:8px}</style></head><body>"
        "<h1>ESP32-USB-VPN-Dongle</h1>"
        "<p class=ok>Phase 1: USB-NCM funktioniert.</p>"
        "<p>Der PC hat per DHCP eine IP vom Dongle erhalten und erreicht das "
        "Webinterface unter <b>192.168.226.1</b>. WLAN / NAT / WireGuard folgen.</p>"
        "<div class=card><b>Firmware-Update (OTA)</b>"
        "<div style='font-size:13px;color:#8ab4f8'>Version: %s</div>"
        "<form id=f><input type=file id=fw accept='.bin' required>"
        "<button type=submit>Update einspielen</button></form>"
        "<progress id=p max=100 value=0 hidden></progress>"
        "<div id=st style='font-size:13px'></div></div>"
        "<script>f.onsubmit=function(e){e.preventDefault();var file=fw.files[0];"
        "if(!file)return;var x=new XMLHttpRequest();x.open('POST','/ota');"
        "p.hidden=false;x.upload.onprogress=function(ev){var v=Math.round("
        "ev.loaded/ev.total*100);p.value=v;st.textContent=v+'%%';};"
        "x.onload=function(){st.textContent=x.responseText;"
        "if(x.status==200)setTimeout(function(){location.reload();},5000);};"
        "x.onerror=function(){st.textContent='Fehler beim Upload';};"
        "x.send(file);};</script></body></html>",
        app ? app->version : "?");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, page);
}

// OTA: roher .bin-Body in die inaktive Partition schreiben, dann Neustart.
// (Phase 1: ohne Auth — wird in Phase 7 auf Admin beschraenkt.)
static esp_err_t ota_post(httpd_req_t *req)
{
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

static void start_http(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;   // OTA-Handler braucht mehr Stack
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &cfg) == ESP_OK) {
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_get };
        httpd_uri_t ota  = { .uri = "/ota", .method = HTTP_POST, .handler = ota_post };
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &ota);
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

    esp_netif_action_start(s_usb_netif, NULL, 0, NULL);       // netif hoch
    esp_netif_action_connected(s_usb_netif, NULL, 0, NULL);   // Link up (ESP-Seite)
    esp_netif_dhcps_start(s_usb_netif);                       // DHCP-Server an

    // WICHTIG: dem HOST "Link up" signalisieren, sonst bleibt der Adapter
    // "Dormant" und Windows/macOS schickt gar kein DHCP.
    tud_network_link_state(0, true);
    ESP_LOGI(TAG, "USB-netif aktiv: 192.168.226.1/29, DHCP-Server an, Link=up");
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

    start_usb_netif();    // dann Subnetz + DHCP (nicht-fatal)
    start_http();

    // Diese App gilt jetzt als lauffaehig -> Rollback abbrechen (fuer OTA).
    esp_ota_mark_app_valid_cancel_rollback();

    ESP_LOGI(TAG, "Phase 1 bereit (DIAG). netif-RX %s.",
             DIAG_NO_NETIF_RX ? "ABGESCHALTET (nur zaehlen)" : "aktiv");

    // Diagnose-Heartbeat: solange das hier laeuft, lebt das Geraet.
    for (int i = 0;; i++) {
        ESP_LOGI(TAG, "alive #%d | rx=%u tx=%u | heap=%u B",
                 i, (unsigned)s_rx_count, (unsigned)s_tx_count,
                 (unsigned)esp_get_free_heap_size());
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
