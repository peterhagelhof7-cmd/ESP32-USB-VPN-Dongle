/*
 * dongle_lwip_hooks.h — benutzerdefinierte lwIP-Hooks fuer den VPN-Dongle.
 *
 * Wird ueber ESP_IDF_LWIP_HOOK_FILENAME (siehe main/CMakeLists.txt) von
 * esp-idfs lwip_default_hooks.h eingebunden — also SEHR frueh (via lwip/opt.h),
 * bevor dhcpserver.c seinen Default fuer LWIP_HOOK_DHCPS_POST_APPEND_OPTS setzt.
 * Deshalb hier nur Forward-Deklarationen, keine schweren Includes.
 */
#pragma once

struct netif;

/*
 * Wird am Ende der DHCP-OFFER/ACK-Optionen des DHCP-SERVERS aufgerufen.
 * Haengt Option 121 (Classless Static Routes, RFC 3442) an, damit der PC den
 * Dongle als Route fuer den VPN-Verkehr (bzw. 0.0.0.0/0 im Volltunnel) nutzt —
 * ohne manuelle Host-Routen/Metriken. Definition in main.c.
 *   netif    = Interface, auf dem der DHCP-Server antwortet (nur USB-IF beachten)
 *   state    = DHCP-Message-Typ (OFFER=2 / ACK=5 / NAK=6)
 *   pp_opts  = Zeiger auf den aktuellen Schreibzeiger im Options-Puffer
 */
void dongle_dhcps_append_opts(struct netif *netif, unsigned char state, unsigned char **pp_opts);

#define LWIP_HOOK_DHCPS_POST_APPEND_OPTS(netif, dhcps, state, pp_opts) \
    dongle_dhcps_append_opts((netif), (state), (pp_opts));
