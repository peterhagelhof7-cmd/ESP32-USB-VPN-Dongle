idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    # esp_wireguard kommt als PlatformIO-lib_deps (droscy-Fork), nicht als
    # ESP-IDF-Managed-Component -> Header-Pfad hier explizit ergaenzen (LDF linkt
    # lib_deps erst am ELF-Schritt, ausserhalb des CMake-Component-Graphen).
    PRIV_INCLUDE_DIRS "../.pio/libdeps/lolin_s2_mini/esp_wireguard/include"
                       "../.pio/libdeps/lolin_s2_mini/esp_wireguard/src"
    PRIV_REQUIRES esp_netif esp_wifi esp_http_server nvs_flash esp_event driver
                  app_update esp_app_format esp_partition espcoredump lwip mbedtls
                  spiffs esp_timer
)

# Benutzerdefinierter lwIP-Hook (DHCP-Server Option 121). esp-idfs
# lwip_default_hooks.h includet ESP_IDF_LWIP_HOOK_FILENAME -> unser Header.
# Global setzen, damit die lwip-Komponente (dhcpserver.c) den Header sieht.
idf_build_set_property(COMPILE_DEFINITIONS "ESP_IDF_LWIP_HOOK_FILENAME=\"dongle_lwip_hooks.h\"" APPEND)
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_CURRENT_LIST_DIR}" APPEND)
