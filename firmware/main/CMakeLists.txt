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
)
