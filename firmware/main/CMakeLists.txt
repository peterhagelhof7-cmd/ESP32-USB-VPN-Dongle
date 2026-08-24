# esp_wireguard ist jetzt eine vendored IDF-Komponente (components/esp_wireguard)
# -> ueber REQUIRES einbinden (die Komponente exponiert include/ + src/).
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_netif esp_wifi esp_http_server nvs_flash esp_event driver
                  app_update esp_app_format esp_partition espcoredump lwip mbedtls
                  spiffs esp_timer esp_http_client esp_driver_rmt esp_wireguard
)

# Benutzerdefinierter lwIP-Hook (DHCP-Server Option 121). esp-idfs
# lwip_default_hooks.h includet ESP_IDF_LWIP_HOOK_FILENAME -> unser Header.
# Global setzen, damit die lwip-Komponente (dhcpserver.c) den Header sieht.
idf_build_set_property(COMPILE_DEFINITIONS "ESP_IDF_LWIP_HOOK_FILENAME=\"dongle_lwip_hooks.h\"" APPEND)
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_CURRENT_LIST_DIR}" APPEND)

# mbedtls Low-Level-AES-Header ist in IDF6 (mbedtls 4.x) nur unter dem
# builtin-Treiber-"private"-Include -> Pfad ergaenzen (Symbole kommen aus der
# mbedtls-Komponente). Einbindung via #include "mbedtls/private/aes.h".
idf_build_get_property(idf_path IDF_PATH)
target_include_directories(${COMPONENT_LIB} PRIVATE
    "${idf_path}/components/mbedtls/mbedtls/tf-psa-crypto/drivers/builtin/include")
