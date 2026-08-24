# esp_wireguard kommt als PlatformIO-lib_deps (droscy-Fork), nicht als ESP-IDF-
# Managed-Component -> Header-Pfad hier explizit ergaenzen (LDF linkt lib_deps
# erst am ELF-Schritt, ausserhalb des CMake-Component-Graphen). Der libdeps-Pfad
# enthaelt den Env-Namen (.pio/libdeps/<env>/); PIOENV ist zur CMake-Zeit NICHT
# als Env-Variable gesetzt -> per GLOB ueber alle Envs suchen (Header sind
# identisch; PlatformIO linkt am ELF-Schritt die korrekte Env-Lib).
file(GLOB _wg_include_dirs "${CMAKE_CURRENT_LIST_DIR}/../.pio/libdeps/*/esp_wireguard/include")
file(GLOB _wg_src_dirs     "${CMAKE_CURRENT_LIST_DIR}/../.pio/libdeps/*/esp_wireguard/src")

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS ${_wg_include_dirs} ${_wg_src_dirs}
    PRIV_REQUIRES esp_netif esp_wifi esp_http_server nvs_flash esp_event driver
                  app_update esp_app_format esp_partition espcoredump lwip mbedtls
                  spiffs esp_timer esp_http_client esp_driver_rmt
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
