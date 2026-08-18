idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_netif esp_http_server nvs_flash esp_event driver
                  app_update esp_app_format esp_partition
)
