# Vendored esp_wireguard (droscy-Fork 0.4.5). Lokal ins Projekt geholt, damit der
# Krypto-Datenpfad (ChaCha20-Poly1305) fuer die Dual-Core-Parallelisierung
# modifiziert werden kann.
#
# libsodium (nur X25519 im Handshake) bleibt ein PlatformIO-lib_dep -> Header per
# GLOB einbinden, die .a linkt PlatformIO am ELF-Schritt. Zwei Include-Pfade:
# der Standard-Header-Dir UND port_include/ (dort liegt das sonst generierte
# sodium/version.h, das sodium.h zieht).
file(GLOB _sodium_inc  "${CMAKE_CURRENT_LIST_DIR}/../../.pio/libdeps/*/libsodium/libsodium/src/libsodium/include")
file(GLOB _sodium_port "${CMAKE_CURRENT_LIST_DIR}/../../.pio/libdeps/*/libsodium/port_include")

idf_component_register(
    SRCS "src/crypto.c"
         "src/crypto/refc/blake2s.c"
         "src/crypto/refc/chacha20.c"
         "src/crypto/refc/chacha20poly1305.c"
         "src/crypto/refc/poly1305-donna.c"
         "src/esp_wireguard.c"
         "src/wireguard-platform.c"
         "src/wireguard.c"
         "src/wireguardif.c"
    # include/ = public API (esp_wireguard.h), src/ noetig weil esp_wireguard.h
    # das dort liegende esp_wireguard_err.h zieht.
    INCLUDE_DIRS "include" "src"
    PRIV_INCLUDE_DIRS ${_sodium_inc} ${_sodium_port}
    REQUIRES lwip esp_netif mbedtls esp_timer esp_system
)

# esp_wireguard ist Fremdcode und nicht mit den strengen -Werror-Flags des
# Projekts geschrieben (z.B. ignorierter crypto_scalarmult_curve25519-Rueckgabe-
# wert) -> Warnungen hier nicht fatal machen, statt die Lib zu patchen.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error)
