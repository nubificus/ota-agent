#ifndef __ESP32_AKRI_H__
#define __ESP32_AKRI_H__

#include "mbedtls/ssl.h"

void apply_esp32_ota(mbedtls_ssl_context *ssl, char *fwpath);

#endif
