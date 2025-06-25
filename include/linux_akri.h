#ifndef __LINUX_AKRI_H__
#define __LINUX_AKRI_H__

#include "mbedtls/ssl.h"

void apply_linux_ota(mbedtls_ssl_context *ssl, char *cimg);

#endif
