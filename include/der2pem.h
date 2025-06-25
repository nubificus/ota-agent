#ifndef __DER2PEM_H__
#define __DER2PEM_H__

#include <stddef.h>

int der_to_pem_buffer(const unsigned char *der_buf, size_t der_len, unsigned char **pem_buf, size_t *pem_len);

#endif
