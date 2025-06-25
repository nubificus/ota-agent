#include <der2pem.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int der_to_pem_buffer(const unsigned char *der_buf, size_t der_len, unsigned char **pem_buf, size_t *pem_len) {
    X509 *cert = NULL;
    BIO *pem_bio = NULL;
    BUF_MEM *pem_mem = NULL;

    const unsigned char *p = der_buf;
    cert = d2i_X509(NULL, &p, der_len);
    if (!cert) {
        fprintf(stderr, "Error reading DER buffer\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    pem_bio = BIO_new(BIO_s_mem());
    if (!pem_bio) {
        fprintf(stderr, "Error creating BIO for PEM data\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 1;
    }

    if (!PEM_write_bio_X509(pem_bio, cert)) {
        fprintf(stderr, "Error writing PEM data to BIO\n");
        ERR_print_errors_fp(stderr);
        BIO_free(pem_bio);
        X509_free(cert);
        return 1;
    }

    BIO_get_mem_ptr(pem_bio, &pem_mem);
    *pem_len = pem_mem->length;

    *pem_buf = (unsigned char *)malloc(*pem_len + 1);
    if (!*pem_buf) {
        fprintf(stderr, "Error allocating memory for PEM buffer\n");
        BIO_free(pem_bio);
        X509_free(cert);
        return 1;
    }

    memcpy(*pem_buf, pem_mem->data, *pem_len);
    (*pem_buf)[*pem_len] = '\0';

    BIO_free(pem_bio);
    X509_free(cert);

    return 0;
}
