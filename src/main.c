#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <dice/dice.h>

#include <curl/curl.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <unistd.h>
#include <fcntl.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define SUCCESS_BYTE "1"
#define FAILURE_BYTE "0"
#define DICE_AUTH_FAIL -1
#define DICE_AUTH_SUCCESS 0

#define PORT 4433
#define DEBUG 0

char *NEW_FIRMWARE_PATH;
char *DICE_AUTH_URL;
char *SERVER_CRT_PATH;
char *SERVER_KEY_PATH;

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

void apply_ota(mbedtls_ssl_context *ssl) {
	int bytes_read;
	int total_bytes_sent = 0;
	int ret;
	char buffer[64] = {0};

	FILE *file = fopen(NEW_FIRMWARE_PATH, "r");
	if (file == NULL) {
		perror("Error: File opening failed");
		exit(0);
	}
	fseek(file, 0, SEEK_END);
	int filelen = ftell(file);
	fseek(file, 0, SEEK_SET);

	while ((bytes_read = fread(buffer, 1, 64, file)) > 0) {
		ret = mbedtls_ssl_write(ssl, buffer, bytes_read);
		if (ret <= 0) {
			printf("Could not send Update firmware-data to client %d\n", ret);
			abort();
		}
		total_bytes_sent += ret;
		printf("\rSent: %d%%", (int) (100 * (double) total_bytes_sent / (double) filelen));
		fflush(stdout);
		memset(buffer, 0, 64);
	}
	printf("\n");
}

void check_input_paths() {
	char *upd_fw_path = getenv("NEW_FIRMWARE_PATH");
	if (upd_fw_path == NULL) {
		fprintf(stderr, "NEW_FIRMWARE_PATH is not set - Please set the path of the new firmware\n");
		exit(0);
	} else {
		NEW_FIRMWARE_PATH = strdup(upd_fw_path);
		fprintf(stdout, "Reading new firmware from:          %s\n", NEW_FIRMWARE_PATH);
	}

	char *dice_auth_url = getenv("DICE_AUTH_URL");
	if (dice_auth_url == NULL) {
		fprintf(stderr, "DICE_AUTH_URL is not set - Please set the URL of the attestation server\n");
		exit(0);
	} else {
		DICE_AUTH_URL = strdup(dice_auth_url);
		fprintf(stdout, "Dice Attestation Server:            %s\n", DICE_AUTH_URL);
	}

	char *srv_crt_path = getenv("SERVER_CRT_PATH");
	if (srv_crt_path == NULL) {
                fprintf(stderr, "SERVER_CRT_PATH is not set - Please set the path of the server certificate file\n");
                exit(0);
        } else {
                SERVER_CRT_PATH = strdup(srv_crt_path);
		fprintf(stdout, "Reading server's certificate from:  %s\n", SERVER_CRT_PATH);
        }

	char *srv_key_path = getenv("SERVER_KEY_PATH");
	if (srv_key_path == NULL) {
                fprintf(stderr, "SERVER_KEY_PATH is not set - Please set the path of the server certificate file\n");
                exit(0);
        } else {
                SERVER_KEY_PATH = strdup(srv_key_path);
		fprintf(stdout, "Reading server's private key from:  %s\n", SERVER_KEY_PATH);
        }
}

int dice_auth_attest(const char *url, const char *pem) {
	int ret = DICE_AUTH_FAIL;

	/* Initialize libcurl */
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Failed to initialize curl\n");
		return ret;
	}

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: text/plain");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pem);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(pem));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	} else {
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 200) {
			printf("HTTP response code is 200: OK\n");
			ret = DICE_AUTH_SUCCESS;
		} else {
			printf("Unexpected HTTP response code: %ld\n", http_code);
		}
	}

	/* Cleanup */
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return ret;
}

int main(int argc, char *argv[]) {
	int ret;
	check_input_paths();

	const char *pers = "tls_server";
	mbedtls_net_context listen_fd, client_fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cert;
	mbedtls_pk_context key;

	mbedtls_net_init(&listen_fd);
	mbedtls_net_init(&client_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_x509_crt_init(&cert);
	mbedtls_pk_init(&key);

	/* Seed the random number generator */
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					 &entropy, (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		fprintf(stderr, "Failed to seed RNG: -0x%04X\n", -ret);
		return -1;
	}

	/* Load SSL configuration */
	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
					       MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		fprintf(stderr, "Failed to set SSL configuration: -0x%04X\n", -ret);
		return -1;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	/* Load certificate */
	if ((ret = mbedtls_x509_crt_parse_file(&cert, SERVER_CRT_PATH)) != 0) {
		fprintf(stderr, "Failed to load server certificate: -0x%04X\n", -ret);
		return -1;
	}

	/* Load private key */
	if ((ret = mbedtls_pk_parse_keyfile(&key, SERVER_KEY_PATH,
					    NULL, mbedtls_ctr_drbg_random,
					    &ctr_drbg)) != 0) {
		fprintf(stderr, "Failed to load server private key: -0x%04X\n", -ret);
		return -1;
	}

	/* Configure key and certificate */
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &cert, &key)) != 0) {
		fprintf(stderr, "Failed to load certificate or key: -0x%04X\n", -ret);
		return -1;
	}

	/* Bind and listen */
	if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433",
				    MBEDTLS_NET_PROTO_TCP)) != 0) {
		fprintf(stderr, "Failed to bind to port 4433: -0x%04X\n", -ret);
		return -1;
	}

	printf("Server is listening on port 4433\n");

	while (1) {
		printf("Waiting for a connection...\n");

		/* Accept a connection */
		if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
					      NULL, 0, NULL)) != 0) {
			fprintf(stderr, "Failed to accept connection: -0x%04X\n", -ret);
			continue;
		}

		printf("Client connected\n");

		/* Setup SSL context */
		if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
			fprintf(stderr, "Failed to setup SSL: -0x%04X\n", -ret);
			mbedtls_net_free(&client_fd);
			continue;
		}

		mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send,
				    mbedtls_net_recv, NULL);

		/* Perform handshake */
		if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			fprintf(stderr, "Failed to perform SSL handshake: -0x%04X\n", -ret);
			mbedtls_ssl_free(&ssl);
			mbedtls_net_free(&client_fd);
			continue;
		}

		printf("TLS connection established\n");

		#if DEBUG
		/* Debug information */
		printf("Session Cipher Suite: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));
		printf("Protocol Version: %s\n", mbedtls_ssl_get_version(&ssl));
		const mbedtls_x509_crt *peer_cert = mbedtls_ssl_get_peer_cert(&ssl);
		if (peer_cert != NULL) {
			char buf[1024];
			mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "    ", peer_cert);
			printf("Peer Certificate Information:\n%s\n", buf);
		} else {
			printf("No peer certificate received.\n");
		}
		#endif

		/* Read client message */
		#define BUF_LEN 4096
		unsigned char client_msg[BUF_LEN] = {0};

		printf("About to receive the certificate..\n");
		int bytes_read = mbedtls_ssl_read(&ssl, client_msg, BUF_LEN - 1);
		if (bytes_read > 0) {
			client_msg[bytes_read] = '\0';
			
			unsigned char *pem_buf = NULL;
			size_t pem_len = 0;
			if (der_to_pem_buffer((const unsigned char *) client_msg,
			      		      bytes_read, &pem_buf, &pem_len) != 0) {
				fprintf(stderr, "Conversion failed\n");
				abort();
			}
			#if DEBUG
			printf("DER to PEM:\n%.50s\n", pem_buf);
			#endif
			if (dice_auth_attest(DICE_AUTH_URL, (const char *)pem_buf) == DICE_AUTH_SUCCESS) {
				printf("Verified device\n");

				int ret = mbedtls_ssl_write(&ssl, SUCCESS_BYTE, 1);
				if (ret <= 0) {
					printf("Could not send verification message\n");
					mbedtls_ssl_close_notify(&ssl);
					mbedtls_ssl_free(&ssl);
					mbedtls_net_free(&client_fd);
					continue;
				}
				printf("Device notified, starting sending data..\n");
				apply_ota(&ssl);
				printf("`apply_ota()` returned\n");
			} else {
				printf("Not verified device\n");
				int ret = mbedtls_ssl_write(&ssl, FAILURE_BYTE, 1);
				if (ret <= 0) {
					printf("Could not notify about auth-failure\n");	
				}
				mbedtls_ssl_close_notify(&ssl);
				mbedtls_ssl_free(&ssl);
				mbedtls_net_free(&client_fd);
			}
			free(pem_buf);	
		} else {
			fprintf(stderr, "Failed to read from client: -0x%04X\n", -ret);
		}

		mbedtls_ssl_close_notify(&ssl);
		mbedtls_net_free(&client_fd);
		mbedtls_ssl_free(&ssl);
		return 0;
	}

	mbedtls_net_free(&listen_fd);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}
