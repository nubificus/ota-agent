#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <dice/dice.h>

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

#define PORT 4433
#define MAX_LINE_LENGTH 1024
#define DEBUG 0

#define SUCCESS_BYTE "1"
#define FAILURE_BYTE "0"

char *DEV_INFO_PATH;
char *NEW_FIRMWARE_PATH;
char *SERVER_CRT_PATH;
char *SERVER_KEY_PATH;

typedef struct {
	char *app_hash;
	char *bootloader_hash;
	char *MAC;
} device_info;

typedef struct {
	unsigned char *cert;
	size_t len;
} cert_t;

device_info *devices;
int device_count;

cert_t make_cert(char *MAC, char *bootloader_hash, char *app_hash);

cert_t* certs_init(device_info* devs, size_t n_dev) {
	cert_t *certs_arr = (cert_t*) malloc(n_dev * sizeof(cert_t));
	for (int i = 0; i < n_dev; i++)
		certs_arr[i] = make_cert(devs[i].MAC, devs[i].bootloader_hash, devs[i].app_hash);

	return certs_arr;
}

device_info* read_device_info(const char *filename, int *count) {
	FILE *file = fopen(filename, "r");
        if (!file) {
	        perror("Failed to open file");
	        return NULL;
	}

	int capacity = 10;  // Starting capacity
	device_info *devices = malloc(capacity * sizeof(device_info));
	if (!devices) {
		perror("Memory allocation failed");
		fclose(file);
		return NULL;
	}
	char line[MAX_LINE_LENGTH];
         *count = 0;
	 while (fgets(line, sizeof(line), file)) {
		 if (*count >= capacity) {
			 capacity *= 2;
			 device_info *new_devices = realloc(devices, capacity * sizeof(device_info));
			 if (!new_devices) {
				 perror("Memory reallocation failed");
				 free(devices);
				 fclose(file);
				 return NULL;
			 }
			 devices = new_devices;
		 }
		 devices[*count].MAC = strdup(strtok(line, " \t\n"));
		 devices[*count].app_hash = strdup(strtok(NULL, " \t\n"));
		 devices[*count].bootloader_hash = strdup(strtok(NULL, "  \t\n"));
		 if (!devices[*count].MAC || !devices[*count].app_hash || !devices[*count].bootloader_hash) {
			 perror("Error parsing line or allocating memory");
			 free(devices);
			 fclose(file);
			 return NULL;
		 }
		 (*count)++;
	 }
	 fclose(file);
	 return devices;
}
void free_device_info(device_info *devices, int count) {
	for (int i = 0; i < count; i++) {
		free(devices[i].MAC);
		free(devices[i].app_hash);
		free(devices[i].bootloader_hash);
	}
	free(devices);
}

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

static char *base64_encode(const unsigned char *input, int length) {
	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BUF_MEM *bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, input, length);
        BIO_flush(b64);
        BIO_get_mem_ptr(b64, &bptr);
        char *buff = (char *)malloc(bptr->length + 1);
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = 0;
        BIO_free_all(b64);
        return buff;
}

static int to_array(char *src, uint8_t arr[], int num)
{
	int i = 0;
	char *token = strtok(src, ":");

	while (token != NULL && i < num) {
		sscanf(token, "%02hhx", &arr[i]);
		token = strtok(NULL, ":");
		i++;
	}

	return i;
}

cert_t make_cert(char *MAC, char *bootloader_hash, char *app_hash) {
	//printf("Makecert -m %s\n-b %s\n-c %s\n", MAC, bootloader_hash, app_hash);
	uint8_t seal_cdi_buffer[DICE_CDI_SIZE] = {0};
	uint8_t cdi_buffer[DICE_CDI_SIZE] = {0};
	DiceInputValues input_values = {0};
	uint8_t cert_buffer[2048];
	uint8_t mac_addr[6];
	size_t cert_size;
	DiceResult ret;
	int opt, i;
	FILE *fp;
	uint8_t boot_hash[DICE_HASH_SIZE] = {0}, code_hash[DICE_HASH_SIZE] = {0};
	uint8_t final_seal_cdi_buffer[DICE_CDI_SIZE] = {0};
	uint8_t final_cdi_buffer[DICE_CDI_SIZE] = {0};
	/*
	 * This must be unique per device on hardware that supports it
	 * On our ESP32 app, we hardcode the UDS. This has to match
	 */
	const uint8_t uds_buffer[] = {
		0xDA, 0xDD, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A,
		0x24, 0xC8, 0x3A, 0xA5, 0xA5, 0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03,
		0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE, 0x62,
		0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11,
		0xEB, 0x44, 0x4A, 0xF7, 0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF,
		0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA
	};
	i = to_array(MAC, mac_addr, sizeof(mac_addr));
	if (i != sizeof(mac_addr)) {
		printf("Invalid MAC\n");
		exit(!EXIT_FAILURE);
	}
	i = to_array(bootloader_hash, boot_hash, sizeof(boot_hash));
	i = to_array(app_hash, code_hash, sizeof(code_hash));

#if DEBUG
	printf("MAC %02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0], mac_addr[1], mac_addr[2],
	       mac_addr[3], mac_addr[4],  mac_addr[5]);
	printf("Boot hash\n");
	for (i = 0; i < sizeof(boot_hash); i++)
		printf("%02x", boot_hash[i]);
	printf("\n");
	printf("Code hash\n");
	for (i = 0; i < sizeof(code_hash); i++)
		printf("%02x", code_hash[i]);
	printf("\n");
#endif

	input_values.mode = kDiceModeNormal;
	input_values.config_type = kDiceConfigTypeInline;
	/* Mac is smaller that code_hash */
	memcpy(input_values.config_value, mac_addr,
	       sizeof(mac_addr));
	memcpy(input_values.code_hash, boot_hash, sizeof(input_values.code_hash));

	ret = DiceMainFlow(NULL, uds_buffer, uds_buffer, &input_values,
			        0, NULL, NULL, cdi_buffer, seal_cdi_buffer);
	if (ret != kDiceResultOk) {
		printf("DICE first CDI failed!");
		abort();
	}

	memset(input_values.code_hash, 0, sizeof(input_values.code_hash));
	memcpy(input_values.code_hash, code_hash, sizeof(input_values.code_hash));
	input_values.mode = kDiceModeNormal;
	input_values.config_type = kDiceConfigTypeInline;
	ret = DiceMainFlow(NULL, cdi_buffer, cdi_buffer,
			   &input_values, sizeof(cert_buffer), cert_buffer,
			   &cert_size, final_cdi_buffer, final_seal_cdi_buffer);

	
	unsigned char *pem_buf = NULL;
	size_t pem_len = 0;
	if (der_to_pem_buffer((const unsigned char *) cert_buffer,
			      cert_size, &pem_buf, &pem_len) != 0) {
		fprintf(stderr, "Conversion failed\n");
		abort();
	}
	cert_t cert = {
		.len = pem_len,
		.cert = pem_buf
	};

	return cert;
}

int is_verified(const char *cert,
		cert_t *verified_certs,
		size_t n_certs)
{
	int i = 0;
	while (strcmp(cert, verified_certs[i++].cert))
		if (i == n_certs)
			return 0;
	return 1;
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

	char *dev_info_path = getenv("DEV_INFO_PATH");
	if (dev_info_path == NULL) {
		fprintf(stderr, "DEV_INFO_PATH is not set - Please set the path of the device-info file\n");
		exit(0);
	} else {
		DEV_INFO_PATH = strdup(dev_info_path);
		fprintf(stdout, "Reading device info from:           %s\n", DEV_INFO_PATH);
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

int main(int argc, char *argv[]) {
	int ret;
	check_input_paths();

	/* Device info loading */
	device_count = 0;
	devices = read_device_info(DEV_INFO_PATH , &device_count);

        if (devices && device_count > 0) {
		for (int i = 0; i < device_count; i++) {
			printf("Device %d:\n", i + 1);
			printf("  MAC: %s\n", devices[i].MAC);

			#if DEBUG
			printf("  App Hash: %s\n", devices[i].app_hash);
			printf("  Bootloader Hash: %s\n", devices[i].bootloader_hash);
			#endif
		}
	} else {
		printf("No devices parsed.\n");
		exit(0);
	}

	cert_t* certs = certs_init(devices, device_count);
	
#if DEBUG
	for (int i = 0; i < device_count; i++)
		 printf("%d. PEM Output:\n%.50s...\n", i, certs[i].cert);
#endif

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
			if (is_verified((const char*) pem_buf, certs, device_count)) {
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
