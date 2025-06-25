#include <esp32_akri.h>
#include <stdlib.h>
#include <unistd.h>

#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 20000

int send_fw(mbedtls_ssl_context *ssl, char *fwpath) {
        printf("Attemting to send the firmware..\n");

	FILE *file = fopen(fwpath, "r");
	if (file == NULL) {
		perror("Error: File opening failed");
		exit(0);
	}
	fseek(file, 0, SEEK_END);
	int len = ftell(file);
	fseek(file, 0, SEEK_SET);

	void *buffer = malloc(len);
	if (!buffer) {
		printf("Could not malloc for the firmware image\n");
		return -1;
	}

	if (len > fread(buffer, 1, len, file)) {
		printf("Could not read the firmware file\n");
		return -1;
	}

        int total_sleep_time = 0;
        int bytes_sent = 0;

        while (bytes_sent < len) {
                const unsigned char *read_from = buffer + bytes_sent;
                int nr_bytes = len - bytes_sent;
                int ret = mbedtls_ssl_write(ssl, read_from, nr_bytes);

                if (ret > 0) {
			bytes_sent += ret;
			printf("\rSent: %d%%", (int) (100 * (double) bytes_sent / (double) len));
			fflush(stdout);
			total_sleep_time = 0;
			continue;
		}

		/* Handle errors */
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			printf("Connection closed before sending the new firmware\n");
			free(buffer);
			return -1;
		} else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			#if DEBUG
			fprintf(stderr, "mbedtls_ssl_write() wants read/write, retrying..\n");
			#endif
		} else if (ret == 0) {
			#if DEBUG
                        fprintf(stderr, "Connection closed unexpectedly\n");
			#endif
		} else {
			#if DEBUG
			printf("mbedtls_ssl_write() failed with error code: %d\n", ret);
			#endif
		}

                /* Wait for an amount of time before retrying */
		if (total_sleep_time < MAX_RETRY_TIME_MS) {
			usleep(1000 * RETRY_DELAY_MS);
			total_sleep_time += RETRY_DELAY_MS;
		} else {
			printf("\nMax retry time exceeded, aborting.\n");
			free(buffer);
			return -1;
		}
	}
	printf("\nFirmware sent to IoT\n");
	free(buffer);
	return 1;
}

void apply_esp32_ota(mbedtls_ssl_context *ssl, char *fwpath) {
	if (send_fw(ssl, fwpath) < 0) {
		printf("Could not apply OTA\n");
	}
}
