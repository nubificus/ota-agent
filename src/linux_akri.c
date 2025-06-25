#include <linux_akri.h>
#include <unistd.h>
#include <string.h>

#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 20000

int send_container_img(mbedtls_ssl_context *ssl, char *cimg) {
        printf("Attemting to send the image..\n");
	int total_sleep_time = 0;
	size_t bytes_sent = 0;
	size_t len = strlen(cimg);
        while (bytes_sent < len) {
                const unsigned char *from = cimg + bytes_sent;
                int nr_bytes = len - bytes_sent;

                int ret = mbedtls_ssl_write(ssl, from, nr_bytes);
                if (ret > 0) {
			bytes_sent += ret;
			printf("\rSent: %d%%", (int) (100 * (double) bytes_sent / (double) len));
			fflush(stdout);
			total_sleep_time = 0;
			continue;
		}

		/* Handle errors */
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			printf("Connection closed before sending the new image\n");
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
			return -1;
		}
	}
	printf("\nImage sent to IoT\n");
	return 1;
}

void apply_linux_ota(mbedtls_ssl_context *ssl, char *cimg) {
	if (send_container_img(ssl, cimg) < 0) {
		printf("Could not apply OTA\n");
	}
}
