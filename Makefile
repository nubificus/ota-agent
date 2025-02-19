INCLUDE_DIR = -Iinclude -Imbedtls/include
CFLAGS = $(INCLUDE_DIR) -g #-Wall
LDFLAGS  = -Lmbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto -lssl -lcrypto -lcurl

src = $(wildcard src/*.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

all: ota-agent

.PHONY = ota-agent
ota-agent: $(obj)
	make -C mbedtls -j$(nproc) && \
	$(CC) -o ota-agent $^ $(LDFLAGS)

-include $(dep)

.PHONY: clean
clean:
	rm -f $(obj) $(dep) ota-agent && \
		 make -C mbedtls clean
