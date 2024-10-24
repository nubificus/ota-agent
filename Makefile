INCLUDE_DIR = -Iinclude -Imbedtls/include
CFLAGS = $(INCLUDE_DIR) -g #-Wall
LDFLAGS  = -Lmbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto -lssl -lcrypto

src = $(wildcard src/*.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

all: dice_app

.PHONY = dice_app
dice_app: $(obj)
	make -C mbedtls -j$(nproc) && \
	$(CC) -o $@ $^ $(LDFLAGS)

-include $(dep)

.PHONY: clean
clean:
	rm -f $(obj) $(dep) dice_app && \
		 make -C mbedtls clean
