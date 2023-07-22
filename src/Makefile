CFLAGS = -g -O3 -Wall
OUTPUT = pp_client \
		 pp_udp

.PHONY: all clean

all: $(OUTPUT)

clean:
	rm $(OUTPUT)

$(OUTPUT): %:%.c
	$(CC) $(CFLAGS) $< -o $@

