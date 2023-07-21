CFLAGS = -g -O3 -Wall
OUTPUT = pp

.PHONY: all clean

all: $(OUTPUT)

clean:
	rm $(OUTPUT)

$(OUTPUT): %:%_client.c
	$(CC) $(CFLAGS) $< -o $@

