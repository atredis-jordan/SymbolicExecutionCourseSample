CC=gcc
CFLAGS=-Wall -Wextra -Werror -z now -z relro

.PHONY: all clean

BIN=guessnum

all: $(BIN)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(BIN)

