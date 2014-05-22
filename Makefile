CC=gcc
CFLAGS=-Wall
OBJ = server-tcp.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: server server-psk server-psk-nonblocking server-psk-threaded

server: server-tcp.c
	$(CC) -Wall -o server server-tcp.c

server-psk: server-psk.c
	$(CC) -Wall -o server-psk server-psk.c -lm -lcyassl

server-psk-nonblocking: server-psk-nonblocking.c
	$(CC) -Wall -o server-psk-nonblocking server-psk-nonblocking.c -lm -lcyassl

server-psk-threaded: server-psk-threaded.c
	$(CC) -Wall -o server-psk-threaded server-psk-threaded.c -lm -lcyassl -lpthread

.PHONY: clean

clean:
	rm -f *.o server server-psk server-psk-nonblocking server-psk-threaded
