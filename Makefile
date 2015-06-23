CC=gcc
CFLAGS=-Wall
OBJ = server-tcp.o
LIB = -lwolfssl

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: server server-ssl server-psk server-psk-nonblocking server-psk-threaded server-epoll

server: server-tcp.c
	$(CC) -Wall -o server server-tcp.c

server-ssl: simple-ssl-server.c
	$(CC) -Wall -o server-ssl simple-ssl-server.c $(LIB)

server-psk: server-psk.c
	$(CC) -Wall -o server-psk server-psk.c $(LIB)

server-psk-nonblocking: server-psk-nonblocking.c
	$(CC) -Wall -o server-psk-nonblocking server-psk-nonblocking.c $(LIB)

server-psk-threaded: server-psk-threaded.c
	$(CC) -Wall -o server-psk-threaded server-psk-threaded.c $(LIB) -lpthread

server-epoll: epoll-ssl.c
	$(CC) -Wall -o server-epoll epoll-ssl.c $(LIB) -lpthread

.PHONY: clean

clean:
	rm -f *.o server server-ssl server-psk server-psk-nonblocking server-psk-threaded server-epoll
