CC=gcc
CFLAGS=-Wall -I include
DEPS = include/unp.h
OBJ = server-tcp.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

server: server-tcp.c
	$(CC) -Wall -o server server-tcp.c -I include -lm
	
.PHONY: clean

clean:
	rm -f *.o server
