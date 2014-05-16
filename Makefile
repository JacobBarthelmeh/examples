CC=gcc
CFLAGS=-Wall -I include
OBJ = server-tcp.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

server: server-tcp.c
	$(CC) -Wall -o server server-tcp.c
	
.PHONY: clean

clean:
	rm -f *.o server
