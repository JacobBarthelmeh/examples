CC=gcc

server: server-tcp.o
	$(CC) -o server server.c

.PHONY: clean

clean:
	rm -f *.o server
