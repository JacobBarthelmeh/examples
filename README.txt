examples-server-tcp
========

TCP server example for wolfSSL

To compile the c code run

make

on the terminal while in the same directory that server-tcp.c is in. This
creates an executable file called server. To start the server execute the
server file.

The server defaults to looking on port 9877 for a client.
After responding ("I hear ya") to a client this basic version of a server
immediately terminates the connection.
