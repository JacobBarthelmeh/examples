examples-server-tcp
========

TCP server example for wolfSSL

To compile the c code run

make

on the terminal while in the same directory that server-tcp.c is in. This
creates an executable file called server. To start the server execute the
server file.

The server defaults to looking at port 9877 for a client.
After printing out the clients message to the terminal and responding ("I hear 
ya") to the client this basic version of a server immediately terminates the 
connection to the current client and waits for the next.
