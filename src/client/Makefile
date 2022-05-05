CC = gcc
HEADERS = lib/RawTCP.h include/sslserver.h
EXTRA_CFLAGS= -I$(PWD)/lib

default:
	make injector

client.o: client.c $(HEADERS)
	gcc -c -Wno-deprecated-declarations client.c 

injector: client.o lib/libRawTCP_Lib.a
	gcc -lm -o injector client.o -L/usr/lib -lssl -lcrypto -L. lib/libRawTCP_Lib.a

clean:
	-rm -f client.o
	-rm -f injector
