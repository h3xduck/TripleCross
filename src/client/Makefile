CC = gcc
HEADERS = lib/RawTCP.h
EXTRA_CFLAGS= -I$(PWD)/lib

default:
	make injector

client.o: client.c $(HEADERS)
	gcc -c client.c

injector: client.o lib/libRawTCP_Lib.a
	gcc -lm -o injector client.o -L. lib/libRawTCP_Lib.a

clean:
	-rm -f client.o
	-rm -f injector
