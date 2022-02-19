CC = gcc
HEADERS = lib/RawTCP.h
EXTRA_CFLAGS= -I$(PWD)/lib

default:
	make execve_hijack

execve_hijack.o: execve_hijack.c $(HEADERS)
	gcc -c execve_hijack.c

execve_hijack: execve_hijack.o lib/libRawTCP_Lib.a
	gcc -lm -o execve_hijack execve_hijack.o -L. lib/libRawTCP_Lib.a

clean:
	-rm -f execve_hijack.o
	-rm -f execve_hijack