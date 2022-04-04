CC = gcc
HEADERS = lib/RawTCP.h
EXTRA_CFLAGS= -I$(PWD)/lib

default:
	make execve_hijack injection_lib

injection_lib: injection_lib.o
	gcc -Wall -shared -fPIC -o injection_lib.so injection_lib.c -ldl

execve_hijack.o: execve_hijack.c $(HEADERS)
	clang -g -c execve_hijack.c

execve_hijack: execve_hijack.o lib/libRawTCP_Lib.a
	clang -g -o execve_hijack execve_hijack.o -ldl -L. lib/libRawTCP_Lib.a

clean:
	-rm -f execve_hijack.o
	-rm -f execve_hijack
	-rm -f injection_lib.o
	-rm -f injection_lib.so