CC = gcc
HEADERS = lib/RawTCP.h
EXTRA_CFLAGS= -I$(PWD)/lib

default:
	make execve_hijack injection_ex

injection_ex.o: injection_ex.c
	clang -g -Wall -c injection_ex.c

injection_ex: injection_ex.o
	clang -g -Wall -o injection_ex injection_ex.o -ldl

execve_hijack.o: execve_hijack.c $(HEADERS)
	clang -c execve_hijack.c

execve_hijack: execve_hijack.o lib/libRawTCP_Lib.a
	clang -lm -o execve_hijack execve_hijack.o -ldl -L. lib/libRawTCP_Lib.a

clean:
	-rm -f execve_hijack.o
	-rm -f execve_hijack
	-rm -f injection_ex.o
	-rm -f injection_ex