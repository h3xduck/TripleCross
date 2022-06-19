CC = gcc
HEADERS = lib/RawTCP.h
EXTRA_CFLAGS= -I$(PWD)/lib

.PHONY: default
default:
	make execve_hijack injection_lib simple_timer simple_open simple_execve

injection_lib: injection_lib.o
	gcc -Wall -shared -fPIC -o injection_lib.so injection_lib.c -ldl

simple_timer.o: simple_timer.c $(HEADERS)
	gcc -g -c simple_timer.c

simple_timer: simple_timer.o
	gcc -g -o simple_timer simple_timer.o

simple_open.o: simple_open.c $(HEADERS)
	gcc -g -c simple_open.c

simple_open: simple_open.o
	gcc -g -o simple_open simple_open.o	

simple_execve.o: simple_open.c $(HEADERS)
	gcc -g -c simple_execve.c

simple_execve: simple_execve.o
	gcc -g -o simple_execve simple_execve.o	

execve_hijack.o: execve_hijack.c $(HEADERS)
	gcc -g -c execve_hijack.c

execve_hijack: execve_hijack.o lib/libRawTCP_Lib.a
	gcc -g -o execve_hijack execve_hijack.o -ldl -L. lib/libRawTCP_Lib.a

clean:
	-rm -f execve_hijack.o
	-rm -f execve_hijack
	-rm -f injection_lib.o
	-rm -f injection_lib.so
	-rm -f simple_timer.o
	-rm -f simple_timer
	-rm -f simple_open.o
	-rm -f simple_open
	-rm -f simple_execve.o
	-rm -f simple_execve