all: test_AES128.o AES128.o
	gcc test_AES128.o AES128.o -o run

test_AES128.o: test_AES128.c
	gcc -c test_AES128.c

AES128.o: AES128.c AES128.h
	gcc -c AES128.c

clean:
	rm -f *.o run
