all: miniRSA.o
	gcc miniRSA.o -o run

miniRSA.o: miniRSA.c miniRSA.h
	gcc -c miniRSA.c

clean:
	rm -f *.o run
