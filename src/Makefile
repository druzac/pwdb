pwdb: util.o main.o pws.o clipb.o
	gcc -g -o pwdb main.o pws.o util.o clipb.o -framework Cocoa -largp -Llib -ltomcrypt -Iinclude

main.o: main.c
	gcc -g -c main.c

util.o: util.c util.h
	gcc -g -c util.c

pws.o: pws.c pws.h util.h
	gcc -g -c pws.c -Iinclude

clipb.o: clipb.c clipb.h
	gcc -g -c clipb.c

.PHONY: clean

clean:
	rm -f *.o pwdb
