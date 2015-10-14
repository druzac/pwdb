# Weverything is super noisy
# also clang only?

pwdb: util.o main.o pws.o clipb.o pwcurs.o
	gcc -g -o pwdb main.o pwcurs.o pws.o util.o clipb.o -framework Cocoa -largp -lmenu -lncurses -Llib -ltomcrypt -Iinclude

main.o: main.c
	gcc -g -c main.c

util.o: util.c util.h
	gcc -g -c util.c

pws.o: pws.c pws.h util.h
	gcc -g -c pws.c -Iinclude

clipb.o: clipb.c clipb.h
	gcc -g -c clipb.c

pwcurs.o: pwcurs.c pwcurs.h util.h pws.h clipb.h
	gcc -g -c pwcurs.c

.PHONY: clean

clean:
	rm -f *.o pwdb
