
# libraries:
# -lsodium
# -largp

# sodium is _deprecated_
# XXX still using it for the util functions

pwdb: util.o db.o main.o pws.o clipb.o
	gcc -g -o pwdb main.o pws.o util.o db.o clipb.o -framework Cocoa -lsodium -largp -Llibs -ltomcrypt -Iltc_headers

main.o: main.c
	gcc -g -c main.c

util.o: util.c util.h
	gcc -g -c util.c

db.o: db.c db.h
	gcc -g -c db.c

pws.o: pws.c pws.h
	gcc -g -c pws.c -Iltc_headers

clipb.o: clipb.c clipb.h
	gcc -g -c clipb.c

.PHONY: clean

clean:
	rm -f *.o pwdb
