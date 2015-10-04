
# libraries:
# -lsodium
# -largp

# sodium is _deprecated_

pwdb: util.o db.o file_encrypt.o main.o pws.o
	gcc -g -o pwdb main.o pws.o util.o db.o file_encrypt.o -lsodium -largp -Llibs -ltomcrypt -Iltc_headers

main.o: main.c
	gcc -g -c main.c

util.o: util.c util.h
	gcc -g -c util.c

db.o: db.c db.h
	gcc -g -c db.c

pws.o: pws.c
	gcc -g -c pws.c -Iltc_headers

file_encrypt.o: file_encrypt.c file_encrypt.h
	gcc -g -c file_encrypt.c

.PHONY: clean

# pws_test: pws.c
# 	gcc -g -o pws_test pws.c -Llibs -ltomcrypt -Iltc_headers

clean:
	rm -f *.o pwdb
