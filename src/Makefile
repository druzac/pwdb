
# libraries:
# -lsodium
# -largp

# sodium is _deprecated_

pwdb: util.o db.o file_encrypt.o main.o
	gcc -o pwdb main.o pws.o util.o db.o file_encrypt.o -lsodium -largp -Llibs -ltomcrypt -Iltc_headers

main.o: main.c
	gcc -c main.c

util.o: util.c util.h
	gcc -c util.c

db.o: db.c db.h
	gcc -c db.c

pws.o: pws.c
	gcc -c pws.c -Iltc_headers

file_encrypt.o: file_encrypt.c file_encrypt.h
	gcc -c file_encrypt.c

.PHONY: clean

# pws_test: pws.c
# 	gcc -g -o pws_test pws.c -Llibs -ltomcrypt -Iltc_headers

clean:
	rm -f *.o pwdb
