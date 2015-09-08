
# libraries:
# -lsodium
# -largp

# sample command line linking libtomcrypt
# gcc -o blah blah.c -L. -ltomcrypt

pwdb: util.o db.o file_encrypt.o main.o
	gcc -o pwdb main.o util.o db.o file_encrypt.o -lsodium -largp

main.o: main.c
	gcc -c main.c

util.o: util.c util.h
	gcc -c util.c

db.o: db.c db.h
	gcc -c db.c

file_encrypt.o: file_encrypt.c file_encrypt.h
	gcc -c file_encrypt.c

.PHONY: clean

pws_test: pws.c
	gcc -o pws_test pws.c -Llibs -ltomcrypt -Iltc_headers

clean:
	rm -f *.o pwdb
