
# libraries:
# -lsodium
# -largp

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

clean:
	rm -f *.o pwdb
