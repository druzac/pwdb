# Weverything is super noisy
# also clang only?

CC = gcc
CFLAGS = -g -Iinclude
LDLIBS = -framework Cocoa -largp -lmenu -lform -lncurses -Llib -ltomcrypt

objects = util.o pwdb.o pws.o clipb.o pwcurs.o

pwdb: $(objects)
pws.o: pws.h util.h
pwdb.o: util.h pws.h clipb.h pwcurs.h
util.o: util.h
clipb.o: clipb.h
pwcurs.o: pwcurs.h util.h pws.h clipb.h

# tests
test_objs = test-pws.o
check: test-pws
	./test-pws
test-pws: pws.o util.o
test-pws.o: pws.h

.PHONY: clean check
clean:
	rm -f pwdb $(objects) $(test_objs)
