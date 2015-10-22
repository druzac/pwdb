# Weverything is super noisy
# also clang only?

CC = gcc
CFLAGS = -g -Iinclude
LDLIBS = -framework Cocoa -largp -lmenu -lform -lncurses -Llib -ltomcrypt

OBJECTS = util.o pwdb.o pws.o clipb.o pwcurs.o

pwdb: $(OBJECTS)
pws.o: pws.h util.h
pwdb.o: util.h pws.h clipb.h pwcurs.h
util.o: util.h
clipb.o: clipb.h
pwcurs.o: pwcurs.h util.h pws.h clipb.h

.PHONY: clean
clean:
	rm -f pwdb $(OBJECTS)
