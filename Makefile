.PHONY: src libtomcrypt clean

PWDBLIBPATH=./pwdbsrv/lib/

pwdbsrv: libpwdb.a libtomcrypt.a
	make -C ./pwdbsrv

libpwdb: libtomcrypt
	make -C src libpwdb.a

libtomcrypt.a: libtomcrypt
	test -e $(PWDBLIBPATH)/libtomcrypt.a || cp ./src/lib/libtomcrypt.a $(PWDBLIBPATH)

libpwdb.a: libpwdb
	test -e $(PWDBLIBPATH)/libpwdb.a || cp ./src/libpwdb.a $(PWDBLIBPATH)

src: libtomcrypt
	make -C src

libtomcrypt:
	mkdir -p src/lib
	mkdir -p src/include
	CFLAGS="-DGMP_DESC" EXTRALIBS="-lgmp" make --file=makefile.unix -C libtomcrypt LIBPATH=`pwd`/src/lib INCPATH=`pwd`/src/include DATAPATH=./docs USER=`id -un` GROUP=`id -gn` install \
		|| CFLAGS="-DGMP_DESC" EXTRALIBS="-lgmp" make --file=makefile.unix -C libtomcrypt LIBPATH=`pwd`/src/lib INCPATH=`pwd`/src/include DATAPATH=./docs USER=`id -un` GROUP=`id -gn` install #dumb hack to get one pass install

TAGS: src
	rm -f TAGS && find . -name "*.[ch]" -print | xargs etags -a

clean:
	make -C libtomcrypt clean
	make -C src clean
	make -C pwdbsrv clean
	rm -f ./pwdbsrv/lib/*.a
