.PHONY: src libtomcrypt

src: libtomcrypt
	make -C src

libtomcrypt:
	mkdir -p src/lib
	mkdir -p src/include
	CFLAGS="-DGMP_DESC" EXTRALIBS="-lgmp" make --file=makefile.unix -C libtomcrypt LIBPATH=`pwd`/src/lib INCPATH=`pwd`/src/include DATAPATH=./docs USER=`id -un` GROUP=`id -gn` install \
		|| CFLAGS="-DGMP_DESC" EXTRALIBS="-lgmp" make --file=makefile.unix -C libtomcrypt LIBPATH=`pwd`/src/lib INCPATH=`pwd`/src/include DATAPATH=./docs USER=`id -un` GROUP=`id -gn` install #dumb hack to get one pass install

TAGS: src
	rm -f TAGS && find . -name "*.[ch]" -print | xargs etags -a
