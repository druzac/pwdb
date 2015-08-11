
.PHONY: src

src:
	make -C src

TAGS: src
	rm -f TAGS && find . -name "*.[ch]" -print | xargs etags -a
