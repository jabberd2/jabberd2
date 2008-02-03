EXTRA_DIST = Doxyfile.in README.win32 README.protocol contrib UPGRADE

SUBDIRS = etc tools man mio subst sx util c2s resolver router s2s sm storage

.PHONY: docs

docs: Doxyfile
	@doxygen

dist-hook:
	if grep 'AC_INIT.*dev' configure.ac ; then echo "Remove 'dev' version flag first!"; exit 1; else : ; fi

