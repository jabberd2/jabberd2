EXTRA_DIST = Doxyfile.in README.win32 README.protocol contrib UPGRADE tests/Makefile.in

LIBTOOL += --quiet

SUBDIRS = etc man
if USE_LIBSUBST
SUBDIRS += subst
endif
SUBDIRS += tools mio sx util c2s router s2s sm storage

.PHONY: docs

docs: Doxyfile
	@doxygen

dist-hook:
	if grep 'AC_INIT.*dev' configure.ac ; then echo "Remove 'dev' version flag first!"; exit 1; else : ; fi
	find $(distdir) -depth \( -name CVS -o -name .svn -o -name .git \) -exec rm -rf {} \;
