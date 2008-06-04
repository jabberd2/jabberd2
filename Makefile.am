EXTRA_DIST = Doxyfile.in README.win32 README.protocol contrib UPGRADE

SUBDIRS = etc tools man mio sx util c2s router s2s sm storage

.PHONY: docs

if USE_LIBSUBST
SUBDIRS += subst
endif

docs: Doxyfile
	@doxygen

dist-hook:
	if grep 'AC_INIT.*dev' configure.ac ; then echo "Remove 'dev' version flag first!"; exit 1; else : ; fi
	find $(distdir) -depth \( -name CVS -o -name .svn -o -name .git \) -exec rm -rf {} \;
