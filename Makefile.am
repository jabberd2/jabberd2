EXTRA_DIST = Doxyfile.in README.md README.win32 README.protocol README.config contrib doc win32

LIBTOOL += --quiet

SUBDIRS = etc man tools lib mio sx router c2s s2s sm
if ENABLE_TESTS
SUBDIRS += tests
endif

ACLOCAL_AMFLAGS = -I m4

.PHONY: doc cppcheck

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

doc: Doxyfile
	@doxygen

cppcheck:
	cppcheck --force --quiet --report-progress -j6 --std=c99 -DSIGHUP -DSIGPIPE --enable=warning,performance,portability,information,missingInclude .

dist-hook:
	if grep 'AC_INIT.*dev' configure.ac ; then echo "Remove 'dev' version flag first!"; exit 1; else : ; fi
	find $(distdir) -depth \( -name CVS -o -name .svn -o -name .git \) -exec rm -rf {} \;
