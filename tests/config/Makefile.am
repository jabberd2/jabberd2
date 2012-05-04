EXTRA_DIST = *.xml test_configs

LIBTOOL += --quiet

noinst_PROGRAMS = configtest

configtest_SOURCES = config_test.cpp
configtest_LDADD = @CPPUNIT_LIBS@

configtest_CXXFLAGS = -I$(top_builddir)/util

# configtest_CXXFLAGS = -fprofile-arcs -ftest-coverage
# configtest_LDADD += -lgcov

configtest_LDADD += \
	$(top_builddir)/util/libutil.la

check:
	./configtest
