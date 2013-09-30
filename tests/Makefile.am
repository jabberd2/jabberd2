LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@

EXTRA_DIST = *.xml subdir

TESTS = check_nad check_config

check_PROGRAMS = check_nad check_config

check_nad_SOURCES = check_nad.c
check_nad_CFLAGS = $(CHECK_CFLAGS)
check_nad_LDADD = $(top_builddir)/util/libutil.la $(CHECK_LIBS)

check_config_SOURCES = check_config.c
check_config_CFLAGS = $(CHECK_CFLAGS)
check_config_LDADD = $(top_builddir)/util/libutil.la $(CHECK_LIBS)
