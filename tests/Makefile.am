LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@ -DSRCDIR="\"$(srcdir)\""

EXTRA_DIST = *.xml subdir

TESTS = check_nad check_xconfig

check_PROGRAMS = check_nad check_xconfig

check_nad_SOURCES = check_nad.c
check_nad_CFLAGS = $(CHECK_CFLAGS)
check_nad_LDADD = $(top_builddir)/lib/libutil.la $(CHECK_LIBS)

check_xconfig_SOURCES = check_xconfig.c
check_xconfig_CFLAGS = $(CHECK_CFLAGS)
check_xconfig_LDADD = $(top_builddir)/lib/libutil.la $(CHECK_LIBS)
