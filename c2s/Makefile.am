LIBTOOL += --quiet

bin_PROGRAMS = c2s

pkglib_LTLIBRARIES =

pkginclude_HEADERS = c2s.h

c2s_SOURCES = authreg.c bind.c c2s.c main.c sm.c pbx.c pbx_commands.c address.c

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -I@top_srcdir@
c2s_CPPFLAGS = $(AM_CPPFLAGS) -DLIBRARY_DIR=\"$(pkglibdir)\"
c2s_LDFLAGS = -export-dynamic
c2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/lib/libutil.la

MODULE_LDFLAGS = -module -export-dynamic -avoid-version

pkglib_LTLIBRARIES += authreg_anon.la
authreg_anon_la_SOURCES = authreg_anon.c
authreg_anon_la_LDFLAGS = $(MODULE_LDFLAGS)
