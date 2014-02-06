LIBTOOL += --quiet

bin_PROGRAMS = c2s

c2s_SOURCES = authreg.c bind.c c2s.c main.c sm.c pbx.c pbx_commands.c address.c
c2s_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DLIBRARY_DIR=\"$(pkglibdir)\" -I@top_srcdir@
c2s_LDFLAGS = -export-dynamic

noinst_HEADERS = c2s.h

c2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la
if USE_LIBSUBST
c2s_LDADD += $(top_builddir)/subst/libsubst.la
endif
