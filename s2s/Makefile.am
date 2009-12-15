INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

LIBTOOL += --quiet

bin_PROGRAMS = s2s

noinst_HEADERS = s2s.h
s2s_SOURCES = in.c main.c out.c router.c db.c util.c

s2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la
if USE_LIBSUBST
s2s_LDADD += $(top_builddir)/subst/libsubst.la
endif
