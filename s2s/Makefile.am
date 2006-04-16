INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS = s2s

noinst_HEADERS = s2s.h
s2s_SOURCES = in.c main.c out.c router.c sx.c util.c

s2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la \
            $(top_builddir)/subst/libsubst.la \
            $(top_builddir)/expat/libexpat.la
