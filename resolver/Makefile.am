INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS = resolver

noinst_HEADERS = resolver.h dns.h
resolver_SOURCES = resolver.c dns.c

resolver_LDADD = $(top_builddir)/sx/libsx.la \
                 $(top_builddir)/mio/libmio.la \
                 $(top_builddir)/util/libutil.la \
                 $(top_builddir)/subst/libsubst.la \
                 $(top_builddir)/expat/libexpat.la
