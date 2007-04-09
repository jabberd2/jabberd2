INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS = storage

storage_SOURCES = main.c
noinst_HEADERS = storage.h

storage_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/scod/libscod.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la \
            $(top_builddir)/subst/libsubst.la
