bin_PROGRAMS = jabberd
AM_CFLAGS = -rdynamic
AM_CPPFLAGS = -I@top_srcdir@

noinst_HEADERS = conf.h module.h
jabberd_SOURCES = conf.c module.c main.c bus.c
jabberd_LDFLAGS = -Wl,--whole-archive,$(top_builddir)/lib/.libs/libutil.a,--no-whole-archive
jabberd_LDADD = $(top_builddir)/lib/libutil.la
jabberd_LDADD += $(GC_LIBS) $(LOG4C_LIBS) $(NANOMSG_LIBS) $(UV_LIBS)
