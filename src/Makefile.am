bin_PROGRAMS = jabberd
AM_CPPFLAGS = -I@top_srcdir@

noinst_HEADERS = conf.h module.h
jabberd_SOURCES = conf.c module.c main.c
jabberd_LDADD = $(top_builddir)/lib/libutil.la $(GC_LIBS) $(LOG4C_LIBS) $(NANOMSG_LIBS) $(UV_LIBS)
