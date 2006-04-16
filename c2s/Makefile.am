INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS = c2s

c2s_SOURCES = authreg.c authreg_anon.c authreg_db.c authreg_ldap.c authreg_mysql.c authreg_pam.c authreg_pgsql.c authreg_pipe.c bind.c c2s.c main.c sm.c
noinst_HEADERS = c2s.h

c2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la \
            $(top_builddir)/subst/libsubst.la \
            $(top_builddir)/expat/libexpat.la
