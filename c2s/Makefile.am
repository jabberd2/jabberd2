INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\" \
            $(MYSQL_CFLAGS) \
            $(PGSQL_CFLAGS)

bin_PROGRAMS = c2s

c2s_SOURCES = authreg.c authreg_anon.c authreg_db.c authreg_ldap.c authreg_pam.c authreg_pipe.c bind.c c2s.c main.c sm.c

# MySQL support
if STORAGE_MYSQL
c2s_SOURCES += authreg_mysql.c
endif

# PostgreSQL support
if STORAGE_PGSQL
c2s_SOURCES += authreg_pgsql.c
endif

# SQLite3 support
if STORAGE_SQLITE
c2s_SOURCES += authreg_sqlite.c
endif


noinst_HEADERS = c2s.h

c2s_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la \
            $(top_builddir)/subst/libsubst.la \
            $(MYSQL_LIBS)   \
            $(PGSQL_LIBS)   \
            $(SQLITE_LIBS)

