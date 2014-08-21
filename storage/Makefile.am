EXTRA_DIST = authreg_ntlogon.c authreg_sspi.c

AM_CFLAGS = -I$(top_srcdir)/c2s -I@top_srcdir@

LIBTOOL += --quiet

MODULE_LDFLAGS = -module -avoid-version
MODULE_LIBADD = -lexpat -L$(top_srcdir)/util

pkglib_LTLIBRARIES =

pkglib_LTLIBRARIES += libstorage.la
libstorage_la_SOURCES = storage.h storage.c object.c
libstorage_la_CPPFLAGS = -DLIBRARY_DIR=\"$(pkglibdir)\"

if STORAGE_ANON
pkglib_LTLIBRARIES += authreg_anon.la
authreg_anon_la_SOURCES = authreg_anon.c
authreg_anon_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_anon_la_LIBADD  = $(MODULE_LIBADD)
endif

if STORAGE_DB
pkglib_LTLIBRARIES += authreg_db.la storage_db.la
authreg_db_la_SOURCES = authreg_db.c
authreg_db_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_db_la_LIBADD  = $(MODULE_LIBADD) $(DB_LIBS)
storage_db_la_SOURCES = storage_db.c
storage_db_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_db_la_LIBADD  = $(MODULE_LIBADD) $(DB_LIBS) ../util/libutil.la
endif

if STORAGE_FS
pkglib_LTLIBRARIES += storage_fs.la
storage_fs_la_SOURCES = storage_fs.c
storage_fs_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_fs_la_LIBADD  = $(MODULE_LIBADD)
endif

if STORAGE_LDAP
pkglib_LTLIBRARIES += authreg_ldap.la authreg_ldapfull.la storage_ldapvcard.la
authreg_ldap_la_SOURCES = authreg_ldap.c
authreg_ldap_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_ldap_la_LIBADD  = $(MODULE_LIBADD) $(LDAP_LIBS)
authreg_ldapfull_la_SOURCES = authreg_ldapfull.c
authreg_ldapfull_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_ldapfull_la_LIBADD  = $(MODULE_LIBADD) $(LDAP_LIBS)
storage_ldapvcard_la_SOURCES = storage_ldapvcard.c
storage_ldapvcard_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_ldapvcard_la_LIBADD  = $(MODULE_LIBADD) $(LDAP_LIBS) ../util/libutil.la
endif

if STORAGE_MYSQL
pkglib_LTLIBRARIES += authreg_mysql.la storage_mysql.la
authreg_mysql_la_SOURCES = authreg_mysql.c
authreg_mysql_la_CPPFLAGS = $(MYSQL_CFLAGS)
authreg_mysql_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_mysql_la_LIBADD  = $(MODULE_LIBADD) $(MYSQL_LIBS) ../util/libutil.la
if HAVE_CRYPT
authreg_mysql_la_LIBADD += -lcrypt
endif
storage_mysql_la_SOURCES = storage_mysql.c
storage_mysql_la_CPPFLAGS = $(MYSQL_CFLAGS)
storage_mysql_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_mysql_la_LIBADD  = $(MODULE_LIBADD) $(MYSQL_LIBS)
endif

if STORAGE_ORACLE
pkglib_LTLIBRARIES += authreg_oracle.la storage_oracle.la
authreg_oracle_la_SOURCES = authreg_oracle.c
authreg_oracle_la_CPPFLAGS = $(ORACLE_CPPFLAGS)
authreg_oracle_la_LDFLAGS = $(MODULE_LDFLAGS) $(ORACLE_LDFLAGS)
authreg_oracle_la_LIBADD  = $(MODULE_LIBADD) $(ORACLE_LIBS)
storage_oracle_la_SOURCES = storage_oracle.c
storage_oracle_la_CPPFLAGS = $(ORACLE_CPPFLAGS)
storage_oracle_la_LDFLAGS = $(MODULE_LDFLAGS) $(ORACLE_LDFLAGS)
storage_oracle_la_LIBADD  = $(MODULE_LIBADD) $(ORACLE_LIBS)
endif

if STORAGE_PAM
pkglib_LTLIBRARIES += authreg_pam.la
authreg_pam_la_SOURCES = authreg_pam.c
authreg_pam_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_pam_la_LIBADD  = $(MODULE_LIBADD) $(PAM_LIBS)
endif

if STORAGE_PGSQL
pkglib_LTLIBRARIES += authreg_pgsql.la storage_pgsql.la
authreg_pgsql_la_SOURCES = authreg_pgsql.c
authreg_pgsql_la_CPPFLAGS = $(PGSQL_CFLAGS)
authreg_pgsql_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_pgsql_la_LIBADD  = $(MODULE_LIBADD) $(PGSQL_LIBS)
storage_pgsql_la_SOURCES = storage_pgsql.c
storage_pgsql_la_CPPFLAGS = $(PGSQL_CFLAGS)
storage_pgsql_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_pgsql_la_LIBADD  = $(MODULE_LIBADD) $(PGSQL_LIBS)
endif

if STORAGE_PIPE
pkglib_LTLIBRARIES += authreg_pipe.la
authreg_pipe_la_SOURCES = authreg_pipe.c
authreg_pipe_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_pipe_la_LIBADD  = $(MODULE_LIBADD) ../util/libutil.la
endif

if STORAGE_SQLITE
pkglib_LTLIBRARIES += authreg_sqlite.la storage_sqlite.la
authreg_sqlite_la_SOURCES = authreg_sqlite.c
authreg_sqlite_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_sqlite_la_LIBADD  = $(MODULE_LIBADD) $(SQLITE_LIBS)
storage_sqlite_la_SOURCES = storage_sqlite.c
storage_sqlite_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_sqlite_la_LIBADD  = $(MODULE_LIBADD) $(SQLITE_LIBS)
endif
