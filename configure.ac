# jabberd configure script
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([jabberd],[2.x.dev],[jabberd2@lists.xiaoka.com],[jabberd],[http://github.com/jabberd2])
AC_CONFIG_SRCDIR([lib/nad.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
LT_PREREQ([2.4.6])
LT_INIT([shared disable-static dlopen])
AC_SUBST([LIBTOOL_DEPS])

# Quit if it is an in-source build
if test ${srcdir} == "." ; then
  AC_MSG_ERROR([In-source build is not allowed. Please configure from a separate build directory.])
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# extra paths
AC_ARG_WITH([extra_include_path], AC_HELP_STRING([--with-extra-include-path],
                                           [use additional include paths]),
            extra_include_path=$withval)
split_includes="`echo $extra_include_path | sed -e 's/:/ /g'`"
for incpath in $split_includes ; do
    CPPFLAGS="-I$incpath $CPPFLAGS"
done

AC_ARG_WITH([extra_library_path], AC_HELP_STRING([--with-extra-library-path],
                                               [use additional library paths (remember to update /etc/ld.so.conf too)]),
            extra_library_path=$withval)
split_libs="`echo $extra_library_path | sed -e 's/:/ /g'`"
for libpath in $split_libs ; do
    LDFLAGS="-L$libpath $LDFLAGS"
done

# Colorized build output
AX_CHECK_COMPILE_FLAG([-fdiagnostics-color], [CFLAGS="${CFLAGS} -fdiagnostics-color"],
    [AX_CHECK_COMPILE_FLAG([-fcolor-diagnostics], [CFLAGS="${CFLAGS} -fcolor-diagnostics"])])

# Checks for packages
PKG_CHECK_MODULES([EXPAT], [expat >= 2])
PKG_CHECK_MODULES([IDN], [libidn >= 0.3])
PKG_CHECK_MODULES([GSASL], [libgsasl >= 1.4])
PKG_CHECK_MODULES([LOG4C], [log4c >= 1.2.4])

# Checks for libraries.
# The dlopen() function is in the C library for *BSD and in
# libdl on GLIBC-based systems
AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen() function])
])

# crypt
AC_CHECK_FUNC([crypt], ,[AC_CHECK_LIB([crypt], [crypt])])
if test "x$ac_cv_lib_crypt_crypt" = "xyes"; then
  AC_DEFINE(HAVE_CRYPT, 1, [Define to 1 if you have the crypt() function])
fi
AM_CONDITIONAL(HAVE_CRYPT, [test "x$ac_cv_lib_crypt_crypt" = "xyes"])

# udns
AC_CHECK_LIB(udns, dns_init)
if test "x-$ac_cv_lib_udns_dns_init" != "x-yes" ; then
    AC_MSG_ERROR([UDNS library not found])
fi

# optional libraries
AC_ARG_WITH([ssl], AS_HELP_STRING([--with-ssl], [enable SSL/TLS support]))
AS_IF([test "x$enable_ssl" != "xno"], [
   PKG_CHECK_MODULES([SSL], [openssl >= 1.0.1 libcrypto], AC_DEFINE(HAVE_SSL,1,[Define to 1 if OpenSSL is available.]))
])
AM_CONDITIONAL(HAVE_SSL, [test -n "$SSL_LIBS"])

# MySQL
AC_ARG_ENABLE([mysql],
       AC_HELP_STRING([--enable-mysql[=DIR]], [enable MySQL auth/reg/storage support (no)]),
       [ enable_mysql="$enableval" have_mysql=no  MYSQL_PREFIX="$enableval" ],
       [ enable_mysql=no           have_mysql=no ])

if test "x-$enable_mysql" != "x-no" ; then
       if test "$MYSQL_PREFIX" = "yes" ; then
               MYSQL_PREFIX=/usr
       fi

       AC_PATH_PROG(mysqlconfig,mysql_config,,[$MYSQL_PREFIX/bin:$PATH])
       if test [ -z "$mysqlconfig" ]
       then
               AC_MSG_ERROR([mysql_config executable not found: MySQL 5.0 or greater is required.])
       else
               AC_MSG_CHECKING(MySQL libraries)
               MYSQL_LIBS=`${mysqlconfig} --libs`
               AC_MSG_RESULT("$MYSQL_LIBS")

               AC_MSG_CHECKING(mysql includes)
               MYSQL_CFLAGS=`${mysqlconfig} --cflags`
               AC_MSG_RESULT("$MYSQL_CFLAGS")

               MYSQL_VERSION=`${mysqlconfig} --version`
               MYSQL_VERSION_MAJOR=${MYSQL_VERSION%%.*}
               if test $MYSQL_VERSION_MAJOR -lt 5 ; then
                       AC_MSG_ERROR([MySQL version 5.0 or greater required.])
               fi

               have_mysql=yes
               AC_DEFINE(STORAGE_MYSQL, 1, [Define to 1 if you want to use MySQL for storage.])
       fi
fi
AC_SUBST(MYSQL_CFLAGS)
AC_SUBST(MYSQL_LIBS)
AM_CONDITIONAL(STORAGE_MYSQL, [test "x-$have_mysql" = "x-yes"])

# PostgreSQL
AC_ARG_ENABLE([pgsql],
        AC_HELP_STRING([--enable-pgsql[=DIR]], [enable PostgreSQL auth/reg/storage support (no)]),
        [ enable_pgsql="$enableval" have_pgsql=no  PGSQL_PREFIX="$enableval"],
        [ enable_pgsql=no           have_pgsql=no ])
if test "x-$enable_pgsql" != "x-no" ; then
       if test "$PGSQL_PREFIX" = "yes" ; then
               PGSQL_PREFIX=/usr
       fi

       AC_PATH_PROG(pgconfig,pg_config,,[$PGSQL_PREFIX/bin:$PATH])
       if test [ -z "$pgconfig" ]
       then
               AC_MSG_ERROR([pg_config executable not found: PostgreSQL 8.0 or greater is required.])
       else
               AC_MSG_CHECKING(PostgresSQL libraries)
               PGSQL_LIBDIR=`$pgconfig --libdir`
               PGSQL_LIBS="-L$PGSQL_LIBDIR -lpq"
               AC_MSG_RESULT("$PGSQL_LIBS")

               AC_MSG_CHECKING(pgsql includes)
               PGSQL_INCLUDE=`$pgconfig --includedir`
               PGSQL_CFLAGS="-I$PGSQL_INCLUDE"
               AC_MSG_RESULT("$PGSQL_CFLAGS")

               have_pgsql=yes
               AC_DEFINE([STORAGE_POSTGRES],[1],[Define to 1 if you want to use PostgreSQL for storage.])
       fi
fi
AC_SUBST(PGSQL_CFLAGS)
AC_SUBST(PGSQL_LIBS)
AM_CONDITIONAL(STORAGE_PGSQL, [test "x-$have_pgsql" = "x-yes"])

# SQLite 3
AC_ARG_ENABLE([sqlite],
        AS_HELP_STRING([--enable-sqlite], [enable SQLite3 auth/reg/storage support (no)]),
        [enable_sqlite=$enableval have_sqlite=no],
        [enable_sqlite=no         have_sqlite=no])
if test "x-$enable_sqlite" = "x-yes" ; then
    AC_CHECK_HEADERS([sqlite3.h], [
                AC_CHECK_LIB([sqlite3], [sqlite3_open], [
                        have_sqlite=yes
                        SQLITE_LIBS="-lsqlite3"
                        AC_DEFINE(STORAGE_SQLITE, 1, [Define to 1 if you want to use SQLite 3 for storage.])
                ])
        ])
        if test "x-$have_sqlite" != "x-yes" ; then
                AC_MSG_ERROR([SQLite3 support requested, but headers/libraries not found.])
        fi
fi
AC_SUBST(SQLITE_LIBS)
AM_CONDITIONAL(STORAGE_SQLITE, [test "x-$have_sqlite" = "x-yes"])

# Berkeley DB
_save_libs="$LIBS"
AC_ARG_ENABLE(db, AC_HELP_STRING([--enable-db], [enable Berkeley DB auth/reg/storage support (no)]),
              want_db=$enableval, want_db=no)
if test "x-$want_db" = "x-yes" ; then
    AC_CHECK_HEADERS(db.h)
    if test "x-$ac_cv_header_db_h" = "x-yes" ; then
        for lib in db43 db42 db-4.3 db-4.2 db-4.1 db-4 db4 db41 db ; do
            if test "xxx$have_db_version" != "xxxyes" ; then
                AC_MSG_CHECKING([for db_create in -l$lib])
                save_libs="$LIBS"
                LIBS="-l$lib $LIBS"
                AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],
                                                [[db_create(0,0,0)]])],
                               [AC_MSG_RESULT(yes)
                                AC_MSG_CHECKING(for Berkeley DB version >= 4.1.25)
                                AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],
                                                               [[do {
                                                                     int major, minor, patch;
                                                                     db_version(&major, &minor, &patch);
                                                                     if(major < 4 ||
                                                                         (major == 4 && minor < 1) ||
                                                                         (major == 4 && minor == 1 && patch < 24) ||
                                                                         (int)DB_VERSION_MAJOR != major ||
                                                                         (int)DB_VERSION_MINOR != minor)
                                                                         return 1;
                                                                 } while(0)]])],
                                              [AC_MSG_RESULT(yes)
                                               have_db_version=yes
                                               DB_LIBS="-l$lib"],
                                              AC_MSG_RESULT(no))],
                                AC_MSG_RESULT(no))
                LIBS="$save_libs"
            fi
        done
    fi
    if test "x-$have_db_version" != "x-yes" ; then
        AC_MSG_ERROR([Berkeley DB >= 4.1.24 not found])
    else
        AC_DEFINE(STORAGE_DB,1,[Define to 1 if you want to use Berkeley DB for auth/reg/storage.])
    fi
fi
AC_SUBST(DB_LIBS)
AM_CONDITIONAL(STORAGE_DB, [test "x-$have_db_version" = "x-yes"])
LIBS="$_save_libs"

# Oracle
AC_ARG_WITH(oracle-home,
        AC_HELP_STRING([--with-oracle-home=DIR], [the Oracle home directory, for includes and libs]),
        [ ac_oracle_home="$withval" ])

AC_ARG_ENABLE(oracle, AC_HELP_STRING([--enable-oracle], [enable Oracle auth/reg/storage support (no)]),
              want_oracle=$enableval, want_oracle=no)
if test "x-$want_oracle" = "x-yes" ; then
    AC_CHECK_HEADERS(oci.h)
    if test "x-$ac_cv_header_oci_h" != "x-yes" ; then
       if test -n $ac_oracle_home ; then
          AC_MSG_CHECKING([for oci.h in $ac_oracle_home])
                save_cppflags="$CPPFLAGS"
                CPPFLAGS="-I$ac_oracle_home/rdbms/demo -I$ac_oracle_home/rdbms/public $CPPFLAGS"
                save_libs="$LIBS"
                LIBS="-L$ac_oracle_home/lib $LIBS"
                save_ldflags="$LDFLAGS"
                LDFLAGS="-Wl,-rpath,$ac_oracle_home/lib $LDFLAGS"
                AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <oci.h>]])],
                                  [AC_MSG_RESULT(yes)
                                   AC_DEFINE(HAVE_OCI_H,,[Define if you have oci.h])
                                   ac_cv_header_oci_h=yes],
                                  AC_MSG_RESULT(no))
                if test "x-$ac_cv_header_oci_h" != "x-yes" ; then
                    CPPFLAGS="$save_cppflags"
                    LIBS="$save_libs"
                    LDFLAGS="$save_ldflags"
                fi
       fi
    fi
    if test "x-$ac_cv_header_oci_h" = "x-yes" ; then
        AC_CHECK_LIB(clntsh, OCIInitialize)
    fi
    if test "x-$ac_cv_lib_clntsh_OCIInitialize" != "x-yes" ; then
        AC_MSG_ERROR([Oracle client libraries not found])
    else
        have_oracle="yes"
        ORACLE_CPPFLAGS="-I$ac_oracle_home/rdbms/demo -I$ac_oracle_home/rdbms/public"
        ORACLE_LIBS="-L$ac_oracle_home/lib"
        ORACLE_LDFLAGS="-Wl,-rpath,$ac_oracle_home/lib"
        AC_DEFINE(STORAGE_ORACLE,1,[Define to 1 if you want to use Oracle for auth/reg/storage.])
    fi
fi
AC_SUBST(ORACLE_CPPFLAGS)
AC_SUBST(ORACLE_LIBS)
AC_SUBST(ORACLE_LDFLAGS)
AM_CONDITIONAL(STORAGE_ORACLE, [test "x-$have_oracle" = "x-yes"])

# OpenLDAP
AC_ARG_ENABLE(ldap, AC_HELP_STRING([--enable-ldap], [enable OpenLDAP auth/reg support (no)]),
              want_ldap=$enableval, want_ldap=no)
if test "x-$want_ldap" = "x-yes" ; then
    AC_CHECK_HEADERS(lber.h ldap.h)
    save_libs="$LIBS"
    if test "x-$ac_cv_header_ldap_h" = "x-yes" -a "x-$ac_cv_header_lber_h" = "x-yes" ; then
        AC_CHECK_LIB(lber, ber_alloc)
        AC_CHECK_LIB(ldap, ldap_init)
    fi
    if test "x-$ac_cv_lib_lber_ber_alloc" = "x-yes" -a "x-$ac_cv_lib_ldap_ldap_init" = "x-yes" ; then
        AC_MSG_CHECKING(for OpenLDAP version >= 2.1.0)
        AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <lber.h>
                                         #include <ldap.h>]],
                                       [[do {
                                             LDAPAPIInfo info;
                                             info.ldapai_info_version = LDAP_API_INFO_VERSION;
                                             ldap_get_option(0, LDAP_OPT_API_INFO, &info);
                                             if(info.ldapai_vendor_version != LDAP_VENDOR_VERSION || LDAP_VENDOR_VERSION < 2004)
                                                 return 1;
                                         } while(0)]])],
                                       [AC_MSG_RESULT(yes)
                                        have_ldap_version=yes],
                                       AC_MSG_RESULT(no))
    fi
    LIBS="$save_libs"
    if test "x-$have_ldap_version" != "x-yes" ; then
        AC_MSG_ERROR([OpenLDAP client libraries >= 2.1.0 not found])
    else
        LDAP_LIBS="-llber -lldap"
        AC_DEFINE(STORAGE_LDAP,1,[Define to 1 if you want to use OpenLDAP for auth/reg.])
    fi
fi
AC_SUBST(LDAP_LIBS)
AM_CONDITIONAL(STORAGE_LDAP, [test "x-$have_ldap_version" = "x-yes"])

# Plugabble Authentication Modules (PAM)
AC_ARG_ENABLE(pam, AC_HELP_STRING([--enable-pam], [enable PAM auth/reg support (no)]),
              want_pam=$enableval, want_pam=no)
if test "x-$want_pam" = "x-yes" ; then
    AC_CHECK_HEADERS(security/pam_appl.h)
    if test "x-$ac_cv_header_security_pam_appl_h" = "x-yes" ; then
        AC_CHECK_LIB(pam, pam_start, [
           have_pam="yes"
            PAM_LIBS="-lpam"
            AC_DEFINE(STORAGE_PAM,1,[Define to 1 if you want to use PAM for auth/reg.])
       ], [AC_MSG_ERROR([PAM application libraries not found])])
    fi
fi
AC_SUBST(PAM_LIBS)
AM_CONDITIONAL(STORAGE_PAM, [test "x-$have_pam" = "x-yes"])

# pipe (not really an external package, but does need some checks)
AC_ARG_ENABLE(pipe, AC_HELP_STRING([--enable-pipe], [enable pipe auth/reg support (no)]),
              want_pipe=$enableval, want_pipe=no)
if test "x-$want_pipe" = "x-yes" ; then
    AC_CHECK_HEADERS(sys/wait.h)
    AC_FUNC_FORK
    AC_CHECK_FUNCS(pipe wait)
    if test "x-$ac_cv_header_sys_wait_h" != "x-yes" -o \
            "x-$ac_cv_func_fork" != "x-yes" -o \
            "x-$ac_cv_func_pipe" != "x-yes" -o \
            "x-$ac_cv_func_wait" != "x-yes" ; then
        AC_MSG_ERROR([Pipe auth/reg requirements (sys/wait.h, fork(), pipe(), wait()) not found])
    else
        have_pipe="yes"
        AC_DEFINE(STORAGE_PIPE,1,[Define to 1 if you want to use pipes for auth/reg.])
    fi
fi
AM_CONDITIONAL(STORAGE_PIPE, [test "x-$have_pipe" = "x-yes"])

# Filesystem storage
AC_ARG_ENABLE(fs, AC_HELP_STRING([--enable-fs], [enable filesystem storage support (no)]),
              want_fs=$enableval, want_fs=no)
if test "x-$want_fs" = "x-yes" ; then
    AC_DEFINE(STORAGE_FS,1,[Define to 1 if you want to use the filesystem for storage.])
fi
AM_CONDITIONAL(STORAGE_FS, [test "x-$want_fs" = "x-yes"])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h sys/time.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TIMEZONE
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 gethostname getpagesize gettimeofday inet_ntoa memchr memmove memset mkdir mkfifo regcomp strcasecmp strchr strcspn strdup strerror strncasecmp strndup strrchr strspn strstr strtol tzset uname utime])

# mio backend selection
AC_ARG_ENABLE(mio, AC_HELP_STRING([--enable-mio=BACKENDS], [use one of BACKENDS to drive MIO (select poll epoll kqueue)]),
              mio_check=$enableval, mio_check='select poll epoll kqueue')

mio_backend=''
for backend in $mio_check ; do
    case x-$backend in

        x-kqueue)
        AC_CHECK_HEADERS(sys/event.h)
        if test "x-$ac_cv_header_sys_event_h" = "x-yes" ; then
            AC_CHECK_FUNCS(kqueue,[
                mio_backend='kqueue'
                AC_DEFINE(MIO_KQUEUE,1,[Define to 1 if you want to use 'kqueue' for non-blocking I/O.])])
        fi
        ;;

        x-epoll)
            AC_CHECK_HEADERS(sys/epoll.h)
            if test "x-$ac_cv_header_sys_epoll_h" = "x-yes" ; then
                AC_CHECK_FUNCS(epoll_create,[
                    mio_backend='epoll'
                    AC_DEFINE(MIO_EPOLL,1,[Define to 1 if you want to use 'epoll' for non-blocking I/O.])])
            fi
            ;;

        x-poll)
            AC_CHECK_HEADERS(poll.h)
            if test "x-$ac_cv_header_poll_h" = "x-yes" ; then
                AC_CHECK_FUNCS(poll,[
                    mio_backend='poll'
                    AC_DEFINE(MIO_POLL,1,[Define to 1 if you want to use 'poll' for non-blocking I/O.])])
            fi
            ;;

        x-select)
            AC_CHECK_HEADERS(sys/select.h)
            if test "x-$ac_cv_header_sys_select_h" = "x-yes" ; then
                AC_CHECK_FUNCS(select, have_select=yes)
            fi

            if test "x-$have_select" != "x-yes" -a "x-$ac_cv_header_winsock2_h" = "x-yes" ; then
                AC_MSG_CHECKING([for select in ws2_32])
                AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <winsock2.h>]],
                                                [[select(0,0,0,0,0)]])],
                               [AC_MSG_RESULT(yes)
                                have_select=yes],
                               AC_MSG_RESULT(no))
            fi

            if test "x-$have_select" = "x-yes" ; then
                mio_backend='select'
                AC_DEFINE(MIO_SELECT,1,[Define to 1 if you want to use 'select' for non-blocking I/O.])
            fi
            ;;
    esac
done

if test "x-$mio_backend" = "x-" ; then
    AC_MSG_ERROR([no MIO backend available out of: $mio_check])
else
    AC_MSG_NOTICE([using MIO backend: $mio_backend])
fi

# conditional features
AC_ARG_ENABLE(websocket, AS_HELP_STRING([--enable-websocket],[enable WebSocket support on C2S port (yes)]),
              want_websocket=$enableval, want_websocket=yes)
if test "x-$want_websocket" = "x-yes" ; then
    AC_CHECK_LIB([http_parser], [http_parser_init])
    if test "x-$ac_cv_lib_http_parser_http_parser_init" != "x-yes" ; then
        AC_MSG_ERROR([http_parser library not found])
    else
        AC_DEFINE(USE_WEBSOCKET,1,[Define to 1 if you want to have WebSocket support in C2S.])
    fi
fi
AM_CONDITIONAL(USE_WEBSOCKET, [test "x-$want_websocket" = "x-yes"])

# Anonymous
AC_ARG_ENABLE(anon, AC_HELP_STRING([--enable-anon], [enable anonymous auth/reg support (no)]),
              want_anon=$enableval, want_anon=no)
if test "x-$want_anon" = "x-yes" ; then
    AC_DEFINE(STORAGE_ANON,1,[Define to 1 if you want anonymous auth.])
fi
AM_CONDITIONAL(STORAGE_ANON, [test "x-$want_anon" = "x-yes"])

AC_ARG_ENABLE(superseded, AS_HELP_STRING([--enable-superseded],[enable superseded XEP support (yes)]),
              want_superseded=$enableval, want_superseded=no)
if test "x-$want_superseded" = "x-yes" ; then
    AC_DEFINE(ENABLE_SUPERSEDED,1,[Define to 1 if you want to compile-in superseded XEP handlers.])
fi

AC_ARG_ENABLE(experimental, AS_HELP_STRING([--enable-experimental],[enable experimental features (yes)]),
              want_experimental=$enableval, want_experimental=yes)
if test "x-$want_experimental" = "x-yes" ; then
    AC_DEFINE(ENABLE_EXPERIMENTAL,1,[Define to 1 if you want to compile-in experimental features.])
fi
AM_CONDITIONAL(ENABLE_EXPERIMENTAL, [test "x-$want_experimental" = "x-yes"])

AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests],[enable tests (yes)]),
              want_tests=$enableval, want_tests=yes)
if test "x-$want_tests" = "x-yes" ; then
    PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [want_tests=yes], [want_tests=no])
fi
AM_CONDITIONAL(ENABLE_TESTS, [test "x-$want_tests" = "x-yes"])

AC_ARG_ENABLE([developer], AC_HELP_STRING([--enable-developer], [Compile with all warnings and debugging symbols]),
              CFLAGS="-Wall -ggdb $CFLAGS")

AC_ARG_ENABLE([werror], AS_HELP_STRING([--enable-werror], [Treat all warnings as error]),
              CFLAGS="-Werror $CFLAGS")

AC_ARG_ENABLE(nad_debug, AC_HELP_STRING([--enable-nad-debug], [enable NAD pointer tracking]),
              want_nad_debug=$enableval, want_nad_debug=no)
if test "x-$want_nad_debug" = "x-yes" ; then
    AC_DEFINE(NAD_DEBUG,1,[Define to 1 if you want to enable NAD pointer tracking.])
fi

AC_ARG_ENABLE(mio_debug, AC_HELP_STRING([--enable-mio-debug], [enable managed IO debug output]),
              want_mio_debug=$enableval, want_mio_debug=no)
if test "x-$want_mio_debug" = "x-yes" ; then
    AC_DEFINE(MIO_DEBUG,1,[Define to 1 if you want to enable managed IO debug output.])
fi

AC_CONFIG_FILES([Doxyfile
                 Makefile
                 etc/Makefile
                 etc/templates/Makefile
                 man/Makefile
                 lib/Makefile
                 mio/Makefile
                 sx/Makefile
                 storage/Makefile
                 c2s/Makefile
                 router/Makefile
                 s2s/Makefile
                 sm/Makefile
                 tools/Makefile
                 tests/Makefile])
AC_OUTPUT
