# jabberd2 configure script
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([jabberd], [2.x.dev], [jabberd2@lists.xiaoka.com])
AC_CONFIG_SRCDIR([sx/sx.h])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
# libtool for internal linking
AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

if test "x-$lt_cv_dlopen_libs" != "x-" ; then
    LIBS="$LIBS $lt_cv_dlopen_libs"
fi

# check for optimisation level
AC_MSG_CHECKING([CFLAGS optimization level])
[if echo $CFLAGS | grep '.*-O[3s].*' >/dev/null 2>&1; then]
    AC_MSG_ERROR([maximum allowed optimization level is -O2])
fi
AC_MSG_RESULT([fine])

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

# set type of "char" to be "unsigned char"
CFLAGS="$CFLAGS -funsigned-char"

# developer flags
AC_ARG_ENABLE([developer], AC_HELP_STRING([--enable-developer], [Compile with warnings and debugging symbols]),
              CFLAGS="-Wall -Wno-pointer-sign -g $CFLAGS")
# debugging
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable debug messages]),
              want_debug=$enableval, want_debug=no)
if test "x-$want_debug" = "x-yes" ; then
    AC_DEFINE(DEBUG,1,[Define to 1 if you want to get debug output with -D.])
    AC_DEFINE(SX_DEBUG,1,[Define to 1 if you want to get SX debug output with -D.])
fi

AC_ARG_ENABLE(nad_debug, AC_HELP_STRING([--enable-nad-debug], [enable NAD pointer tracking]),
              want_nad_debug=$enableval, want_nad_debug=no)
if test "x-$want_nad_debug" = "x-yes" ; then
    AC_DEFINE(NAD_DEBUG,1,[Define to 1 if you want to enable NAD pointer tracking.])
fi

AC_ARG_ENABLE(pool_debug, AC_HELP_STRING([--enable-pool-debug], [enable memory pool statistics]),
              want_pool_debug=$enableval, want_pool_debug=no)
if test "x-$want_pool_debug" = "x-yes" ; then
    AC_DEFINE(POOL_DEBUG,1,[Define to 1 if you want to enable memory pool statistics.])
fi

AC_ARG_ENABLE(mio_debug, AC_HELP_STRING([--enable-mio-debug], [enable managed IO debug output]),
              want_mio_debug=$enableval, want_mio_debug=no)
if test "x-$want_mio_debug" = "x-yes" ; then
    AC_DEFINE(MIO_DEBUG,1,[Define to 1 if you want to enable managed IO debug output.])
fi

# Two-step header checking.  First check for headers which don't
# require any other headers.
AC_HEADER_DIRENT
AC_HEADER_RESOLV
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_CHECK_HEADERS([arpa/inet.h \
                  arpa/nameser.h \
                  fcntl.h \
                  netinet/in.h \
                  signal.h \
                  stdarg.h \
                  stdint.h \
                  stdlib.h \
                  string.h \
                  sys/filio.h \
                  sys/ioctl.h \
                  sys/socket.h \
                  sys/time.h \
                  sys/timeb.h \
                  sys/types.h \
                  sys/stat.h \
                  sys/utsname.h \
                  syslog.h \
                  unistd.h \
                  windows.h \
                  winsock2.h \
])

# Now check for those headers that do, including all the required
# headers.
AC_CHECK_HEADERS([resolv.h windns.h],,,
[#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_STRUCT_TIMEZONE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# generic system types
AC_CREATE_STDINT_H(ac-stdint.h)

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_REPLACE_FNMATCH
AC_FUNC_FORK
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([close \
                dup2 \
                fcntl \
                _findfirst \
                gethostname \
                getopt \
                getpagesize \
                getpid \
                gettimeofday \
                inet_aton \
                inet_ntoa \
                ioctl \
                isascii \
                memchr \
                memmove \
                memset \
                mkdir \
                _mkdir \
                modf \
                select \
                setenv \
                sleep \
                Sleep \
                socket \
                strcasecmp \
                strchr \
                strdup \
                strerror \
                stricmp \
                strncasecmp \
                strndup \
                strnicmp \
                strstr \
                tzset \
                uname \
])

AC_CHECK_FUNC([crypt], ,[AC_CHECK_LIB([crypt], [crypt])])
if test "x$ac_cv_lib_crypt_crypt" = "xyes"; then
  AC_DEFINE(HAVE_CRYPT, 1, [Define to 1 if you have the crypt() function])
fi
AM_CONDITIONAL(HAVE_CRYPT, [test "x$ac_cv_lib_crypt_crypt" = "xyes"])
AC_CHECK_FUNC([connect], ,[AC_CHECK_LIB([socket], [connect])])
AC_CHECK_LIB([ws2_32], [_head_libws2_32_a])

AC_CHECK_FUNC(gethostbyname, ,[AC_CHECK_LIB([resolv], [gethostbyname])])
AC_CHECK_FUNC(gethostbyname, ,[AC_CHECK_LIB([nsl], [gethostbyname])])
if test "x$ac_cv_lib_nsl_gethostbyname" != "xyes" && test "x$ac_cv_func_gethostbyname" != "xyes" ; then
  AC_CHECK_FUNC([gethostbyname], , [AC_CHECK_LIB([socket], [gethostbyname])])
fi
if test "$ac_cv_lib_nsl_gethostbyname" = "$ac_cv_func_gethostbyname" ; then
  AC_MSG_CHECKING([if we can include libnsl + libsocket])
  LIBS="-lnsl -lsocket $LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[(void) gethostbyname]])],[my_ac_link_result=yes],[my_ac_link_result=no ])
  if test "$my_ac_link_result" = "no" ; then
    AC_MSG_RESULT([failure])
    AC_MSG_ERROR([unable to use gethostbyname()])
  else
    AC_MSG_RESULT([success])
  fi
fi

AC_SEARCH_LIBS(inet_ntop, nsl,[
    AC_DEFINE(HAVE_INET_NTOP, 1,
    [Define to 1 if you have the `inet_ntop' function.])])

dnl ** Check for inet_ntop
AC_SEARCH_LIBS(inet_pton, nsl,[
    AC_DEFINE(HAVE_INET_PTON, 1,
    [Define to 1 if you have the `inet_pton' function.])])

# windows has different names for a few basic things
if test "x-$ac_cv_func_getpid" != "x-yes" -a "x-$ac_cv_func__getpid" = "x-yes" ; then
    AC_DEFINE(getpid,_getpid,[Define to a function than can provide getpid(2) functionality.])
fi

if test "x-$ac_cv_func_sleep" != "x-yes" -a "x-$ac_cv_func_Sleep" = "x-yes" ; then
    AC_DEFINE(sleep,Sleep,[Define to a function than can provide sleep(2) functionality.])
fi

if test "x-$ac_cv_func_strcasecmp" != "x-yes" -a "x-$ac_cv_func_stricmp" = "x-yes" ; then
    AC_DEFINE(strcasecmp,stricmp,[Define to a function than can provide strcasecmp(3) functionality.])
fi

if test "x-$ac_cv_func_strncasecmp" != "x-yes" -a "x-$ac_cv_func_strnicmp" = "x-yes" ; then
    AC_DEFINE(strncasecmp,strnicmp,[Define to a function than can provide strncasecmp(3) functionality.])
fi

# winsock substitutions
if test "x-$ac_cv_func_close" != "x-yes" ; then
    AC_MSG_CHECKING(for closesocket)
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <winsock2.h>]],
                                    [[closesocket(0)]])],
                   [AC_MSG_RESULT(yes)
                    AC_DEFINE(close,closesocket,[Define to a function than can provide close(2) functionality.])],
                    AC_DEFINE(HAVE_CLOSE,1,[Define to 1 if you have the 'close' function.])
                   AC_MSG_RESULT(no))
fi

if test "x-$ac_cv_func_ioctl" != "x-yes" ; then
    AC_MSG_CHECKING(for ioctlsocket)
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <winsock2.h>]],
                                    [[ioctlsocket(0,0,0)]])],
                   [AC_MSG_RESULT(yes)
                    AC_DEFINE(ioctl,ioctlsocket,[Define to a function than can provide ioctl(2) functionality.])],
                    AC_DEFINE(HAVE_IOCTL,1,[Define to 1 if you have the 'ioctl' function.])
                   AC_MSG_RESULT(no))
fi

# res_query has been seen in libc, libbind and libresolv
if test "x-$ac_cv_header_resolv_h" = "x-yes" ; then
    AC_CHECK_FUNCS(res_query)
    if test "x-$ac_cv_func_res_query" = "x-yes" ; then
        have_res_query=yes
    else
        AC_CHECK_LIB(resolv, res_query)
        if test "x-$ac_cv_lib_resolv_res_query" = "x-yes" ; then
            have_res_query=yes
        else
            AC_CHECK_LIB(bind, res_query)
            if test "x-$ac_cv_lib_bind_res_query" = "x-yes" ; then
                have_res_query=yes
            else
                dnl some glibcs have res_query as a macro, so work around it
                AC_MSG_CHECKING([for res_query in -lresolv (alternate version)])
                save_libs="$LIBS"
                LIBS="-lresolv $LIBS"
                AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]],
                                                [[res_query(0,0,0,0,0)]])],
                               [AC_MSG_RESULT(yes)
                                have_res_query=yes],
                               [AC_MSG_RESULT(no)
                                LIBS="$save_libs"])
            fi
        fi
    fi
fi
# windows calls it DnsQuery
if test "x-$ac_cv_header_windns_h" = "x-yes" ; then
    AC_MSG_CHECKING([for DnsQuery in -ldnsapi])
    save_libs="$LIBS"
    LIBS="-ldnsapi $LIBS"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <windows.h>
                                      #include <windns.h>]],
                                    [[DnsQuery(0,0,0,0,0,0)]])],
                   [AC_MSG_RESULT(yes)
                    have_dnsquery=yes],
                   [AC_MSG_RESULT(no)
                    LIBS="$save_libs"])
fi
if test "x-$have_res_query" = "x-yes" ; then
    AC_DEFINE(HAVE_RES_QUERY,1,[Define to 1 if you have the 'res_query' function.])
elif test "x-$have_dnsquery" = "x-yes" ; then
    AC_DEFINE(HAVE_DNSQUERY,1,[Define to 1 if you have the 'DnsQuery' function.])
else
    AC_MSG_ERROR([no DNS resolver interface (res_query or DnsQuery) found])
fi

# syslog
if test "x-$ac_cv_header_syslog_h" = "x-yes" ; then
    AC_CHECK_FUNCS(syslog vsyslog)
fi

if test "x-$ac_cv_header_windows_h" = "x-yes" ; then
    AC_MSG_CHECKING(for ReportEvent)
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <windows.h>]],
                                    [[ReportEvent(0,0,0,0,0,0,0,0,0)]])],
                   [AC_MSG_RESULT(yes)
                    AC_DEFINE(HAVE_REPORTEVENT,1,[Define to 1 if you have the 'ReportEvent' function.])],
                   AC_MSG_RESULT(no))
fi

# snprintf/vsnprintf don't exist everywhere. additionally, we require
# them to gracefully accept NULLs, which is non-standard
AC_CHECK_FUNCS(snprintf vsnprintf)
if test "x-$ac_cv_func_snprintf" = "x-yes" ; then
    AC_MSG_CHECKING([if snprintf can handle NULL arguments])
    AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <stdio.h>
                                    #include <signal.h>
                                    segv() { exit(1); }
                                    main() { char b[10]; signal(SIGSEGV,segv); snprintf(b,10,"%s",NULL); exit(0); }]])],
                  AC_MSG_RESULT(yes),
                  [AC_MSG_RESULT(no)
                   AC_DEFINE(HAVE_BROKEN_SNPRINTF,1,[Define to 1 if 'snprintf' cannot handle NULL arguments.])])
fi
if test "x-$ac_cv_func_vsnprintf" = "x-yes" ; then
    AC_MSG_CHECKING([if vsnprintf can handle NULL arguments])
    AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <stdio.h>
                                    #include <signal.h>
                                    #include <stdarg.h>
                                    segv() { exit(1); }
                                    expand(char *f,...) { va_list ap; char b[10]; va_start(ap,f); vsnprintf(b,10,f,ap); va_end(ap); }
                                    main() { char b[10]; signal(SIGSEGV,segv); expand("%s", NULL); exit(0); }]])],
                  AC_MSG_RESULT(yes),
                  [AC_MSG_RESULT(no)
                   AC_DEFINE(HAVE_BROKEN_VSNPRINTF,1,[Define to 1 if 'vsnprintf' cannot handle NULL arguments.])])
fi
TYPE_SOCKLEN_T
#
# Checks for libraries.

# Expat
AC_CHECK_LIB([expat], [XML_ParserCreate])
if test "x-$ac_cv_lib_expat_XML_ParserCreate" != "x-yes" ; then
    AC_MSG_ERROR([Expat not found])
fi

# libidn >= 0.3.0
AC_CHECK_LIB(idn, stringprep_check_version)
if test "x-$ac_cv_lib_idn_stringprep_check_version" = "x-yes" ; then
    AC_MSG_CHECKING(for Libidn version >= 0.3.0)
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <stringprep.h>]],
                                   [[return !(stringprep_check_version("0.3.0"))]])],
                  [AC_MSG_RESULT(yes)
                    have_idn=yes],
                  AC_MSG_RESULT(no))
fi
if test "x-$have_idn" != "x-yes" ; then
    AC_MSG_ERROR([Libidn >= 0.3.0 not found])
fi

# udns
AC_CHECK_LIB(udns, dns_init)
if test "x-$ac_cv_lib_udns_dns_init" != "x-yes" ; then
    AC_MSG_ERROR([UDNS library not found])
fi

# GnuSASL
AC_CHECK_HEADERS(gsasl.h)
if test "x-$ac_cv_header_gsasl_h" = "x-yes" ; then
    AC_CHECK_LIB(gsasl, gsasl_check_version)
fi
if test "x-$ac_cv_lib_gsasl_gsasl_check_version" = "x-yes" ; then
    AC_MSG_CHECKING(for GnuSASL version >= 1.4.0)
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <gsasl.h>]],
                                   [[return !(gsasl_check_version("1.4.0"))]])],
                  [AC_MSG_RESULT(yes)
                    have_gsasl=yes],
                  AC_MSG_RESULT(no))
fi

if test "x-$have_gsasl" != "x-yes" ; then
    AC_MSG_ERROR([GnuSASL >= 1.4.0 not found])
fi

#
# optional libs

# OpenSSL >= 1.0.1
AC_ARG_ENABLE(ssl, AC_HELP_STRING([--enable-ssl[=DIR]], [enable SSL/TLS support (yes)]), want_ssl=$enableval, want_ssl=yes)
if test "x-$want_ssl" != "x-no" ; then
    if test "x-$want_ssl" != "x-yes" ; then
        CFLAGS="$CFLAGS -I$enableval/include" 
        CPPFLAGS="$CPPFLAGS -I$enableval/include" 
        LDFLAGS="$LDFLAGS -L$enableval/lib"
    fi
    AC_CHECK_HEADERS(openssl/crypto.h)
    if test "x-$ac_cv_header_openssl_crypto_h" = "x-yes" ; then
        AC_CHECK_LIB(crypto, CRYPTO_lock)
    fi
    if test "x-$ac_cv_lib_crypto_CRYPTO_lock" = "x-yes" ; then
        AC_CHECK_HEADERS(openssl/ssl.h)
    fi
    if test "x-$ac_cv_header_openssl_ssl_h" = "x-yes" ; then
        AC_CHECK_LIB(ssl, SSL_connect)
    fi
    if test "x-$ac_cv_lib_ssl_SSL_connect" = "x-yes" ; then
        AC_MSG_CHECKING(for OpenSSL version >= 1.0.1)
        AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <openssl/crypto.h>]],
                                       [[return !(SSLeay() >= 0x010001000L)]])],
                      [AC_MSG_RESULT(yes)
                       have_openssl=yes],
                      AC_MSG_RESULT(no))
    fi
    if test "x-$have_openssl" != "x-yes" ; then
        AC_MSG_ERROR([OpenSSL >= 1.0.1 not found])
    fi

    AC_DEFINE(HAVE_SSL,1,[Define to 1 if OpenSSL is available.])
fi
AM_CONDITIONAL(HAVE_SSL, [test "x-$have_openssl" = "x-yes"])

dnl Check for & handle argument to --with-zlib.
_cppflags=$CPPFLAGS
_ldflags=$LDFLAGS
AC_ARG_WITH(zlib,
AC_HELP_STRING([--with-zlib=DIR],[search for zlib in DIR])
AC_HELP_STRING([--without-zlib],[disable use of zlib]),
               [OPT_ZLIB="$withval"])

if test "$OPT_ZLIB" = "no" ; then
    AC_MSG_WARN([zlib disabled])
else
  if test "$OPT_ZLIB" = "yes" ; then
     OPT_ZLIB=""
  fi

  if test -z "$OPT_ZLIB" ; then
    dnl check for the lib first without setting any new path, since many
    dnl people have it in the default path

    AC_CHECK_LIB(z, inflateEnd,
                   dnl libz found, set the variable
                   [HAVE_LIBZ="1"],
                   dnl if no lib found, try /usr/local
                   [OPT_ZLIB="/usr/local"])

  fi

  dnl Add a nonempty path to the compiler flags
  if test -n "$OPT_ZLIB"; then
     CPPFLAGS="$CPPFLAGS -I$OPT_ZLIB/include"
     LDFLAGS="$LDFLAGS -L$OPT_ZLIB/lib$libsuff"
  fi

  AC_CHECK_HEADER(zlib.h,
    [
    dnl zlib.h was found
    HAVE_ZLIB_H="1"
    dnl if the lib wasn't found already, try again with the new paths
    if test "$HAVE_LIBZ" != "1"; then
      AC_CHECK_LIB(z, gzread,
                   [
                   dnl the lib was found!
                   HAVE_LIBZ="1"
                   ],
                   [ CPPFLAGS=$_cppflags
                   LDFLAGS=$_ldflags])
    fi
    ],
    [
      dnl zlib.h was not found, restore the flags
      CPPFLAGS=$_cppflags
      LDFLAGS=$_ldflags]
    )

  if test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" != "1"
  then
    AC_MSG_WARN([configure found only the libz lib, not the header file!])
  elif test "$HAVE_LIBZ" != "1" && test "$HAVE_ZLIB_H" = "1"
  then
    AC_MSG_WARN([configure found only the libz header file, not the lib!])
  elif test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" = "1"
  then
    dnl both header and lib were found!
    AC_SUBST(HAVE_LIBZ)
    AC_DEFINE(HAVE_ZLIB_H, 1, [if you have the zlib.h header file])
    AC_DEFINE(HAVE_LIBZ, 1, [if zlib is available])
    LIBS="$LIBS -lz"
  fi
fi
AM_CONDITIONAL(HAVE_LIBZ, [test "$HAVE_LIBZ" = "1"])

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

# Anonymous
AC_ARG_ENABLE(anon, AC_HELP_STRING([--enable-anon], [enable anonymous auth/reg support (no)]),
              want_anon=$enableval, want_anon=no)
if test "x-$want_anon" = "x-yes" ; then
    AC_DEFINE(STORAGE_ANON,1,[Define to 1 if you want anonymous auth.])
fi
AM_CONDITIONAL(STORAGE_ANON, [test "x-$want_anon" = "x-yes"])


# Filesystem storage
AC_ARG_ENABLE(fs, AC_HELP_STRING([--enable-fs], [enable filesystem storage support (no)]),
              want_fs=$enableval, want_fs=no)
if test "x-$want_fs" = "x-yes" ; then
    AC_DEFINE(STORAGE_FS,1,[Define to 1 if you want to use the filesystem for storage.])
fi
AM_CONDITIONAL(STORAGE_FS, [test "x-$want_fs" = "x-yes"])

#
# IPv6 checks
AC_DEFUN([_IP6_INCLUDES],[[
#include "ac-stdint.h"
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
]])

# these types are sometimes missing
AC_CHECK_TYPES([in_port_t, sa_family_t, struct sockaddr_storage, struct sockaddr_in6, struct in6_addr],,, _IP6_INCLUDES)

# some glibcs have broken sockaddr_storage members
if test "x-$ac_cv_type_struct_sockaddr_storage" = "x-yes" ; then
    AC_MSG_CHECKING(for broken __ss_family member in struct sockaddr_storage)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(_IP6_INCLUDES,
                                       [[do {
                                             struct sockaddr_storage s;
                                             s.__ss_family = 0;
                                         } while(0)]])],
                      [AC_MSG_RESULT(yes)
                       AC_DEFINE(ss_family, __ss_family,
                                 [Define to '__ss_family' if 'struct sockaddr_storage' defines '__ss_family' instead of 'ss_family'.])],
                      AC_MSG_RESULT(no))

    AC_MSG_CHECKING(for broken __ss_len member in struct sockaddr_storage)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(_IP6_INCLUDES,
                                       [[do {
                                             struct sockaddr_storage s;
                                             s.__ss_len = 0;
                                         } while(0)]])],
                      [AC_MSG_RESULT(yes)
                       AC_DEFINE(ss_len, __ss_len,
                                 [Define to '__ss_len' if 'struct sockaddr_storage' defines '__ss_len' instead of 'ss_len'.])],
                      AC_MSG_RESULT(no))
fi


#
# mio backend selection

AC_ARG_ENABLE(mio, AC_HELP_STRING([--enable-mio=BACKENDS], [use one of BACKENDS to drive MIO (select poll epoll kqueue)]),
              mio_check=$enableval, mio_check='kqueue epoll poll select')

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
fi

# use libc function substitution library?
AC_ARG_WITH(subst,
AC_HELP_STRING([--without-subst],[disable use of substitution library]),
               [OPT_LIBSUBST="$withval"])
AC_SUBST(USE_LIBSUBST)
AM_CONDITIONAL(USE_LIBSUBST, [test "$OPT_LIBSUBST" != "no"])

# conditional features
AC_ARG_ENABLE(superseded, AC_HELP_STRING([--enable-superseded], [enable superseded XEP support (yes)]),
              want_superseded=$enableval, want_superseded=no)
if test "x-$want_superseded" = "x-yes" ; then
    AC_DEFINE(ENABLE_SUPERSEDED,1,[Define to 1 if you want to compile-in superseded XEP handlers.])
fi

AC_ARG_ENABLE(experimental, AC_HELP_STRING([--enable-experimental], [enable experimental features (yes)]),
              want_experimental=$enableval, want_experimental=no)
if test "x-$want_experimental" = "x-yes" ; then
    AC_DEFINE(ENABLE_EXPERIMENTAL,1,[Define to 1 if you want to compile-in experimental features.])
fi
AM_CONDITIONAL(ENABLE_EXPERIMENTAL, [test "x-$want_experimental" = "x-yes"])

AC_ARG_ENABLE(tests, AC_HELP_STRING([--enable-tests], [enable tests (yes)]),
              want_tests=$enableval, want_tests=yes)
if test "x-$want_tests" = "x-yes" ; then
    PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [want_tests=yes], [want_tests=no])
fi
AM_CONDITIONAL(ENABLE_TESTS, [test "x-$want_tests" = "x-yes"])

AC_ARG_ENABLE([werror], AC_HELP_STRING([--enable-werror], [Treat all warnings as error]),
              CFLAGS="-Wall -Werror $CFLAGS")

# Generate Makefiles
AC_CONFIG_FILES([Doxyfile
                 Makefile
                 etc/Makefile
                 etc/templates/Makefile
                 man/Makefile
                 subst/Makefile
                 util/Makefile
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
