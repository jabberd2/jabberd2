/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "ac-stdint.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <expat.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#elif defined(HAVE_SYS_TIMEB_H)
# include <sys/timeb.h>
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ctype.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifndef PATH_MAX
#ifndef MAXPATHLEN
# define PATH_MAX 512
#else
# define PATH_MAX MAXPATHLEN
#endif
#endif

#ifdef USE_LIBSUBST
#include "subst/subst.h"
#endif

#include "util/util_compat.h"

#ifndef INCL_UTIL_H
#define INCL_UTIL_H

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

#ifdef __cplusplus
extern "C" {
#endif

/* crypto hashing utils */
#include "sha1.h"
#include "md5.h"

#include <util/nad.h>
#include <util/pool.h>
#include <util/xhash.h>

/* --------------------------------------------------------- */
/*                                                           */
/* String management routines                                */
/*                                                           */
/** --------------------------------------------------------- */
JABBERD2_API char *j_strdup(const char *str); /* provides NULL safe strdup wrapper */
JABBERD2_API char *j_strcat(char *dest, char *txt); /* strcpy() clone */
JABBERD2_API int j_strcmp(const char *a, const char *b); /* provides NULL safe strcmp wrapper */
JABBERD2_API int j_strcasecmp(const char *a, const char *b); /* provides NULL safe strcasecmp wrapper */
JABBERD2_API int j_strncmp(const char *a, const char *b, int i); /* provides NULL safe strncmp wrapper */
JABBERD2_API int j_strncasecmp(const char *a, const char *b, int i); /* provides NULL safe strncasecmp wrapper */
JABBERD2_API int j_strlen(const char *a); /* provides NULL safe strlen wrapper */
JABBERD2_API int j_atoi(const char *a, int def); /* checks for NULL and uses default instead, convienence */
JABBERD2_API char *j_attr(const char** atts, const char *attr); /* decode attr's (from expat) */
JABBERD2_API char *j_strnchr(const char *s, int c, int n); /* like strchr, but only searches n chars */

/** old convenience function, now in str.c */
JABBERD2_API void shahash_r(const char* str, char hashbuf[41]);
JABBERD2_API void shahash_raw(const char* str, unsigned char hashval[20]);

/* --------------------------------------------------------- */
/*                                                           */
/* XML escaping utils                                        */
/*                                                           */
/* --------------------------------------------------------- */
JABBERD2_API char *strescape(pool_t p, char *buf, int len); /* Escape <>&'" chars */
JABBERD2_API char *strunescape(pool_t p, char *buf);


/* --------------------------------------------------------- */
/*                                                           */
/* String pools (spool) functions                            */
/*                                                           */
/* --------------------------------------------------------- */
struct spool_node
{
    char *c;
    struct spool_node *next;
};

typedef struct spool_struct
{
    pool_t p;
    int len;
    struct spool_node *last;
    struct spool_node *first;
} *spool;

JABBERD2_API spool spool_new(pool_t p); /* create a string pool */
JABBERD2_API void spooler(spool s, ...); /* append all the char * args to the pool, terminate args with s again */
JABBERD2_API char *spool_print(spool s); /* return a big string */
JABBERD2_API void spool_add(spool s, char *str); /* add a single string to the pool */
JABBERD2_API void spool_escape(spool s, char *raw, int len); /* add and xml escape a single string to the pool */
JABBERD2_API char *spools(pool_t p, ...); /* wrap all the spooler stuff in one function, the happy fun ball! */


/* known namespace uri */
#include "util/uri.h"

/* JID manipulation */
#include "util/jid.h"

/* logging */

typedef enum {
    log_STDOUT,
    log_SYSLOG,
    log_FILE
} log_type_t;

typedef struct log_st
{
    log_type_t  type;
    FILE        *file;
} *log_t;

typedef struct log_facility_st
{
    const char  *facility;
    int         number;
} log_facility_t;

JABBERD2_API log_t    log_new(log_type_t type, const char *ident, const char *facility);
JABBERD2_API void     log_write(log_t log, int level, const char *msgfmt, ...);
JABBERD2_API void     log_free(log_t log);

/* config files */
typedef struct config_elem_st   *config_elem_t;
typedef struct config_st        *config_t;

/** holder for the config hash and nad */
struct config_st
{
    xht                 hash;
    nad_t               nad;
};

/** a single element */
struct config_elem_st
{
    char                **values;
    int                 nvalues;
    char                ***attrs;
};

JABBERD2_API config_t         config_new(void);
JABBERD2_API int              config_load(config_t c, const char *file);
JABBERD2_API int              config_load_with_id(config_t c, const char *file, const char *id);
JABBERD2_API config_elem_t    config_get(config_t c, const char *key);
JABBERD2_API const char      *config_get_one(config_t c, const char *key, int num);
JABBERD2_API const char      *config_get_one_default(config_t c, const char *key, int num, const char *default_value);
JABBERD2_API int              config_count(config_t c, const char *key);
JABBERD2_API char             *config_get_attr(config_t c, const char *key, int num, const char *attr);
JABBERD2_API char             *config_expand(config_t c, const char *value); //! Replaces $(some.value) with config_get_one(c, "some.value", 0)
JABBERD2_API void             config_free(config_t);


/*
 * IP-based access controls
 */

typedef struct access_rule_st
{
    struct sockaddr_storage ip;
    int            mask;
} *access_rule_t;

typedef struct access_st
{
    int             order;      /* 0 = allow,deny  1 = deny,allow */

    access_rule_t   allow;
    int             nallow;

    access_rule_t   deny;
    int             ndeny;
} *access_t;

JABBERD2_API access_t    access_new(int order);
JABBERD2_API void        access_free(access_t access);
JABBERD2_API int         access_allow(access_t access, char *ip, char *mask);
JABBERD2_API int         access_deny(access_t access, char *ip, char *mask);
JABBERD2_API int         access_check(access_t access, char *ip);


/*
 * rate limiting
 */

typedef struct rate_st
{
    int             total;      /* if we exceed this many events */
    int             seconds;    /* in this many seconds */
    int             wait;       /* then go bad for this many seconds */

    time_t          time;       /* time we started counting events */
    int             count;      /* event count */

    time_t          bad;        /* time we went bad, or 0 if we're not */
} *rate_t;

JABBERD2_API rate_t      rate_new(int total, int seconds, int wait);
JABBERD2_API void        rate_free(rate_t rt);
JABBERD2_API void        rate_reset(rate_t rt);

/**
 * Add a number of events to the counter.  This takes care of moving
 * the sliding window, if we've moved outside the previous window.
 */
JABBERD2_API void        rate_add(rate_t rt, int count);

/**
 * @return The amount of events we have left before we hit the rate
 *         limit.  This could be number of bytes, or number of
 *         connection attempts, etc.
 */
JABBERD2_API int         rate_left(rate_t rt);

/**
 * @return 1 if we're under the rate limit and everything is fine or
 *         0 if the rate limit has been exceeded and we should throttle
 *         something.
 */
JABBERD2_API int         rate_check(rate_t rt);

/*
 * helpers for ip addresses
 */

#include "inaddr.h"        /* used in mio as well */

/*
 * serialisation helper functions
 */

JABBERD2_API int         ser_string_get(char **dest, int *source, const char *buf, int len);
JABBERD2_API int         ser_int_get(int *dest, int *source, const char *buf, int len);
JABBERD2_API void        ser_string_set(char *source, int *dest, char **buf, int *len);
JABBERD2_API void        ser_int_set(int source, int *dest, char **buf, int *len);

/*
 * priority queues
 */

typedef struct _jqueue_node_st  *_jqueue_node_t;
struct _jqueue_node_st {
    void            *data;

    int             priority;

    _jqueue_node_t  next;
    _jqueue_node_t  prev;
};

typedef struct _jqueue_st {
    pool_t          p;
    _jqueue_node_t  cache;

    _jqueue_node_t  front;
    _jqueue_node_t  back;

    int             size;
    char            *key;
    time_t          init_time;
} *jqueue_t;

JABBERD2_API jqueue_t    jqueue_new(void);
JABBERD2_API void        jqueue_free(jqueue_t q);
JABBERD2_API void        jqueue_push(jqueue_t q, void *data, int pri);
JABBERD2_API void        *jqueue_pull(jqueue_t q);
JABBERD2_API int         jqueue_size(jqueue_t q);
JABBERD2_API time_t      jqueue_age(jqueue_t q);


/* ISO 8601 / JEP-0082 date/time manipulation */
typedef enum {
    dt_DATE     = 1,
    dt_TIME     = 2,
    dt_DATETIME = 3,
    dt_LEGACY   = 4
} datetime_t;

JABBERD2_API time_t  datetime_in(char *date);
JABBERD2_API void    datetime_out(time_t t, datetime_t type, char *date, int datelen);


/* base64 functions */
JABBERD2_API int apr_base64_decode_len(const char *bufcoded, int buflen);
JABBERD2_API int apr_base64_decode(char *bufplain, const char *bufcoded, int buflen);
JABBERD2_API int apr_base64_encode_len(int len);
JABBERD2_API int apr_base64_encode(char *encoded, const char *string, int len);

/* convenience, result string must be free()'d by caller */
JABBERD2_API char *b64_encode(char *buf, int len);
JABBERD2_API char *b64_decode(char *buf);


/* stanza manipulation */
#define stanza_err_BAD_REQUEST              (100)
#define stanza_err_CONFLICT                 (101)
#define stanza_err_FEATURE_NOT_IMPLEMENTED  (102)
#define stanza_err_FORBIDDEN                (103)
#define stanza_err_GONE                     (104)
#define stanza_err_INTERNAL_SERVER_ERROR    (105)
#define stanza_err_ITEM_NOT_FOUND           (106)
#define stanza_err_JID_MALFORMED            (107)
#define stanza_err_NOT_ACCEPTABLE           (108)
#define stanza_err_NOT_ALLOWED              (109)
#define stanza_err_PAYMENT_REQUIRED         (110)
#define stanza_err_RECIPIENT_UNAVAILABLE    (111)
#define stanza_err_REDIRECT                 (112)
#define stanza_err_REGISTRATION_REQUIRED    (113)
#define stanza_err_REMOTE_SERVER_NOT_FOUND  (114)
#define stanza_err_REMOTE_SERVER_TIMEOUT    (115)
#define stanza_err_RESOURCE_CONSTRAINT      (116)
#define stanza_err_SERVICE_UNAVAILABLE      (117)
#define stanza_err_SUBSCRIPTION_REQUIRED    (118)
#define stanza_err_UNDEFINED_CONDITION      (119)
#define stanza_err_UNEXPECTED_REQUEST       (120)
#define stanza_err_OLD_UNAUTH               (121)
#define stanza_err_UNKNOWN_SENDER           (122)
#define stanza_err_LAST                     (123)

JABBERD2_API nad_t stanza_error(nad_t nad, int elem, int err);
JABBERD2_API nad_t stanza_tofrom(nad_t nad, int elem);

typedef struct _stanza_error_st {
    const char  *name;
    const char  *type;
    const char  *code;
} *stanza_error_t;

JABBERD2_API struct _stanza_error_st _stanza_errors[];


/* hex conversion utils */
JABBERD2_API void hex_from_raw(char *in, int inlen, char *out);
JABBERD2_API int hex_to_raw(char *in, int inlen, char *out);


/* xdata in a seperate file */
#include "xdata.h"


/* debug logging */
JABBERD2_API int get_debug_flag(void);
JABBERD2_API void set_debug_flag(int v);
JABBERD2_API void debug_log(const char *file, int line, const char *msgfmt, ...);
JABBERD2_API int set_debug_file(const char *filename);

JABBERD2_API int set_debug_log_from_config(config_t c);

#define ZONE __FILE__,__LINE__
#define MAX_DEBUG 8192

/* if no debug, basically compile it out */
#ifdef DEBUG
#define log_debug if(get_debug_flag()) debug_log
#else
#define log_debug if(0) debug_log
#endif

/* Portable signal function */
typedef void jsighandler_t(int);
JABBERD2_API jsighandler_t* jabber_signal(int signo,  jsighandler_t *func);

#ifdef _WIN32
/* Windows service wrapper function */
typedef int (jmainhandler_t)(int argc, char** argv);
JABBERD2_API int jabber_wrap_service(int argc, char** argv, jmainhandler_t *wrapper, LPCTSTR name, LPCTSTR display, LPCTSTR description, LPCTSTR depends);
#define JABBER_MAIN(name, display, description, depends) jabber_main(int argc, char** argv); \
                    main(int argc, char** argv) { return jabber_wrap_service(argc, argv, jabber_main, name, display, description, depends); } \
                    jabber_main(int argc, char** argv)
#else /* _WIN32 */
#define JABBER_MAIN(name, display, description, depends) int main(int argc, char** argv)
#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif

#if XML_MAJOR_VERSION > 1
/* XML_StopParser is present in expat 2.x */
#define HAVE_XML_STOPPARSER
#endif

/* define TRUE and FALSE if not yet defined */
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#endif    /* INCL_UTIL_H */


