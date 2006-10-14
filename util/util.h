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

#include "subst/subst.h"

#include "util/util_compat.h"

#ifndef INCL_UTIL_H
#define INCL_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/* crypto hashing utils */
#include "sha1.h"
#include "md5.h"


/* --------------------------------------------------------- */
/*                                                           */
/* Pool-based memory management routines                     */
/*                                                           */
/* --------------------------------------------------------- */

#ifdef POOL_DEBUG
/* prime number for top # of pools debugging */
#define POOL_NUM 40009
#endif

/** pheap - singular allocation of memory */
struct pheap
{
    void *block;
    int size, used;
};

/** pool_cleaner - callback type which is associated
   with a pool entry; invoked when the pool entry is 
   free'd */
typedef void (*pool_cleaner)(void *arg);

/** pfree - a linked list node which stores an
   allocation chunk, plus a callback */
struct pfree
{
    pool_cleaner f;
    void *arg;
    struct pheap *heap;
    struct pfree *next;
};

/** pool - base node for a pool. Maintains a linked list
   of pool entries (pfree) */
typedef struct pool_struct
{
    int size;
    struct pfree *cleanup;
    struct pfree *cleanup_tail;
    struct pheap *heap;
#ifdef POOL_DEBUG
    char name[8], zone[32];
    int lsize;
} _pool, *pool;
#define pool_new() _pool_new(ZONE) 
#define pool_heap(i) _pool_new_heap(i,ZONE) 
#else
} _pool, *pool;
#define pool_heap(i) _pool_new_heap(i,NULL,0) 
#define pool_new() _pool_new(NULL,0)
#endif

pool _pool_new(char *zone, int line); /* new pool :) */
pool _pool_new_heap(int size, char *zone, int line); /* creates a new memory pool with an initial heap size */
void *pmalloc(pool p, int size); /* wrapper around malloc, takes from the pool, cleaned up automatically */
void *pmalloc_x(pool p, int size, char c); /* Wrapper around pmalloc which prefils buffer with c */
void *pmalloco(pool p, int size); /* YAPW for zeroing the block */
char *pstrdup(pool p, const char *src); /* wrapper around strdup, gains mem from pool */
void pool_stat(int full); /* print to stderr the changed pools and reset */
char *pstrdupx(pool p, const char *src, int len); /* use given len */
void pool_cleanup(pool p, pool_cleaner f, void *arg); /* calls f(arg) before the pool is freed during cleanup */
void pool_free(pool p); /* calls the cleanup functions, frees all the data on the pool, and deletes the pool itself */
int pool_size(pool p); /* returns total bytes allocated in this pool */




/* --------------------------------------------------------- */
/*                                                           */
/* String management routines                                */
/*                                                           */
/** --------------------------------------------------------- */
char *j_strdup(const char *str); /* provides NULL safe strdup wrapper */
char *j_strcat(char *dest, char *txt); /* strcpy() clone */
int j_strcmp(const char *a, const char *b); /* provides NULL safe strcmp wrapper */
int j_strcasecmp(const char *a, const char *b); /* provides NULL safe strcasecmp wrapper */
int j_strncmp(const char *a, const char *b, int i); /* provides NULL safe strncmp wrapper */
int j_strncasecmp(const char *a, const char *b, int i); /* provides NULL safe strncasecmp wrapper */
int j_strlen(const char *a); /* provides NULL safe strlen wrapper */
int j_atoi(const char *a, int def); /* checks for NULL and uses default instead, convienence */
char *j_attr(const char** atts, char *attr); /* decode attr's (from expat) */
char *j_strnchr(const char *s, int c, int n); /* like strchr, but only searches n chars */

/** old convenience function, now in str.c */
void shahash_r(const char* str, char hashbuf[41]);

/* --------------------------------------------------------- */
/*                                                           */
/* Hashtable functions                                       */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct xhn_struct
{
    struct xhn_struct *next;
    const char *key;
    void *val;
} *xhn, _xhn;

typedef struct xht_struct
{
    pool p;
    int prime;
    int dirty;
    int count;
    struct xhn_struct *zen;
    int iter_bucket;
    xhn iter_node;
} *xht, _xht;

xht xhash_new(int prime);
void xhash_put(xht h, const char *key, void *val);
void xhash_putx(xht h, const char *key, int len, void *val);
void *xhash_get(xht h, const char *key);
void *xhash_getx(xht h, const char *key, int len);
void xhash_zap(xht h, const char *key);
void xhash_zapx(xht h, const char *key, int len);
void xhash_free(xht h);
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);
void xhash_walk(xht h, xhash_walker w, void *arg);
int xhash_dirty(xht h);
int xhash_count(xht h);
pool xhash_pool(xht h);

/* iteration functions */
int xhash_iter_first(xht h);
int xhash_iter_next(xht h);
void xhash_iter_zap(xht h);
int xhash_iter_get(xht h, const char **key, void **val);

/* --------------------------------------------------------- */
/*                                                           */
/* XML escaping utils                                        */
/*                                                           */
/* --------------------------------------------------------- */
char *strescape(pool p, char *buf, int len); /* Escape <>&'" chars */
char *strunescape(pool p, char *buf);


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
    pool p;
    int len;
    struct spool_node *last;
    struct spool_node *first;
} *spool;

spool spool_new(pool p); /* create a string pool */
void spooler(spool s, ...); /* append all the char * args to the pool, terminate args with s again */
char *spool_print(spool s); /* return a big string */
void spool_add(spool s, char *str); /* add a single string to the pool */
void spool_escape(spool s, char *raw, int len); /* add and xml escape a single string to the pool */
char *spools(pool p, ...); /* wrap all the spooler stuff in one function, the happy fun ball! */


/* known namespace uri */
#define uri_STREAMS     "http://etherx.jabber.org/streams"
#define uri_CLIENT      "jabber:client"
#define uri_SERVER      "jabber:server"
#define uri_DIALBACK    "jabber:server:dialback"
#define uri_TLS         "urn:ietf:params:xml:ns:xmpp-tls"
#define uri_SASL        "urn:ietf:params:xml:ns:xmpp-sasl"
#define uri_BIND        "urn:ietf:params:xml:ns:xmpp-bind"
#define uri_XSESSION    "urn:ietf:params:xml:ns:xmpp-session"
#define uri_STREAM_ERR  "urn:ietf:params:xml:ns:xmpp-streams"
#define uri_STANZA_ERR  "urn:ietf:params:xml:ns:xmpp-stanzas"
#define uri_COMPONENT   "http://jabberd.jabberstudio.org/ns/component/1.0"
#define uri_SESSION     "http://jabberd.jabberstudio.org/ns/session/1.0"
#define uri_RESOLVER    "http://jabberd.jabberstudio.org/ns/resolver/1.0"
#define uri_XDATA       "jabber:x:data"
#define uri_XML         "http://www.w3.org/XML/1998/namespace"

#define uri_DIALBACK_L	22	/* strlen(uri_DIALBACK) */

/*
 * JID manipulation. Validity is checked via stringprep, using the "nodeprep",
 * "nameprep" and "resourceprep" profiles (see xmpp-core section 3).
 *
 * The provided functions are mainly for convenience. The application should
 * fill out node, domain and resource directly. When they modify these, they
 * should either call jid_expand(), or set the dirty flag.
 */

/** preparation cache, for speed */
typedef struct prep_cache_st {
    xht             node;
    xht             domain;
    xht             resource;
} *prep_cache_t;

prep_cache_t    prep_cache_new(void);
void            prep_cache_free(prep_cache_t pc);
char            *prep_cache_node_get(prep_cache_t pc, char *from);
void            prep_cache_node_set(prep_cache_t pc, char *from, char *to);
char            *prep_cache_domain_get(prep_cache_t pc, char *from);
void            prep_cache_domain_set(prep_cache_t pc, char *from, char *to);
char            *prep_cache_resource_get(prep_cache_t pc, char *from);
void            prep_cache_resource_set(prep_cache_t pc, char *from, char *to);

/** these sizings come from xmpp-core */
#define MAXLEN_JID_COMP  1023    /* XMPP (RFC3920) 3.1 */
#define MAXLEN_JID       3071    /* nodename (1023) + '@' + domain (1023) + '/' + resource (1023) = 3071 */

typedef struct jid_st {
    /* cache for prep, if any */
    prep_cache_t    pc;

    /* basic components of the jid */
    unsigned char   *node;
    unsigned char   *domain;
    unsigned char   *resource;

    /* Points to jid broken with \0s into componets. node/domain/resource point
     * into this string (or to statically allocated empty string, if they are
     * empty) */
    unsigned char   *jid_data;
    /* Valid only when jid_data != NULL. When = 0, jid_data is statically
     * allocated. Otherwise it tells length of the allocated data. Used to
     * implement jid_dup() */
    size_t          jid_data_len;

    /* the "user" part of the jid (sans resource) */
    unsigned char   *_user;

    /* the complete jid */
    unsigned char   *_full;

    /* application should set to 1 if user/full need regenerating */
    int             dirty;

    /* for lists of jids */
    struct jid_st    *next;
} *jid_t;

typedef enum {
    jid_NODE    = 1,
    jid_DOMAIN  = 2,
    jid_RESOURCE = 3
} jid_part_t;

/** JID static buffer **/
typedef char jid_static_buf[3*1025];

/** make a new jid, and call jid_reset() to populate it */
jid_t               jid_new(prep_cache_t pc, const unsigned char *id, int len);

/** Make jid to use static buffer (jid data won't be allocated dynamically, but
 * given buffer will be always used. */
void                jid_static(jid_t jid, jid_static_buf *buf);

/** clear and populate the jid with the given id. if id == NULL, just clears the jid to 0 */
jid_t               jid_reset(jid_t jid, const unsigned char *id, int len);
jid_t               jid_reset_components(jid_t jid, const unsigned char *node, const unsigned char *domain, const unsigned char *resource);

/** free the jid */
void                jid_free(jid_t jid);

/** do string preparation on a jid */
int                 jid_prep(jid_t jid);

/** fill jid's resource with a random string **/
void                jid_random_part(jid_t jid, jid_part_t part);

/** expands user and full if the dirty flag is set */
void                jid_expand(jid_t jid);

/** return the user or full jid. these call jid_expand to make sure the user and
 * full jid are up to date */
const unsigned char *jid_user(jid_t jid);
const unsigned char *jid_full(jid_t jid);

/** compare two user or full jids. these call jid_expand, then strcmp. returns
 * 0 if they're the same, < 0 if a < b, > 0 if a > b */
int                 jid_compare_user(jid_t a, jid_t b);
int                 jid_compare_full(jid_t a, jid_t b);

/** duplicate a jid */
jid_t               jid_dup(jid_t jid);

/** list helpers */

/** see if a jid is present in a list */
int                 jid_search(jid_t list, jid_t jid);

/** remove a jid from a list, and return the new list */
jid_t               jid_zap(jid_t list, jid_t jid);

/** insert of a copy of jid into list, avoiding dups */
jid_t               jid_append(jid_t list, jid_t jid);


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
    char        *facility;
    int         number;
} log_facility_t;

extern log_t    log_new(log_type_t type, char *ident, char *facility);
extern void     log_write(log_t log, int level, const char *msgfmt, ...);
extern void     log_free(log_t log);


/* Not A DOM */

/* using nad:
 * 
 * nad is very simplistic, and requires all string handling to use a length.
 * Apps using this must be aware of the structure and access it directly for
 * most information. nads can only be built by successively using the _append_
 * functions correctly. After built, they can be modified using other functions,
 * or by direct access. To access cdata on an elem or attr, use nad->cdata +
 * nad->xxx[index].ixxx for the start, and .lxxx for len.
 *
 * Namespace support seems to work, but hasn't been thoroughly tested. in
 * particular, editing the nad after its creation might have quirks. use at
 * your own risk! Note that nad_add_namespace() brings a namespace into scope
 * for the next element added with nad_append_elem(), nad_insert_elem() or
 * nad_wrap_elem() (and by extension, any of its subelements). This is the same
 * way that Expat does things, so nad_add_namespace() can be driven from the
 * Expat's StartNamespaceDeclHandler.
 */

typedef struct nad_st **nad_cache_t;

struct nad_elem_st
{
    int parent;
    int iname, lname;
    int icdata, lcdata; /* cdata within this elem (up to first child) */
    int itail, ltail; /* cdata after this elem */
    int attr;
    int ns;
    int my_ns;
    int depth;
};

struct nad_attr_st
{
    int iname, lname;
    int ival, lval;
    int my_ns;
    int next;
};

struct nad_ns_st
{
    int iuri, luri;
    int iprefix, lprefix;
    int next;
};

typedef struct nad_st
{
    nad_cache_t cache;   /* he who gave us life */
    struct nad_elem_st *elems;
    struct nad_attr_st *attrs;
    struct nad_ns_st *nss;
    char *cdata;
    int *depths; /* for tracking the last elem at a depth */
    int elen, alen, nlen, clen, dlen;
    int ecur, acur, ncur, ccur;
    int scope; /* currently scoped namespaces, get attached to the next element */
    struct nad_st *next; /* for keeping a list of nads */
} *nad_t;

/** create a new cache for nads */
nad_cache_t nad_cache_new(void);

/** free the cache */
void nad_cache_free(nad_cache_t cache);

/** create a new nad */
nad_t nad_new(nad_cache_t cache);

/** copy a nad */
nad_t nad_copy(nad_t nad);

/** free that nad */
void nad_free(nad_t nad);

/** find the next element with this name/depth */
/** 0 for siblings, 1 for children and so on */
int nad_find_elem(nad_t nad, int elem, int ns, const char *name, int depth);

/** find the first matching attribute (and optionally value) */
int nad_find_attr(nad_t nad, int elem, int ns, const char *name, const char *val);

/** find the first matching namespace (and optionally prefix) */
int nad_find_namespace(nad_t nad, int elem, const char *uri, const char *prefix);

/** find a namespace in scope (and optionally prefix) */
int nad_find_scoped_namespace(nad_t nad, const char *uri, const char *prefix);

/** reset or store the given attribute */
void nad_set_attr(nad_t nad, int elem, int ns, const char *name, const char *val, int vallen);

/** insert and return a new element as a child of this one */
int nad_insert_elem(nad_t nad, int elem, int ns, const char *name, const char *cdata);

/** wrap an element with another element */
void nad_wrap_elem(nad_t nad, int elem, int ns, const char *name);

/** append and return a new element */
int nad_append_elem(nad_t nad, int ns, const char *name, int depth);

/** append attribs to the last element */
int nad_append_attr(nad_t nad, int ns, const char *name, const char *val);

/** append more cdata to the last element */
void nad_append_cdata(nad_t nad, const char *cdata, int len, int depth);

/** add a namespace to the next element (ie, called when the namespace comes into scope) */
int nad_add_namespace(nad_t nad, const char *uri, const char *prefix);

/** declare a namespace on an already existing element */
int nad_append_namespace(nad_t nad, int elem, const char *uri, const char *prefix);

/** create a string representation of the given element (and children), point references to it */
void nad_print(nad_t nad, int elem, char **xml, int *len);

/** serialize and deserialize a nad */
void nad_serialize(nad_t nad, char **buf, int *len);
nad_t nad_deserialize(nad_cache_t cache, const char *buf);

/** create a nad from raw xml */
nad_t nad_parse(nad_cache_t cache, const char *buf, int len);

/* these are some helpful macros */
#define NAD_ENAME(N,E) (N->cdata + N->elems[E].iname)
#define NAD_ENAME_L(N,E) (N->elems[E].lname)
#define NAD_CDATA(N,E) (N->cdata + N->elems[E].icdata)
#define NAD_CDATA_L(N,E) (N->elems[E].lcdata)
#define NAD_ANAME(N,A) (N->cdata + N->attrs[A].iname)
#define NAD_ANAME_L(N,A) (N->attrs[A].lname)
#define NAD_AVAL(N,A) (N->cdata + N->attrs[A].ival)
#define NAD_AVAL_L(N,A) (N->attrs[A].lval)
#define NAD_NURI(N,NS) (N->cdata + N->nss[NS].iuri)
#define NAD_NURI_L(N,NS) (N->nss[NS].luri)
#define NAD_NPREFIX(N,NS) (N->cdata + N->nss[NS].iprefix)
#define NAD_NPREFIX_L(N,NS) (N->nss[NS].lprefix)

#define NAD_ENS(N,E) (N->elems[E].my_ns)
#define NAD_ANS(N,A) (N->attrs[A].my_ns)


/* config files */
typedef struct config_elem_st   *config_elem_t;
typedef struct config_st        *config_t;

/** holder for the config hash and nad */
struct config_st
{
    xht                 hash;
    nad_cache_t         nads;
    nad_t               nad;
};

/** a single element */
struct config_elem_st
{
    char                **values;
    int                 nvalues;
    char                ***attrs;
};

extern config_t         config_new(void);
extern int              config_load(config_t c, char *file);
extern config_elem_t    config_get(config_t c, char *key);
extern char             *config_get_one(config_t c, char *key, int num);
extern int              config_count(config_t c, char *key);
extern char             *config_get_attr(config_t c, char *key, int num, char *attr);
extern void             config_free(config_t);


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

access_t    access_new(int order);
void        access_free(access_t access);
int         access_allow(access_t access, char *ip, char *mask);
int         access_deny(access_t access, char *ip, char *mask);
int         access_check(access_t access, char *ip);


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

rate_t      rate_new(int total, int seconds, int wait);
void        rate_free(rate_t rt);
void        rate_reset(rate_t rt);
void        rate_add(rate_t rt, int count);
int         rate_left(rate_t rt);
int         rate_check(rate_t rt);          /* 1 == good, 0 == bad */

/*
 * helpers for ip addresses
 */

#include "inaddr.h"		/* used in mio as well */

/*
 * serialisation helper functions
 */

int         ser_string_get(char **dest, int *source, const char *buf, int len);
int         ser_int_get(int *dest, int *source, const char *buf, int len);
void        ser_string_set(char *source, int *dest, char **buf, int *len);
void        ser_int_set(int source, int *dest, char **buf, int *len);

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
    pool            p;
    _jqueue_node_t  cache;

    _jqueue_node_t  front;
    _jqueue_node_t  back;

    int             size;
} *jqueue_t;

jqueue_t    jqueue_new(void);
void        jqueue_free(jqueue_t q);
void        jqueue_push(jqueue_t q, void *data, int pri);
void        *jqueue_pull(jqueue_t q);
int         jqueue_size(jqueue_t q);


/* ISO 8601 / JEP-0082 date/time manipulation */
typedef enum {
    dt_DATE     = 1,
    dt_TIME     = 2,
    dt_DATETIME = 3,
    dt_LEGACY   = 4
} datetime_t;

time_t  datetime_in(char *date);
void    datetime_out(time_t t, datetime_t type, char *date, int datelen);


/* base64 functions */
extern int ap_base64decode_len(const char *bufcoded, int buflen);
extern int ap_base64decode(char *bufplain, const char *bufcoded, int buflen);
extern int ap_base64decode_binary(unsigned char *bufplain, const char *bufcoded, int buflen);
extern int ap_base64encode_len(int len);
extern int ap_base64encode(char *encoded, const char *string, int len);
extern int ap_base64encode_binary(char *encoded, const unsigned char *string, int len);

/* convenience, result string must be free()'d by caller */
extern char *b64_encode(char *buf, int len);
extern char *b64_decode(char *buf);


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
#define stanza_err_LAST                     (122)

extern nad_t stanza_error(nad_t nad, int elem, int err);
extern nad_t stanza_tofrom(nad_t nad, int elem);


/* hex conversion utils */
void hex_from_raw(char *in, int inlen, char *out);
int hex_to_raw(char *in, int inlen, char *out);


/* xdata in a seperate file */
#include "xdata.h"


/* debug logging */
int get_debug_flag(void);
void set_debug_flag(int v);
void debug_log(char *file, int line, const char *msgfmt, ...);
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
jsighandler_t* jabber_signal(int signo,  jsighandler_t *func);

#ifdef __cplusplus
}
#endif

#endif    /* INCL_UTIL_H */


