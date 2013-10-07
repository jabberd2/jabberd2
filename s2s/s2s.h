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
#   include <config.h>
#endif

#include "mio/mio.h"
#include "sx/sx.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#include <udns.h>

/* forward decl */
typedef struct host_st      *host_t;
typedef struct s2s_st       *s2s_t;
typedef struct pkt_st       *pkt_t;
typedef struct conn_st      *conn_t;
typedef struct dnsquery_st  *dnsquery_t;
typedef struct dnscache_st  *dnscache_t;
typedef struct dnsres_st    *dnsres_t;

struct host_st {
    /** our realm */
    const char          *realm;

    /** starttls pemfile */
    const char          *host_pemfile;

    /** certificate chain */
    const char          *host_cachain;

    /** verify-mode  */
    int                 host_verify_mode;

    /** private key password */
    char                *host_private_key_password;    
};

struct s2s_st {
    /** our id (hostname) with the router */
    const char          *id;

    /** how to connect to the router */
    const char          *router_ip;
    int                 router_port;
    const char          *router_user;
    const char          *router_pass;
    const char          *router_pemfile;
    const char          *router_cachain;
    const char          *router_private_key_password;
    int                 router_default;

    /** mio context */
    mio_t               mio;

    /** sx environment */
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;
    sx_plugin_t         sx_db;

    /** router's conn */
    sx_t                router;
    mio_fd_t            fd;

    /** listening sockets */
    mio_fd_t            server_fd;

    /** config */
    config_t            config;

    /** logging */
    log_t               log;

    /** log data */
    log_type_t          log_type;
    const char          *log_facility;
    const char          *log_ident;

    /** packet counter */
    long long int       packet_count;
    const char          *packet_stats;

    /** connect retry */
    int                 retry_init;
    int                 retry_lost;
    int                 retry_sleep;
    int                 retry_left;

    /** ip/port to listen on */
    const char          *local_ip;
    int                 local_port;

    /** ip(s) to originate connections from */
    const char          **origin_ips;
    int                 origin_nips;

    /** dialback secret */
    const char          *local_secret;

    /** pemfile for peer connections */
    const char          *local_pemfile;

    /** private key password for local pemfile, if encrypted */
    const char          *local_private_key_password;

    /** certificate chain */
    const char          *local_cachain;

    /** verify-mode  */
    int                 local_verify_mode;

    /** hosts mapping */
    xht                 hosts;

    /** max file descriptors */
    int                 io_max_fds;

    /** maximum stanza size */
    int                 stanza_size_limit;

    /** enable Stream Compression */
    int                 compression;

    /** srvs to lookup */
    const char          **lookup_srv;
    int                 lookup_nsrv;
    
    /** if we resolve AAAA records */
    int                 resolve_aaaa;

    /** dns ttl limits */
    int                 dns_min_ttl;
    int                 dns_max_ttl;

    /** /etc/hosts ttl limits */
    int                 etc_hosts_ttl;

    /** time checks */
    int                 check_interval;
    int                 check_queue;
    int                 check_invalid;
    int                 check_keepalive;
    int                 check_idle;
    int                 check_dnscache;
    int                 retry_limit;

    time_t              last_queue_check;
    time_t              last_invalid_check;

    time_t              next_check;
    time_t              next_expiry;

    /** Apple security options */
	int					require_tls;
	int					enable_whitelist;
	/*const*/ char      **whitelist_domains; // TODO clarify if need to be const
	int					n_whitelist_domains;

    /** list of sx_t on the way out */
    jqueue_t            dead;

    /** list of conn_t on the way out */
    jqueue_t            dead_conn;

    /** this is true if we've connected to the router at least once */
    int                 started;

    /** true if we're bound in the router */
    int                 online;

    /** queues of packets waiting to go out (key is route) */
    xht                 outq;

    /** reuse outgoing conns keyed by ip/port */
    int                 out_reuse;

    /** outgoing conns (key is ip/port) */
    xht                 out_host;

    /** outgoing conns (key is dest) */
    xht                 out_dest;

    /** incoming conns (key is stream id) */
    xht                 in;

    /** incoming conns prior to stream initiation (key is ip/port) */
    xht                 in_accept;

    /** udns fds */
    int                 udns_fd;
    mio_fd_t            udns_mio_fd;

    /** dns resolution cache */
    xht                 dnscache;
    int                 dns_cache_enabled;

    /** dns resolution bad host cache */
    xht                 dns_bad;
    int                 dns_bad_timeout;
};

struct pkt_st {
    nad_t               nad;

    jid_t               from;
    jid_t               to;

    int                 db;

    char                ip[INET6_ADDRSTRLEN+1];
    int                 port;
};

typedef enum {
    conn_NONE,
    conn_INPROGRESS,
    conn_VALID,
    conn_INVALID
} conn_state_t;

struct conn_st {
    s2s_t               s2s;

    const char          *key;
    const char          *dkey;

    sx_t                s;
    mio_fd_t            fd;

    char                ip[INET6_ADDRSTRLEN+1];
    int                 port;

    /** states of outgoing dialbacks (key is local/remote) */
    xht                 states;

    /** time of the last state change (key is local/remote) */
    xht                 states_time;

    /** routes that this conn handles (key is local/remote) */
    xht                 routes;

    time_t              init_time;

    int                 online;
    
    /** number and last timestamp of outstanding db:verify requests */
    int                 verify;
    time_t              last_verify;

    /** timestamps for idle timeouts */
    time_t              last_activity;
    time_t              last_packet;

    unsigned int        packet_count;
};

#define DNS_MAX_RESULTS 50

/** dns query data */
struct dnsquery_st {
    s2s_t               s2s;

    /** domain name */
    const char          *name;

    /** srv lookup index */
    int                 srv_i;

    /** srv lookup results (key host/port) */
    xht                 hosts;

    /** current host lookup name */
    const char          *cur_host;

    /** current host lookup port */
    int                 cur_port;

    /** current host max expiry */
    time_t              cur_expiry;

    /** current host priority */
    int                 cur_prio;

    /** current host weight */
    int                 cur_weight;

    /** host lookup results (key ip/port) */
    xht                 results;

    /** time that all entries expire */
    time_t              expiry;

    /** set when we're waiting for a resolve response */
    struct dns_query   *query;
};

/** one item in the dns resolution cache */
struct dnscache_st {
    /** the name proper */
    char                name[1024];

    /** results (key ip/port) */
    xht                 results;

    /** time that this entry expires */
    time_t              expiry;

    time_t              init_time;

    /** set when we're waiting for a resolve response */
    int                 pending;
    dnsquery_t          query;
};

/** dns resolution results */
struct dnsres_st {
    /** ip/port */
    const char          *key;

    /** host priority */
    int                 prio;

    /** host weight */
    int                 weight;

    /** time that this entry expires */
    time_t              expiry;
};

extern sig_atomic_t s2s_lost_router;

int             s2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
int             s2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);
int             s2s_domain_in_whitelist(s2s_t s2s, const char *in_domain);

char            *s2s_route_key(pool_t p, const char *local, const char *remote);
int             s2s_route_key_match(char *local, const char *remote, const char *rkey, int rkeylen);
char            *s2s_db_key(pool_t p, const char *secret, const char *remote, const char *id);
char            *dns_make_ipport(const char* host, int port);

int             out_packet(s2s_t s2s, pkt_t pkt);
int             out_route(s2s_t s2s, const char *route, int routelen, conn_t *out, int allow_bad);
int             dns_select(s2s_t s2s, char* ip, int* port, time_t now, dnscache_t dns, int allow_bad);
void            dns_resolve_domain(s2s_t s2s, dnscache_t dns);
void            out_resolve(s2s_t s2s, const char *domain, xht results, time_t expiry);
void            out_dialback(s2s_t s2s, pkt_t pkt);
int             out_bounce_domain_queues(s2s_t s2s, const char *domain, int err);
int             out_bounce_route_queue(s2s_t s2s, const char *rkey, int rkeylen, int err);
int             out_bounce_conn_queues(conn_t out, int err);
void            out_flush_domain_queues(s2s_t s2s, const char *domain);
void            out_flush_route_queue(s2s_t s2s, const char *rkey, int rkeylen);

int             in_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);

/* sx flag for outgoing dialback streams */
#define S2S_DB_HEADER   (1<<10)

/* max length of FQDN for whitelist matching */
#define MAX_DOMAIN_LEN	1023

int             s2s_db_init(sx_env_t env, sx_plugin_t p, va_list args);

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  char **char_val;
  conn_t *conn_val;
  conn_state_t *state_val;
  jqueue_t *jq_val;
  dnscache_t *dns_val;
  dnsres_t *dnsres_val;
};

void out_pkt_free(pkt_t pkt);
