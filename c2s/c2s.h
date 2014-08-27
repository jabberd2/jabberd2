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

#include <expat.h>

#include "mio/mio.h"
#include "sx/sx.h"
#include "util/util.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef _WIN32
  #ifdef _USRDLL
    #define DLLEXPORT  __declspec(dllexport)
    #define C2S_API    __declspec(dllimport)
  #else
    #define DLLEXPORT  __declspec(dllimport)
    #define C2S_API    __declspec(dllexport)
  #endif
#else
  #define DLLEXPORT
  #define C2S_API
#endif

/* forward declarations */
typedef struct host_st      *host_t;
typedef struct c2s_st       *c2s_t;
typedef struct bres_st      *bres_t;
typedef struct sess_st      *sess_t;
typedef struct authreg_st   *authreg_t;

/** list of resources bound to session */
struct bres_st {
    /** full bound jid */
    jid_t               jid;
    /** session id for this jid for us and them */
    char                c2s_id[44], sm_id[41];
    /** this holds the id of the current pending SM request */
    char                sm_request[41];

    bres_t              next;
};

/**
 * There is one instance of this struct per user who is logged in to
 * this c2s instance.
 */
struct sess_st {
    c2s_t               c2s;

    mio_fd_t            fd;

    char                skey[44];

    const char          *smcomp; /* sm component servicing this session */

    const char          *ip;
    int                 port;

    sx_t                s;

    /** host this session belongs to */
    host_t              host;

    rate_t              rate;
    int                 rate_log;

    rate_t              stanza_rate;
    int                 stanza_rate_log;

    time_t              last_activity;
    unsigned int        packet_count;

    /* count of bound resources */
    int                 bound;
    /* list of bound jids */
    bres_t              resources;

    int                 active;

    /* session related packet waiting for sm response */
    nad_t               result;

    int                 sasl_authd;     /* 1 = they did a sasl auth */

    /** Apple: session challenge for challenge-response authentication */
    char                auth_challenge[65];

    /* Per user session authreg private data */
    void                *authreg_private;
};

/* allowed mechanisms */
#define AR_MECH_TRAD_PLAIN      (1<<0)
#define AR_MECH_TRAD_DIGEST     (1<<1)
#define AR_MECH_TRAD_CRAMMD5    (1<<2)

struct host_st {
    /** our realm (SASL) */
    const char          *realm;

    /** starttls pemfile */
    const char          *host_pemfile;

    /** certificate chain */
    const char          *host_cachain;

    /** private key password */
    char                *host_private_key_password;

    /** verify-mode  */
    int                 host_verify_mode;

    /** require starttls */
    int                 host_require_starttls;

    /** registration */
    int                 ar_register_enable;
    const char          *ar_register_instructions;
    const char          *ar_register_oob;
    int                 ar_register_password;

};

struct c2s_st {
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

    /** mio context */
    mio_t               mio;

    /** sessions */
    xht                 sessions;

    /** sx environment */
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;

    /** router's conn */
    sx_t                router;
    mio_fd_t            fd;

    /** listening sockets */
    mio_fd_t            server_fd;
#ifdef HAVE_SSL
    mio_fd_t            server_ssl_fd;
#endif

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

    /** ip to listen on */
    const char          *local_ip;

    /** unencrypted port */
    int                 local_port;

    /** encrypted port */
    int                 local_ssl_port;

    /** encrypted port pemfile */
    const char          *local_pemfile;

    /** encrypted port cachain file */
    const char          *local_cachain;

    /** private key password */
    const char          *local_private_key_password;

    /** verify-mode  */
    int                 local_verify_mode;

    /** http forwarding URL */
    const char          *http_forward;

    /** PBX integration named pipe */
    const char          *pbx_pipe;
    int                 pbx_pipe_fd;
    mio_fd_t            pbx_pipe_mio_fd;

    /** stream redirection (see-other-host) on session connect */
    xht                 stream_redirects;

    /** max file descriptors */
    int                 io_max_fds;

    /** enable Stream Compression */
    int                 compression;

    /** time checks */
    int                 io_check_interval;
    int                 io_check_idle;
    int                 io_check_keepalive;

    time_t              next_check;

    /** auth/reg module */
    const char          *ar_module_name;
    authreg_t           ar;

    /** allowed mechanisms */
    int                 ar_mechanisms;
    int                 ar_ssl_mechanisms;
    
    /** connection rates */
    int                 conn_rate_total;
    int                 conn_rate_seconds;
    int                 conn_rate_wait;

    xht                 conn_rates;

    /** byte rates (karma) */
    int                 byte_rate_total;
    int                 byte_rate_seconds;
    int                 byte_rate_wait;

    /** stanza rates */
    int                 stanza_rate_total;
    int                 stanza_rate_seconds;
    int                 stanza_rate_wait;

    /** maximum stanza size */
    int                 stanza_size_limit;

    /** access controls */
    access_t            access;

    /** list of sx_t on the way out */
    jqueue_t            dead;

    /** list of sess on the way out */
    jqueue_t            dead_sess;

    /** this is true if we've connected to the router at least once */
    int                 started;

    /** true if we're bound in the router */
    int                 online;

    /** hosts mapping */
    xht                 hosts;
    host_t              vhost;

    /** availability of sms that we are servicing */
    xht                 sm_avail;
};

extern sig_atomic_t c2s_lost_router;

C2S_API int         c2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
C2S_API int         c2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);

C2S_API void        sm_start(sess_t sess, bres_t res);
C2S_API void        sm_end(sess_t sess, bres_t res);
C2S_API void        sm_create(sess_t sess, bres_t res);
C2S_API void        sm_delete(sess_t sess, bres_t res);
C2S_API void        sm_packet(sess_t sess, bres_t res, nad_t nad);

C2S_API int         bind_init(sx_env_t env, sx_plugin_t p, va_list args);

C2S_API void        c2s_pbx_init(c2s_t c2s);

/* My IP Address plugin */
JABBERD2_API int    address_init(sx_env_t env, sx_plugin_t p, va_list args);

struct authreg_st
{
    c2s_t       c2s;

    /** module private data */
    void        *private;

    /** returns 1 if the user exists, 0 if not */
    int         (*user_exists)(authreg_t ar, sess_t sess, const char *username,const char *realm);

    /** return this users cleartext password in the array (digest auth, password auth) */
    int         (*get_password)(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]);

    /** check the given password against the stored password, 0 if equal, !0 if not equal (password auth) */
    int         (*check_password)(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]);

    /** store this password (register) */
    int         (*set_password)(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]);

    /** make or break the user (register / register remove) */
    int         (*create_user)(authreg_t ar, sess_t sess, const char *username, const char *realm);
    int         (*delete_user)(authreg_t ar, sess_t sess, const char *username, const char *realm);

    /** called prior to session being closed, to cleanup session specific private data */
    void        (*sess_end)(authreg_t ar, sess_t sess);

    /** called prior to authreg shutdown */
    void        (*free)(authreg_t ar);

    /* Additions at the end - to preserve offsets for existing modules */

    /** returns 1 if the user is permitted to authorize as the requested_user, 0 if not. requested_user is a JID */
    int         (*user_authz_allowed)(authreg_t ar, sess_t sess, const char *username, const char *realm, const char *requested_user);

    /** Apple extensions for challenge/response authentication methods */
    int         (*create_challenge)(authreg_t ar, sess_t sess, const char *username, const char *realm, const char *challenge, int maxlen);
    int         (*check_response)(authreg_t ar, sess_t sess, const char *username, const char *realm, const char *challenge, const char *response);
};

/** get a handle for a single module */
C2S_API authreg_t   authreg_init(c2s_t c2s, const char *name);

/** shut down */
C2S_API void        authreg_free(authreg_t ar);

/** type for the module init function */
typedef int (*ar_module_init_fn)(authreg_t);

/** the main authreg processor */
C2S_API int         authreg_process(c2s_t c2s, sess_t sess, nad_t nad);

/*
int     authreg_user_exists(authreg_t ar, const char *username, const char *realm);
int     authreg_get_password(authreg_t ar, const char *username, const char *realm, char password[257]);
int     authreg_check_password(authreg_t ar, const char *username, const char *realm, char password[257]);
int     authreg_set_password(authreg_t ar, const char *username, const char *realm, char password[257]);
int     authreg_create_user(authreg_t ar, const char *username, const char *realm);
int     authreg_delete_user(authreg_t ar, const char *username, const char *realm);
void    authreg_free(authreg_t ar);
*/

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  const char **char_val;
  sess_t *sess_val;
};

// Data for stream redirect errors
typedef struct stream_redirect_st
{
    const char *to_address;
    const char *to_port;
} *stream_redirect_t;
