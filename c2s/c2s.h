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
#include "sx/ssl.h"
#ifdef MD5_CTX
#  define MD5_H
#endif
#include "sx/sasl.h"
#include "util/util.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

/* forward decl */
typedef struct host_st      *host_t;
typedef struct c2s_st       *c2s_t;
typedef struct sess_st      *sess_t;
typedef struct authreg_st   *authreg_t;

struct sess_st {
    c2s_t               c2s;

    mio_fd_t            fd;

    char                skey[10];

    char                *ip;
    int                 port;

    sx_t                s;

    rate_t              rate;
    int                 rate_log;

    time_t              last_activity;

    int                 bound;
    int                 active;

    nad_t               result;

    int                 sasl_authd;     /* 1 = they did a sasl auth */

    /** full jid of the session */
    jid_t               jid;

    /** session id for us and them */
    char                c2s_id[24], sm_id[41];

    /** host this session belongs to */
    host_t              host;

    /** this holds the id of the current pending SM request */
    char                sm_request[41];
};

/* allowed mechanisms */
#define AR_MECH_TRAD_PLAIN      (1<<0)
#define AR_MECH_TRAD_DIGEST     (1<<1)
#define AR_MECH_TRAD_ZEROK      (1<<2)

struct host_st {
    /** our realm (SASL) */
    char                *realm;

    /** starttls pemfile */
    char                *host_pemfile;

    /** verify-mode  */
    int                 host_verify_mode;

    /** require starttls */
    int                 host_require_starttls;

    /** registration */
    int                 ar_register_enable;
    char                *ar_register_instructions;
    int                 ar_register_password;

};

struct c2s_st {
    /** our id (hostname) with the router */
    char                *id;

    /** how to connect to the router */
    char                *router_ip;
    int                 router_port;
    char                *router_user;
    char                *router_pass;
    char                *router_pemfile;

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
    char                *log_facility;
    char                *log_ident;

    /** connect retry */
    int                 retry_init;
    int                 retry_lost;
    int                 retry_sleep;
    int                 retry_left;

    /** ip to listen on */
    char                *local_ip;

    /** unencrypted port */
    int                 local_port;

    /** encrypted port */
    int                 local_ssl_port;

    /** encrypted port pemfile */
    char                *local_pemfile;

    /** certificate chain */
    char                *local_cachain;

    /** verify-mode  */
    int                 local_verify_mode;

    /** http forwarding URL */
    char                *http_forward;

    /** max file descriptors */
    int                 io_max_fds;

    /** time checks */
    int                 io_check_interval;
    int                 io_check_idle;
    int                 io_check_keepalive;

    time_t              next_check;

    /** auth/reg module */
    char                *ar_module_name;
    authreg_t           ar;

    /** allowed mechanisms */
    int                 ar_mechanisms;

    /** connection rates */
    int                 conn_rate_total;
    int                 conn_rate_seconds;
    int                 conn_rate_wait;

    xht                 conn_rates;

    /** byte rates (karma) */
    int                 byte_rate_total;
    int                 byte_rate_seconds;
    int                 byte_rate_wait;

    /** stringprep cache */
    prep_cache_t        pc;

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

    /** availability of sms that we are servicing */
    xht                 sm_avail;
};

extern sig_atomic_t c2s_lost_router;

int             c2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
int             c2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);

void            sm_start(sess_t sess);
void            sm_end(sess_t sess);
void            sm_create(sess_t sess);
void            sm_delete(sess_t sess);
void            sm_packet(sess_t sess, nad_t nad);

int             bind_init(sx_env_t env, sx_plugin_t p, va_list args);

struct authreg_st
{
    c2s_t       c2s;

    /** module private data */
    void        *private;

    /** returns 1 if the user exists, 0 if not */
    int         (*user_exists)(authreg_t ar, char *username, char *realm);

    /** return this users cleartext password in the array (digest auth, password auth) */
    int         (*get_password)(authreg_t ar, char *username, char *realm, char password[257]);

    /** check the given password against the stored password, 0 if equal, !0 if not equal (password auth) */
    int         (*check_password)(authreg_t ar, char *username, char *realm, char password[257]);

    /** store this password (register) */
    int         (*set_password)(authreg_t ar, char *username, char *realm, char password[257]);

    /** get/set zerok data for this user (zerok auth, zerok register) */
    int         (*get_zerok)(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int *sequence);
    int         (*set_zerok)(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int sequence);

    /** make or break the user (register / register remove) */
    int         (*create_user)(authreg_t ar, char *username, char *realm);
    int         (*delete_user)(authreg_t ar, char *username, char *realm);

    void        (*free)(authreg_t ar);
};

/** get a handle for a single module */
authreg_t   authreg_init(c2s_t c2s, char *name);

/** shut down */
void        authreg_free(authreg_t ar);

/** type for the module init function */
typedef int (*ar_module_init_fn)(authreg_t);

/** the main authreg processor */
int         authreg_process(c2s_t c2s, sess_t sess, nad_t nad);

/*
int     authreg_user_exists(authreg_t ar, char *username, char *realm);
int     authreg_get_password(authreg_t ar, char *username, char *realm, char password[257]);
int     authreg_check_password(authreg_t ar, char *username, char *realm, char password[257]);
int     authreg_set_password(authreg_t ar, char *username, char *realm, char password[257]);
int     authreg_get_zerok(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int *sequence);
int     authreg_set_zerok(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int sequence);
int     authreg_create_user(authreg_t ar, char *username, char *realm);
int     authreg_delete_user(authreg_t ar, char *username, char *realm);
void    authreg_free(authreg_t ar);
*/

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  char **char_val;
  sess_t *sess_val;
};
