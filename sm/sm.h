/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or drvify
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

/** @file sm/sm.h
  * @brief data structures and prototypes for the session manager
  * @author Jeremie Miller
  * @author Robert Norris
  * $Date: 2005/09/09 05:34:13 $
  * $Revision: 1.62 $
  */

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif

#include "sx/sx.h"
#include "mio/mio.h"
#include "util/util.h"

#ifdef HAVE_SIGNAL_H
  #include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
  #include <sys/stat.h>
#endif

#ifdef _WIN32
  #ifdef _USRDLL
    #define DLLEXPORT  __declspec(dllexport)
    #define SM_API     __declspec(dllimport)
  #else
    #define DLLEXPORT  __declspec(dllimport)
    #define SM_API     __declspec(dllexport)
  #endif
#else
  #define DLLEXPORT
  #define SM_API
#endif

/* forward declarations */
typedef struct sm_st        *sm_t;
typedef struct user_st      *user_t;
typedef struct sess_st      *sess_t;
typedef struct aci_st       *aci_t;
typedef struct storage_st   *storage_t;
typedef struct mm_st        *mm_t;

/* namespace uri strings */
#include "util/uri.h"

/* indexed known namespace values */
#define ns_AUTH         (1)
#define ns_REGISTER     (2)
#define ns_ROSTER       (3)
#define ns_AGENTS       (4)
#define ns_DELAY        (5)
#define ns_BROWSE       (6)
#define ns_EVENT        (7)
#define ns_GATEWAY      (8)
#define ns_EXPIRE       (9)
#define ns_SEARCH       (10)
#define ns_DISCO        (11)
#define ns_DISCO_ITEMS  (12)
#define ns_DISCO_INFO   (13)

#define ns_AMP                          (14)
#define ns_AMP_ERRORS                   (15)
#define ns_AMP_ACTION_DROP              (16)
#define ns_AMP_ACTION_ERROR             (17)
#define ns_AMP_ACTION_NOTIFY            (18)
#define ns_AMP_CONDITION_DELIVER        (19)
#define ns_AMP_CONDITION_EXPIREAT       (20)
#define ns_AMP_CONDITION_MATCHRESOURCE  (21)

/** packet types */
typedef enum { 
    pkt_NONE = 0x00,            /**< no packet */
    pkt_MESSAGE = 0x10,         /**< message */
    pkt_MESSAGE_CHAT = 0x11,    /**< message (chat) */
    pkt_MESSAGE_HEADLINE = 0x12,/**< message (headline) */
    pkt_MESSAGE_GROUPCHAT = 0x14,/**< message (groupchat) */
    pkt_PRESENCE = 0x20,        /**< presence */
    pkt_PRESENCE_UN = 0x21,     /**< presence (unavailable) */
    pkt_PRESENCE_PROBE = 0x24,  /**< presence (probe) */
    pkt_S10N = 0x40,            /**< subscribe request */
    pkt_S10N_ED = 0x41,         /**< subscribed response */
    pkt_S10N_UN = 0x42,         /**< unsubscribe request */
    pkt_S10N_UNED = 0x44,       /**< unsubscribed response */
    pkt_IQ = 0x80,              /**< info/query (get) */
    pkt_IQ_SET = 0x81,          /**< info/query (set) */
    pkt_IQ_RESULT = 0x82,       /**< info/query (result) */
    pkt_SESS = 0x100,           /**< session start request */
    pkt_SESS_END = 0x101,       /**< session end request */
    pkt_SESS_CREATE = 0x102,    /**< session create request */
    pkt_SESS_DELETE = 0x104,    /**< session delete request */
    pkt_SESS_FAILED = 0x08,     /**< session request failed (mask) */
    pkt_SESS_MASK = 0x10f,      /**< session request (mask) */
    pkt_ERROR = 0x200           /**< packet error */
} pkt_type_t;

/** route types */
typedef enum {
    route_NONE = 0x00,          /**< no route */
    route_UNICAST = 0x10,       /**< unicast */
    route_BROADCAST = 0x11,     /**< broadcast */
    route_ADV = 0x20,           /**< advertisement (available) */
    route_ADV_UN = 0x21,        /**< advertisement (unavailable) */
    route_ERROR = 0x40          /**< route error */
} route_type_t;

/** packet summary data wrapper */
typedef struct pkt_st {
    sm_t                sm;         /**< sm context */

    sess_t              source;     /**< session this packet came from */

    jid_t               rto, rfrom; /**< addressing of enclosing route */

    route_type_t        rtype;      /**< type of enclosing route */

    pkt_type_t          type;       /**< packet type */

    jid_t               to, from;   /**< packet addressing (not used for routing) */

    int                 ns;         /**< iq sub-namespace */

    int                 pri;        /**< presence priority */

    nad_t               nad;        /**< nad of the entire packet */
} *pkt_t;

/** roster items */
typedef struct item_st {
    jid_t               jid;        /**< id of this item */

    char                *name;      /**< display name */

    char                **groups;   /**< groups this item is in */

    int                 ngroups;    /**< number of groups in groups array */

    int                 to, from;   /**< subscription to this item (they get presence FROM us, they send presence TO us) */

    int                 ask;        /**< pending subscription (0 == none, 1 == subscribe, 2 == unsubscribe) */

    int                 ver;        /**< roster item version number */
} *item_t;

/** session manager global context */
struct sm_st {
    char                *id;                /**< component id */

    char                *router_ip;         /**< ip to connect to the router at */
    int                 router_port;        /**< port to connect to the router at */
    char                *router_user;       /**< username to authenticate to the router as */
    char                *router_pass;       /**< password to authenticate to the router with */
    char                *router_pemfile;    /**< name of file containing a SSL certificate &
                                                 key for channel to the router */

    mio_t               mio;                /**< mio context */

    sx_env_t            sx_env;             /**< SX environment */
    sx_plugin_t         sx_sasl;            /**< SX SASL plugin */ 
    sx_plugin_t         sx_ssl;             /**< SX SSL plugin */

    sx_t                router;             /**< SX of router connection */
    mio_fd_t            fd;                 /**< file descriptor of router connection */

    xht                 users;              /**< pointers to currently loaded users (key is user@@domain) */

    xht                 sessions;           /**< pointers to all connected sessions (key is random sm id) */

    xht                 xmlns;              /**< index of namespaces (for iq sub-namespace in pkt_t) */
    xht                 xmlns_refcount;     /**< ref-counting for modules namespaces */

    xht                 features;           /**< feature index (key is feature string */

    config_t            config;             /**< config context */

    log_t               log;                /**< log context */

    log_type_t          log_type;           /**< log type */
    char                *log_facility;      /**< syslog facility (local0 - local7) */
    char                *log_ident;         /**< log identifier */

    int                 retry_init;         /**< number of times to try connecting to the router at startup */
    int                 retry_lost;         /**< number of times to try reconnecting to the router if the connection drops */
    int                 retry_sleep;        /**< sleep interval between retries */
    int                 retry_left;         /**< number of tries left before failure */

    storage_t           st;                 /**< storage subsystem */

    mm_t                mm;                 /**< module subsystem */

    xht                 acls;               /**< access control lists (key is list name, value is jid_t list) */

    char                signature[2048];    /**< server signature */
    int                 siglen;             /**< length of signature */

    int                 started;            /**< true if we've connected to the router at least once */

    int                 online;             /**< true if we're currently bound in the router */

    xht                 hosts;              /**< vHosts map */

};

/** data for a single user */
struct user_st {
    pool_t              p;                  /**< memory pool this user is allocated off */

    sm_t                sm;                 /**< sm context */

    jid_t               jid;                /**< user jid (user@@host) */

    xht                 roster;             /**< roster for this user (key is full jid of item, value is item_t) */

    sess_t              sessions;           /**< list of action sessions */
    sess_t              top;                /**< top priority session */

    time_t              active;             /**< time that user first logged in (ever) */

    void                **module_data;      /**< per-user module data */
};

/** data for a single session */
struct sess_st {
    pool_t              p;                  /**< memory pool this session is allocated off */

    user_t              user;               /**< user this session belongs to */

    jid_t               jid;                /**< session jid (user@@host/res) */

    char                c2s[1024];          /**< id of c2s that is handling their connection */

    char                sm_id[41];          /**< local id (for session control) */
    char                c2s_id[10];         /**< remote id (for session control) */

    pkt_t               pres;               /**< copy of the last presence packet we received */

    int                 available;          /**< true if this session is available */
    int                 pri;                /**< current priority of this session */

    jid_t               A;                  /**< list of jids that this session has sent directed presence to */
    jid_t               E;                  /**< list of jids that bounced presence updates we sent them */

    void                **module_data;      /**< per-session module data */

    sess_t              next;               /**< next session (in a list of sessions) */
};

extern sig_atomic_t sm_lost_router;

/* functions */
SM_API xht             aci_load(sm_t sm);
SM_API int             aci_check(xht acls, char *type, jid_t jid);
SM_API void            aci_unload(xht acls);

SM_API int             sm_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);
SM_API int             sm_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
SM_API void            sm_timestamp(time_t t, char timestamp[18]);
SM_API void            sm_c2s_action(sess_t dest, char *action, char *target);
SM_API void            sm_signature(sm_t sm, char *str);

SM_API int             sm_register_ns(sm_t sm, char *uri);
SM_API void            sm_unregister_ns(sm_t sm, char *uri);
SM_API int             sm_get_ns(sm_t sm, char *uri);

SM_API void            dispatch(sm_t sm, pkt_t pkt);

SM_API pkt_t           pkt_error(pkt_t pkt, int err);
SM_API pkt_t           pkt_tofrom(pkt_t pkt);
SM_API pkt_t           pkt_dup(pkt_t pkt, const char *to, const char *from);
SM_API pkt_t           pkt_new(sm_t sm, nad_t nad);
SM_API void            pkt_free(pkt_t pkt);
SM_API pkt_t           pkt_create(sm_t sm, const char *elem, const char *type, const char *to, const char *from);
SM_API void            pkt_id(pkt_t src, pkt_t dest);
SM_API void            pkt_id_new(pkt_t pkt);
SM_API void            pkt_delay(pkt_t pkt, time_t t, const char *from);

SM_API void            pkt_router(pkt_t pkt);
SM_API void            pkt_sess(pkt_t pkt, sess_t sess);

SM_API int             pres_trust(user_t user, jid_t jid);
SM_API void            pres_roster(sess_t sess, item_t item);
SM_API void            pres_update(sess_t sess, pkt_t pres);
SM_API void            pres_error(sess_t sess, jid_t jid);
SM_API void            pres_deliver(sess_t sess, pkt_t pres);
SM_API void            pres_in(user_t user, pkt_t pres);
SM_API void            pres_probe(user_t user);

SM_API void            sess_route(sess_t sess, pkt_t pkt);
SM_API sess_t          sess_start(sm_t sm, jid_t jid);
SM_API void            sess_end(sess_t sess);
SM_API sess_t          sess_match(user_t user, char *resource);

SM_API user_t          user_load(sm_t sm, jid_t jid);
SM_API void            user_free(user_t user);
SM_API int             user_create(sm_t sm, jid_t jid);
SM_API void            user_delete(sm_t sm, jid_t jid);

SM_API void            feature_register(sm_t sm, char *feature);
SM_API void            feature_unregister(sm_t sm, char *feature);


/* driver module manager */

/** module return values */
typedef enum {
    mod_HANDLED,                /**< packet was handled (and freed) */
    mod_PASS                    /**< packet was unhandled, should be passed to the next module */
} mod_ret_t;

/** module chain types */
typedef enum {
    chain_SESS_START,           /**< session start, load per-session data */
    chain_SESS_END,             /**< session ended, save & free per-session data */
    chain_IN_SESS,              /**< packet from an active session */
    chain_IN_ROUTER,            /**< packet from the router */
    chain_OUT_SESS,             /**< packet to an active session */
    chain_OUT_ROUTER,           /**< packet to a router */
    chain_PKT_SM,               /**< packet for the sm itself */
    chain_PKT_USER,             /**< packet for a user */
    chain_PKT_ROUTER,           /**< packet from the router (special purpose) */
    chain_USER_LOAD,            /**< user loaded, load per-user data */
    chain_USER_CREATE,          /**< user creation, generate and save per-user data */
    chain_USER_DELETE,          /**< user deletion, delete saved per-user data */
    chain_DISCO_EXTEND          /**< disco request, extend sm disco#info */
} mod_chain_t;

typedef struct module_st *module_t;
typedef struct mod_instance_st *mod_instance_t;

/** module manager data */
struct mm_st {
    sm_t                sm;         /**< sm context */

    xht                 modules;    /**< pointers to module data (key is module name) */

    int                 nindex;     /**< counter for module instance sequence (!!! should be local to mm_new) */

    /** sess-start chain */
    mod_instance_t      *sess_start;    int nsess_start;
    /** sess-end chain */
    mod_instance_t      *sess_end;      int nsess_end;
    /** in-sess chain */
    mod_instance_t      *in_sess;       int nin_sess;
    /** in-router chain */
    mod_instance_t      *in_router;     int nin_router;
    /** out-sess chain */
    mod_instance_t      *out_sess;      int nout_sess;
    /** out-router chain */
    mod_instance_t      *out_router;    int nout_router;
    /** pkt-sm chain */
    mod_instance_t      *pkt_sm;        int npkt_sm;
    /** pkt-user chain */
    mod_instance_t      *pkt_user;      int npkt_user;
    /** pkt-router chain */
    mod_instance_t      *pkt_router;    int npkt_router;
    /** user-load chain */
    mod_instance_t      *user_load;     int nuser_load;
    /** user-create chain */
    mod_instance_t      *user_create;   int nuser_create;
    /** user-delete chain */
    mod_instance_t      *user_delete;   int nuser_delete;
    /** disco-extend chain */
    mod_instance_t      *disco_extend;  int ndisco_extend;
};

/** data for a single module */
struct module_st {
    mm_t                mm;         /**< module manager */

    char                *name;      /**< name of module */

    int                 index;      /**< module index. this is the index into user->module_data and
                                         sess->module_data where the module can store its own
                                         per-user/per-session data */

    void                *handle;    /**< module handle */

    int                 (*module_init_fn)(mod_instance_t);    /**< module init function */

    int                 init;       /**< number of times the module intialiser has been called */

    void                *private;   /**< module private data */

    int                 (*sess_start)(mod_instance_t mi, sess_t sess);              /**< sess-start handler */
    void                (*sess_end)(mod_instance_t mi, sess_t sess);                /**< sess-end handler */

    mod_ret_t           (*in_sess)(mod_instance_t mi, sess_t sess, pkt_t pkt);      /**< in-sess handler */
    mod_ret_t           (*in_router)(mod_instance_t mi, pkt_t pkt);                 /**< in-router handler */

    mod_ret_t           (*out_sess)(mod_instance_t mi, sess_t sess, pkt_t pkt);     /**< out-sess handler */
    mod_ret_t           (*out_router)(mod_instance_t mi, pkt_t pkt);                /**< out-router handler */

    mod_ret_t           (*pkt_sm)(mod_instance_t mi, pkt_t pkt);                    /**< pkt-sm handler */
    mod_ret_t           (*pkt_user)(mod_instance_t mi, user_t user, pkt_t pkt);     /**< pkt-user handler */

    mod_ret_t           (*pkt_router)(mod_instance_t mi, pkt_t pkt);                /**< pkt-router handler */

    int                 (*user_load)(mod_instance_t mi, user_t user);               /**< user-load handler */

    int                 (*user_create)(mod_instance_t mi, jid_t jid);               /**< user-create handler */
    void                (*user_delete)(mod_instance_t mi, jid_t jid);               /**< user-delete handler */

    void                (*disco_extend)(mod_instance_t mi, pkt_t pkt);              /**< disco-extend handler */

    void                (*free)(module_t mod);                                      /**< called when module is freed */
};

/** single instance of a module in a chain */
struct mod_instance_st {
    sm_t                sm;         /**< sm context */

    module_t            mod;        /**< module that this is an instance of */

    int                 seq;        /**< number of this instance */

    mod_chain_t         chain;      /**< chain this instance is in */

    char                *arg;       /**< option arg that this instance was started with */
};

/** allocate a module manager instance, and loads the modules */
SM_API mm_t                    mm_new(sm_t sm);
/** free a mm instance */
SM_API void                    mm_free(mm_t mm);

/** fire sess-start chain */
SM_API int                     mm_sess_start(mm_t mm, sess_t sess);
/** fire sess-end chain */
SM_API void                    mm_sess_end(mm_t mm, sess_t sess);

/** fire in-sess chain */
SM_API mod_ret_t               mm_in_sess(mm_t mm, sess_t sess, pkt_t pkt);
/** fire in-router chain */
SM_API mod_ret_t               mm_in_router(mm_t mm, pkt_t pkt);

/** fire out-sess chain */
SM_API mod_ret_t               mm_out_sess(mm_t mm, sess_t sess, pkt_t pkt);
/** fire out-router chain */
SM_API mod_ret_t               mm_out_router(mm_t mm, pkt_t pkt);

/** fire pkt-sm chain */
SM_API mod_ret_t               mm_pkt_sm(mm_t mm, pkt_t pkt);
/** fire pkt-user chain */
SM_API mod_ret_t               mm_pkt_user(mm_t mm, user_t user, pkt_t pkt);

/** fire pkt-router chain */
SM_API mod_ret_t               mm_pkt_router(mm_t mm, pkt_t pkt);

/** fire user-load chain */
SM_API int                     mm_user_load(mm_t mm, user_t user);

/** fire user-create chain */
SM_API int                     mm_user_create(mm_t mm, jid_t jid);
/** fire user-delete chain */
SM_API void                    mm_user_delete(mm_t mm, jid_t jid);

/** fire disco-extend chain */
SM_API void                    mm_disco_extend(mm_t mm, pkt_t pkt);


/* object sets */

/** object types */
typedef enum {
    os_type_BOOLEAN,            /**< boolean (0 or 1) */
    os_type_INTEGER,            /**< integer */
    os_type_STRING,             /**< string */
    os_type_NAD,                /**< XML */
    os_type_UNKNOWN             /**< unknown */
} os_type_t;

/** a single tuple (value) within an object */ 
typedef struct os_field_st {
    char        *key;           /**< field name */
    void        *val;           /**< field value */
    os_type_t   type;           /**< field type */
} *os_field_t;

typedef struct os_st        *os_t;
typedef struct os_object_st *os_object_t;

/** object set (ie group of several objects) */
struct os_st {
    pool_t      p;              /**< pool the objects are allocated from */

    os_object_t head;           /**< first object in the list */
    os_object_t tail;           /**< last object in the list */

    int         count;          /**< number of objects in this set */

    os_object_t iter;           /**< pointer for iteration */
};

/** an object */
struct os_object_st {
    /** object set this object is part of */
    os_t        os;

    /** fields (key is field name) */
    xht         hash;

    os_object_t next;           /**< next object in the list */
    os_object_t prev;           /**< previous object in the list */
};

/** create a new object set */
SM_API os_t        os_new(void);
/** free an object set */
SM_API void        os_free(os_t os);

/** number of objects in a set */
SM_API int         os_count(os_t os);

/** set iterator to first object (1 = exists, 0 = doesn't exist) */
SM_API int         os_iter_first(os_t os);

/** set iterator to next object (1 = exists, 0 = doesn't exist) */
SM_API int         os_iter_next(os_t os);

/** get the object currently under the iterator */
SM_API os_object_t os_iter_object(os_t os);

/** create a new object in this set */
SM_API os_object_t os_object_new(os_t os);
/** free an object (remove it from its set) */
SM_API void        os_object_free(os_object_t o);

/** add a field to the object */
SM_API void        os_object_put(os_object_t o, const char *key, const void *val, os_type_t type);

/** get a field from the object of type type (result in val), ret 0 == not found */
SM_API int         os_object_get(os_t os, os_object_t o, const char *key, void **val, os_type_t type, os_type_t *ot);

/** wrappers for os_object_get to avoid breaking strict-aliasing rules in gcc3 */
SM_API int         os_object_get_nad(os_t os, os_object_t o, const char *key, nad_t *val);
SM_API int         os_object_get_str(os_t os, os_object_t o, const char *key, char **val);
SM_API int         os_object_get_int(os_t os, os_object_t o, const char *key, int *val);
SM_API int         os_object_get_bool(os_t os, os_object_t o, const char *key, int *val);
SM_API int         os_object_get_time(os_t os, os_object_t o, const char *key, time_t *val);

/** wrappers for os_object_put to avoid breaking strict-aliasing rules in gcc3 */
SM_API void        os_object_put_time(os_object_t o, const char *key, const time_t *val);

/** set field iterator to first field (1 = exists, 0 = doesn't exist) */
SM_API int         os_object_iter_first(os_object_t o);
/** set field iterator to next field (1 = exists, 0 = doesn't exist) */
SM_API int         os_object_iter_next(os_object_t o);
/** extract field values from field currently under the iterator */
SM_API void        os_object_iter_get(os_object_t o, char **key, void **val, os_type_t *type);


/* storage manager */

/** storage driver return values */
typedef enum {
    st_SUCCESS,                 /**< call completed successful */
    st_FAILED,                  /**< call failed (driver internal error) */
    st_NOTFOUND,                /**< no matching objects were found */
    st_NOTIMPL                  /**< call not implemented */
} st_ret_t;

typedef struct st_driver_st *st_driver_t;

/** storage manager data */
struct storage_st {
    sm_t        sm;             /**< sm context */

    xht         drivers;        /**< pointers to drivers (key is driver name) */
    xht         types;          /**< pointers to drivers (key is type name) */

    st_driver_t default_drv;    /**< default driver (used when there is no module
                                     explicitly registered for a type) */
};

/** data for a single storage driver */
struct st_driver_st {
    storage_t   st;             /**< storage manager context */ 

    char        *name;          /**< name of driver */

    void        *private;       /**< driver private data */

    /** called to find out if this driver can handle a particular type */
    st_ret_t    (*add_type)(st_driver_t drv, const char *type);

    /** put handler */
    st_ret_t    (*put)(st_driver_t drv, const char *type, const char *owner, os_t os);
    /** get handler */
    st_ret_t    (*get)(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os);
    /** count handler */
    st_ret_t    (*count)(st_driver_t drv, const char *type, const char *owner, const char *filter, int *count);
    /** delete handler */
    st_ret_t    (*delete)(st_driver_t drv, const char *type, const char *owner, const char *filter);
    /** replace handler */
    st_ret_t    (*replace)(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os);

    /** called when driver is freed */
    void        (*free)(st_driver_t drv);
};

/** allocate a storage manager instance */
SM_API storage_t       storage_new(sm_t sm);
/** free a storage manager instance */
SM_API void            storage_free(storage_t st);

/** associate this data type with this driver */
SM_API st_ret_t        storage_add_type(storage_t st, const char *driver, const char *type);

/** store objects in this set */
SM_API st_ret_t        storage_put(storage_t st, const char *type, const char *owner, os_t os);
/** get objects matching this filter */
SM_API st_ret_t        storage_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os);
/** count objects matching this filter */
SM_API st_ret_t        storage_count(storage_t st, const char *type, const char *owner, const char *filter, int *count);
/** delete objects matching this filter */
SM_API st_ret_t        storage_delete(storage_t st, const char *type, const char *owner, const char *filter);
/** replace objects matching this filter with objects in this set (atomic delete + get) */
SM_API st_ret_t        storage_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os);

/** type for the driver init function */
typedef st_ret_t (*st_driver_init_fn)(st_driver_t);


/** storage filter types */
typedef enum {
    st_filter_type_PAIR,        /**< key=value pair */
    st_filter_type_AND,         /**< and operator */
    st_filter_type_OR,          /**< or operator */
    st_filter_type_NOT          /**< not operator */
} st_filter_type_t;

typedef struct st_filter_st *st_filter_t;
/** filter abstraction */
struct st_filter_st {
    pool_t              p;      /**< pool that filter is allocated from */

    st_filter_type_t    type;   /**< type of this filter */

    char                *key;   /**< key for PAIR filters */
    char                *val;   /**< value for PAIR filters */

    st_filter_t         sub;    /**< sub-filter for operator filters */

    st_filter_t         next;   /**< next filter in a group */
};

/** create a filter abstraction from a LDAP-like filter string */
SM_API st_filter_t     storage_filter(const char *filter);

/** see if the object matches the filter */
SM_API int             storage_match(st_filter_t filter, os_object_t o, os_t os);
