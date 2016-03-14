#include <src/conf.h>
#include <src/module.h>
#include <lib/xhash.h>
#include <lib/log.h>
#include <lib/uv_nn.h>
#include <src/functions.h>

#include <uv.h>
#include <nanomsg/nn.h>
#include <nanomsg/bus.h>

#include <assert.h>
#include <unistd.h>

/**
 * @file bus.c
 * @brief message bus broker device
 */

typedef struct mod_bus_instance_st
{
    mod_instance_t _;
    log_t   *log;
    xht     *listen_connections;
    xht     *connect_connections;
    int s;
    int eid;
    int fd;
    uv_poll_t poll;
    uv_nn_t nn;
} mod_bus_instance_t;

static void _alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->len = 1024;
    buf->base = GC_MALLOC(buf->len);
    if (!buf->base) buf->len = 0;
}

static void _read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    mod_bus_instance_t * const mi = (mod_bus_instance_t *) stream->data;
    LOG_DEBUG(mi->log, "_read_cb %zd:%.*s", nread, (int)buf->len, buf->base);
}

static void _bus_bind(const char *key, const char *value, void *data, xconfig_elem_t *elem)
{
    mod_bus_instance_t * const mi = (mod_bus_instance_t *) data;
    //bus_listen(mi->log, mi->listen_connections, elem->values, elem->nvalues);
    if (value) {
        LOG_DEBUG(mi->log, "bus_bind for %s", value);

        if (uv_nn_init(uv_default_loop(), &mi->nn) < 0) {
            LOG_ERROR(mi->log, "bus_bind uv_nn_init failed: %s\n", nn_strerror(nn_errno()));
            abort();
        }

        if (uv_nn_open(&mi->nn, nn_socket(AF_SP, NN_BUS)) < 0) {
            LOG_ERROR(mi->log, "bus_bind uv_nn_open failed: %s\n", nn_strerror(nn_errno()));
            abort();
        }

        if ((mi->eid = uv_nn_bind(&mi->nn, value)) < 0) {
            LOG_ERROR(mi->log, "bus_bind uv_nn_bind failed: %s\n", nn_strerror(nn_errno()));
            abort();
        }

        LOG_DEBUG(mi->log, "bus_bind sock:%d eid:%d", mi->nn.sock, mi->eid);
        sleep(1);
        int ret = nn_send(mi->nn.sock, "bind", 4, NN_DONTWAIT);
        LOG_DEBUG(mi->log, "bus_bind sent %d", ret);

        mi->nn.data = mi;
        uv_nn_read_start(&mi->nn, _alloc_cb, _read_cb);
    }
}

static void _bus_connect(const char *key, const char *value, void *data, xconfig_elem_t *elem)
{
    mod_bus_instance_t * const mi = (mod_bus_instance_t *) data;
    //bus_connect(mi->log, mi->connect_connections, elem->values, elem->nvalues);
    if (value) {
        LOG_DEBUG(mi->log, "bus_connect for %s", value);
        mi->s = nn_socket(AF_SP, NN_BUS);
        assert (mi->s >= 0);
        mi->eid = nn_connect(mi->s, value);
        assert (mi->eid >= 0);
        LOG_DEBUG(mi->log, "bus_connect s:%d eid:%d", mi->s, mi->eid);
        sleep(1);
        int ret = nn_send(mi->s, "connect", 7, NN_DONTWAIT);
        LOG_DEBUG(mi->log, "bus_connect sent %d", ret);
    }
}


DLLEXPORT char *module_name = MOD_NAME;

DLLEXPORT bool module_recycle(mod_instance_t *_mi)
{
    mod_bus_instance_t * const mi = (mod_bus_instance_t *) _mi;
    LOG_TRACE(mi->log, "recycling module " MOD_NAME "[%p]", mi);
    GC_FREE(mi);
    return false;
}

DLLEXPORT mod_instance_t *module_instanitate(mod_instance_t *_mi)
{
    mod_bus_instance_t *mi = (mod_bus_instance_t *) GC_REALLOC(_mi, sizeof(mod_bus_instance_t));
    assert(mi);

    mi->log = log_get("mod." MOD_NAME);
    assert(mi->log);

    mi->listen_connections = xhash_new(3);
    config_register("io.bind", MI(mi)->confprefixes, NULL, _bus_bind, mi);
    mi->connect_connections = xhash_new(3); // get from config?
    config_register("io.connect", MI(mi)->confprefixes, NULL, _bus_connect, mi);

    LOG_TRACE(mi->log, "module " MOD_NAME "[%p] instanitated", mi)
    return (mod_instance_t *) mi;
}
