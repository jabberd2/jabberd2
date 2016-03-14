#include "uv_nn.h"
#include <string.h>

int uv_nn_init(uv_loop_t* loop, uv_nn_t* handle)
{
    memset(handle, 0, sizeof(uv_nn_t));
    handle->loop = loop;
    handle->type = UV_NN;
    return 0;
}

int uv_nn_open(uv_nn_t* handle, int sock)
{
    if (sock < 0) return sock;
    handle->sock = sock;

    size_t fdsz = sizeof handle->fd;
    int ret = nn_getsockopt(handle->sock, NN_SOL_SOCKET, NN_RCVFD, &handle->fd, &fdsz);
    if (ret != 0) return ret;

    ret = uv_poll_init(uv_default_loop(), &handle->poll, handle->fd);
    if (ret != 0) return ret;

    handle->poll.data = handle;
    return 0;
}

static void _nn_read(uv_poll_t* poll, int status, int events)
{
    uv_nn_t* const handle = (uv_nn_t*) poll->data;
    if (status == 0 && events & UV_READABLE) {
        uv_buf_t *buf = uv_nn_malloc(sizeof(uv_buf_t));
        handle->alloc_cb((uv_handle_t*)handle, 65536, buf);
        int read = nn_recv(handle->sock, buf->base, buf->len, handle->flags);
        handle->read_cb((uv_stream_t*)handle, read, buf);
    }
}

int uv_nn_read_start(uv_nn_t* handle, uv_alloc_cb alloc_cb, uv_read_cb read_cb)
{
    handle->alloc_cb = alloc_cb;
    handle->read_cb = read_cb;
    return uv_poll_start(&handle->poll, UV_READABLE, _nn_read);
}

inline int uv_nn_read_stop(uv_nn_t* handle)
{
    return uv_poll_stop(&handle->poll);
}

inline int uv_nn_bind(uv_nn_t* handle, const char *addr)
{
    return nn_bind(handle->sock, addr);
}

inline int uv_nn_connect(uv_nn_t* handle, const char *addr)
{
    return nn_connect(handle->sock, addr);
}
