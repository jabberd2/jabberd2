/* See https://github.com/smokku/uv_nn */

#ifndef UV_NN_H
#define UV_NN_H

/* you need to provide memory allocation function */
#include "uv_nn_malloc.h"

#include <uv.h>
#include <nanomsg/nn.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  UV_NN = UV_HANDLE_TYPE_MAX + 0x100
} uv_nn_handle_type;


typedef struct uv_nn_s uv_nn_t;

#define UV_NN_FIELDS                                                          \
  int sock;                                                                   \
  int eid;                                                                    \
  int fd;                                                                     \
  /* private */                                                               \
  uv_poll_t poll;                                                             \

/*
 * uv_nn_t
 *
 * Represents a nanomsg socket.
 */
#define UV_STREAM_PRIVATE_FIELDS
struct uv_nn_s {
  UV_HANDLE_FIELDS
  UV_STREAM_FIELDS
  UV_NN_FIELDS
};

UV_EXTERN int uv_nn_init(uv_loop_t*, uv_nn_t* handle);
UV_EXTERN int uv_nn_open(uv_nn_t* handle, int sock);

UV_EXTERN int uv_nn_bind(uv_nn_t* handle, const char *addr);
UV_EXTERN int uv_nn_connect(uv_nn_t* handle, const char *addr);
NN_EXPORT int uv_nn_shutdown(uv_nn_t* handle, int how);

UV_EXTERN int uv_nn_read_start(uv_nn_t*,
                               uv_alloc_cb alloc_cb,
                               uv_read_cb read_cb);
UV_EXTERN int uv_nn_read_stop(uv_nn_t*);

UV_EXTERN int uv_nn_write(uv_write_t* req,
                          uv_nn_t* handle,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          uv_write_cb cb);

UV_EXTERN int uv_nn_is_readable(const uv_nn_t* handle);
UV_EXTERN int uv_nn_is_writable(const uv_nn_t* handle);

UV_EXTERN int uv_nn_is_closing(const uv_nn_t* handle);

UV_EXTERN int uv_nn_send_buffer_size(uv_nn_t* handle, int* value);
UV_EXTERN int uv_nn_recv_buffer_size(uv_nn_t* handle, int* value);

#ifdef __cplusplus
}
#endif
#endif /* UV_NN_H */
