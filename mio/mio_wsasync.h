/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Adam Strzelecki
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

/* MIO backend for select() */

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#define WM_MIO_EVENT (WM_APP + 100)

#define MIO_FUNCS \
    static ATOM mio_class = NULL;                                       \
                                                                        \
    LONG CALLBACK _mio_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LONG lParam); \
                                                                        \
    static mio_fd_t _mio_alloc_fd(mio_t m, int fd)                      \
    {                                                                   \
        mio_priv_fd_t priv_fd = MIO(m)->next_free;                      \
                                                                        \
        if(priv_fd == NULL)                                             \
            return NULL;                                                \
                                                                        \
        MIO(m)->next_free = priv_fd->next_free;                         \
        priv_fd->mio_fd.fd = fd;                                        \
        priv_fd->next_free = NULL;                                      \
                                                                        \
        return (mio_fd_t)priv_fd;                                       \
    }                                                                   \
                                                                        \
    static void _mio_free_fd(mio_t m, mio_priv_fd_t priv_fd)            \
    {                                                                   \
        priv_fd->next_free = MIO(m)->next_free;                         \
        priv_fd->mio_fd.fd = 0;                                         \
        priv_fd->revent = 0;                                            \
        priv_fd->event = 0;                                             \
        MIO(m)->next_free = priv_fd;                                    \
    }                                                                   \
                                                                        \
    static int _mio_select(mio_priv_t m, int t)                         \
    {                                                                   \
        MSG msg; int lResult = 0;                                       \
        MIO(m)->select_fd = NULL;                                       \
        MIO(m)->timer = SetTimer(MIO(m)->hwnd,                          \
            MIO(m)->timer ? MIO(m)->timer : 0, 1000 * t, NULL);         \
        while(!lResult && GetMessage(&msg, NULL, 0, 0))                 \
        {                                                               \
            TranslateMessage(&msg);                                     \
            lResult = DispatchMessage(&msg);                            \
        }                                                               \
        return MIO(m)->select_fd ? 1 : 0;                               \
    }                                                                   \
                                                                        \
    static mio_priv_fd_t _mio_peek(mio_priv_t m)                        \
    {                                                                   \
        MSG msg;                                                        \
        MIO(m)->select_fd = NULL;                                       \
        if(PeekMessage(&msg, MIO(m)->hwnd, WM_MIO_EVENT, WM_MIO_EVENT + MIO(m)->maxfd, PM_REMOVE)) \
        {                                                               \
            TranslateMessage(&msg);                                     \
            DispatchMessage(&msg);                                      \
        }                                                               \
        return MIO(m)->select_fd;                                       \
    }

#define MIO_FD_VARS \
    struct mio_priv_fd_st *next_free;                                   \
    long event;                                                         \
    long revent;                                                        \
    int idx;

#define MIO_VARS \
    HWND hwnd;                                                          \
    UINT_PTR timer;                                                     \
    int defer_free;                                                     \
    int count;                                                          \
    mio_priv_fd_t select_fd;                                            \
    mio_priv_fd_t fds;                                                  \
    mio_priv_fd_t next_free;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        int i;                                                          \
        HINSTANCE hInstance = GetModuleHandle(NULL);                    \
        MIO(m)->defer_free = 0;                                         \
        if(mio_class == NULL) {                                         \
            WNDCLASS wndclass;                                          \
            memset(&wndclass, 0, sizeof(WNDCLASS));                     \
            wndclass.style = CS_NOCLOSE;                                \
            wndclass.lpfnWndProc = _mio_wnd_proc;                       \
            wndclass.lpszClassName = "jabberd2mio";                     \
            wndclass.hInstance = hInstance;                             \
                                                                        \
            if((mio_class = RegisterClass(&wndclass)) == NULL) {        \
                mio_debug(ZONE, "cannot create listener class (%d, %x)", GetLastError(), hInstance); \
                free(m);                                                \
                return NULL;                                            \
            }                                                           \
            mio_debug(ZONE, "created listener class");                  \
        }                                                               \
        MIO(m)->hwnd = CreateWindow("jabberd2mio", "jabberd2mio",       \
            0, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,                  \
            NULL, NULL, hInstance, m);                                  \
        if(MIO(m)->hwnd == NULL) {                                      \
            mio_debug(ZONE, "cannot create listener window (%d, %x)", GetLastError(), hInstance); \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        mio_debug(ZONE, "created listener window (%x)", MIO(m)->hwnd);  \
        if((MIO(m)->fds = malloc(sizeof(struct mio_priv_fd_st) * maxfd)) == NULL) { \
            mio_debug(ZONE, "cannot allocate descriptors table");       \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        memset(MIO(m)->fds, 0, sizeof(struct mio_priv_fd_st) * maxfd);  \
        MIO(m)->count = maxfd;                                          \
        for(i = 0; i < maxfd; i++)                                      \
            MIO(m)->fds[i].idx = i;                                     \
        for(i = 0; i < maxfd - 1; i++)                                  \
            MIO(m)->fds[i].next_free = &(MIO(m)->fds[i + 1]);           \
        MIO(m)->fds[maxfd - 1].next_free = NULL;                        \
        MIO(m)->next_free = &(MIO(m)->fds[0]);                          \
        MIO(m)->select_fd = NULL;                                       \
    } while(0)

#define MIO_FREE_VARS(m) \
    do {                                                                \
        DestroyWindow(MIO(m)->hwnd);                                    \
        free(MIO(m)->fds);                                              \
    } while(0)

#define MIO_ALLOC_FD(m, rfd)    _mio_alloc_fd(MIO(m), rfd)
#define MIO_FREE_FD(m, mfd)     _mio_free_fd(m, mfd)

#define MIO_DEQUEUE(m, mfd) \
    if(mfd->event) {                                                \
        MSG msg;                                                    \
        WSAAsyncSelect(mfd->mio_fd.fd, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, 0); \
        while(PeekMessage(&msg, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, WM_MIO_EVENT + mfd->idx, PM_REMOVE)); \
    }                                                               \

#define MIO_REMOVE_FD(m, mfd)   MIO_DEQUEUE(m, mfd)

#define MIO_CHECK(m, t)         _mio_select(m, t)

#define MIO_SET_READ(m, mfd) \
    if(!(mfd->event & FD_READ)) {                                       \
        MIO_DEQUEUE(m, mfd);                                            \
        WSAAsyncSelect(mfd->mio_fd.fd, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, (mfd->event |= FD_READ|FD_ACCEPT|FD_CONNECT|FD_CLOSE)); \
    }
#define MIO_SET_WRITE(m, mfd) \
    if(!(mfd->event & FD_WRITE)) {                                      \
        MIO_DEQUEUE(m, mfd);                                            \
        WSAAsyncSelect(mfd->mio_fd.fd, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, (mfd->event |= FD_WRITE|FD_CONNECT|FD_CLOSE)); \
    }

#define MIO_UNSET_READ(m, mfd) \
    if(mfd->event & FD_READ) {                                          \
        mfd->event &= ~(FD_READ|FD_ACCEPT|FD_CONNECT|FD_CLOSE);         \
        if(mfd->event & FD_WRITE)                                       \
            mfd->event = FD_WRITE|FD_CONNECT|FD_CLOSE;                  \
        MIO_DEQUEUE(m, mfd);                                            \
        WSAAsyncSelect(mfd->mio_fd.fd, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, mfd->event); \
    }
#define MIO_UNSET_WRITE(m, mfd)                                         \
    if(mfd->event & FD_WRITE) {                                         \
        mfd->event &= ~FD_WRITE;                                        \
        if(!(mfd->event & FD_READ))                                     \
            mfd->event = 0;                                             \
        MIO_DEQUEUE(m, mfd);                                            \
        WSAAsyncSelect(mfd->mio_fd.fd, MIO(m)->hwnd, WM_MIO_EVENT + mfd->idx, mfd->event); \
    }

#define MIO_CAN_READ(m, iter)   (iter->revent & (FD_READ|FD_ACCEPT|FD_CONNECT|FD_CLOSE))
#define MIO_CAN_WRITE(m, iter)  ((iter->revent & FD_WRITE) || !(iter->revent & FD_READ) && (iter->revent & (FD_CONNECT|FD_CLOSE)))
#define MIO_CAN_FREE(m)         (!MIO(m)->defer_free)

#define MIO_INIT_ITERATOR(iter) \
    mio_priv_fd_t iter = NULL

#define MIO_ITERATE_RESULTS(m, retval, iter) \
    for(MIO(m)->defer_free = 1, iter = MIO(m)->select_fd; iter || ((MIO(m)->defer_free = 0)); iter = _mio_peek(m))

#define MIO_ITERATOR_FD(m, iter) \
    (&iter->mio_fd)
