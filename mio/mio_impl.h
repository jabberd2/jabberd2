/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris, Christof Meerwald
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

/*
   MIO -- Managed Input/Output
   ---------------------------
*/

#include "util/inaddr.h"

/* win32 wrappers around strerror */
#ifdef _WIN32
#define close(x) closesocket(x)
JABBERD2_API char *mio_strerror(int code)
{
  static char buff[1024];
  if(FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, code, 0, buff, sizeof(buff), NULL))
    return buff;
  return strerror(code);
}
#endif /* _WIN32 */

/** our internal wrapper around a fd */
typedef enum { 
    type_CLOSED = 0x00, 
    type_NORMAL = 0x01, 
    type_LISTEN = 0x02, 
    type_CONNECT = 0x10, 
    type_CONNECT_READ = 0x11,
    type_CONNECT_WRITE = 0x12
} mio_type_t;
typedef struct mio_priv_fd_st
{
    struct mio_fd_st mio_fd;

    mio_type_t type;
    /* app event handler and data */
    mio_handler_t app;
    void *arg;

    MIO_FD_VARS
} *mio_priv_fd_t;

/** now define our master data type */
typedef struct mio_priv_st
{
    struct mio_st *mio;

    int maxfd;
    MIO_VARS
} *mio_priv_t;

/* lazy factor */
#define MIO(m) ((mio_priv_t) m)
#define FD(m,f) ((mio_priv_fd_t) f)
#define ACT(m,f,a,d) (*(FD(m,f)->app))(m,a,&FD(m,f)->mio_fd,d,FD(m,f)->arg)

/* temp debug outputter */
#define ZONE __LINE__
#ifndef MIO_DEBUG
#define MIO_DEBUG 0
#endif
#define mio_debug if(MIO_DEBUG) _mio_debug
static void _mio_debug(int line, const char *msgfmt, ...)
{
    va_list ap;
    va_start(ap,msgfmt);
    fprintf(stderr,"mio.c#%d: ",line);
    vfprintf(stderr,msgfmt,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

MIO_FUNCS

/** add and set up this fd to this mio */
static mio_fd_t _mio_setup_fd(mio_t m, int fd, mio_handler_t app, void *arg)
{
    int flags;
    mio_fd_t mio_fd;

    mio_debug(ZONE, "adding fd #%d", fd);

    mio_fd = MIO_ALLOC_FD(m, fd);
    if (mio_fd == NULL) return NULL;

    /* ok to process this one, welcome to the family */
    FD(m,mio_fd)->type = type_NORMAL;
    FD(m,mio_fd)->app = app;
    FD(m,mio_fd)->arg = arg;

    /* set the socket to non-blocking */
#if defined(HAVE_FCNTL)
    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
#elif defined(HAVE_IOCTL)
    flags = 1;
    ioctl(fd, FIONBIO, &flags);
#endif

    return mio_fd;
}

/** internal close function */
static void _mio_close(mio_t m, mio_fd_t fd)
{
    if(FD(m,fd)->type == type_CLOSED)
        return;

    mio_debug(ZONE,"actually closing fd #%d", fd->fd);

    /* take out of poll sets */
    MIO_REMOVE_FD(m, FD(m,fd));

    /* let the app know, it must process any waiting write data it has and free it's arg */
    if (FD(m,fd)->app != NULL)
        ACT(m, fd, action_CLOSE, NULL);

    /* close the socket, and reset all memory */
    close(fd->fd);
    FD(m,fd)->type = type_CLOSED;
    FD(m,fd)->app = NULL;
    FD(m,fd)->arg = NULL;

    if (MIO_CAN_FREE(m))
    {
        MIO_FREE_FD(m, fd);
    }
}

/** internally accept an incoming connection from a listen sock */
static void _mio_accept(mio_t m, mio_fd_t fd)
{
    struct sockaddr_storage serv_addr;
    socklen_t addrlen = (socklen_t) sizeof(serv_addr);
    int newfd;
    mio_fd_t mio_fd;
    char ip[INET6_ADDRSTRLEN];

    mio_debug(ZONE, "accepting on fd #%d", fd->fd);

    /* pull a socket off the accept queue and check */
    newfd = accept(fd->fd, (struct sockaddr*)&serv_addr, &addrlen);
    if(newfd <= 0) return;
    if(addrlen <= 0) {
        close(newfd);
        return;
    }

    j_inet_ntop(&serv_addr, ip, sizeof(ip));
    mio_debug(ZONE, "new socket accepted fd #%d, %s:%d", newfd, ip, j_inet_getport(&serv_addr));

    /* set up the entry for this new socket */
    mio_fd = _mio_setup_fd(m, newfd, FD(m,fd)->app, FD(m,fd)->arg);

    if(!mio_fd) {
        close(newfd);
        return;
    }

    /* tell the app about the new socket, if they reject it clean up */
    if (ACT(m, mio_fd, action_ACCEPT, ip))
    {
        mio_debug(ZONE, "accept was rejected for %s:%d", ip, newfd);
        MIO_REMOVE_FD(m, FD(m,mio_fd));

        /* close the socket, and reset all memory */
        close(newfd);
        MIO_FREE_FD(m, mio_fd);
    }

    return;
}

/** internally change a connecting socket to a normal one */
static void _mio__connect(mio_t m, mio_fd_t fd)
{
    mio_type_t type = FD(m,fd)->type;

    mio_debug(ZONE, "connect processing for fd #%d", fd->fd);

    /* reset type and clear the "write" event that flags connect() is done */
    FD(m,fd)->type = type_NORMAL;
    MIO_UNSET_WRITE(m,FD(m,fd));

    /* if the app had asked to do anything in the meantime, do those now */
    if(type & type_CONNECT_READ) mio_read(m,fd);
    if(type & type_CONNECT_WRITE) mio_write(m,fd);
}

/** reset app stuff for this fd */
static void _mio_app(mio_t m, mio_fd_t fd, mio_handler_t app, void *arg)
{
    FD(m,fd)->app = app;
    FD(m,fd)->arg = arg;
}

/** main select loop runner */
static void _mio_run(mio_t m, int timeout)
{
    int retval;
    MIO_INIT_ITERATOR(iter);

    mio_debug(ZONE, "mio running for %d sec", timeout);

    /* wait for a socket event */
    retval = MIO_CHECK(m, timeout);

    /* nothing to do */
    if(retval == 0) return;

    /* an error */
    if(retval < 0)
    {
        mio_debug(ZONE, "MIO_CHECK returned an error (%d)", MIO_ERROR);

        return;
    }

    mio_debug(ZONE,"mio processing %d file descriptors", retval);

    /* loop through the sockets, check for stuff to do */
    MIO_ITERATE_RESULTS(m, retval, iter)
    {
        mio_fd_t fd = MIO_ITERATOR_FD(m,iter);
        if (fd == NULL) continue;

        /* skip already dead slots */ 
        if(FD(m,fd)->type == type_CLOSED) continue; 

        /* new conns on a listen socket */
        if(FD(m,fd)->type == type_LISTEN && MIO_CAN_READ(m,iter))
        {
            _mio_accept(m, fd);
            goto deferred;
        }

        /* check for connecting sockets */
        if(FD(m,fd)->type & type_CONNECT &&
           (MIO_CAN_READ(m,iter) || MIO_CAN_WRITE(m,iter)))
        {
            _mio__connect(m, fd);
            goto deferred;
        }

        /* read from ready sockets */
        if(FD(m,fd)->type == type_NORMAL && MIO_CAN_READ(m,iter))
        {
            /* if they don't want to read any more right now */
            if(ACT(m, fd, action_READ, NULL) == 0)
                MIO_UNSET_READ(m, FD(m,fd));
        }

        /* write to ready sockets */
        if(FD(m,fd)->type == type_NORMAL && MIO_CAN_WRITE(m,iter))
        {
            /* don't wait for writeability if nothing to write anymore */
            if(ACT(m, fd, action_WRITE, NULL) == 0)
                MIO_UNSET_WRITE(m, FD(m,fd));
        }

    deferred:
        /* deferred closing fd
         * one of previous actions might change the state of fd */ 
        if(FD(m,fd)->type == type_CLOSED)
        {
            MIO_FREE_FD(m, fd);
        }
    }
}

/** start processing read events */
static void _mio_read(mio_t m, mio_fd_t fd)
{
    if(m == NULL || fd == NULL) return;

    /* if connecting, do this later */
    if(FD(m,fd)->type & type_CONNECT)
    {
        FD(m,fd)->type |= type_CONNECT_READ;
        return;
    }

    MIO_SET_READ(m, FD(m,fd));
}

/** try writing to the socket via the app */
static void _mio_write(mio_t m, mio_fd_t fd)
{
    if(m == NULL || fd == NULL) return;

    /* if connecting, do this later */
    if(FD(m,fd)->type & type_CONNECT)
    {
        FD(m,fd)->type |= type_CONNECT_WRITE;
        return;
    }

    if(FD(m,fd)->type != type_NORMAL)
        return;

    if(ACT(m, fd, action_WRITE, NULL) == 0) return;

    /* not all written, do more l8r */
    MIO_SET_WRITE(m, FD(m,fd));
}

/** set up a listener in this mio w/ this default app/arg */
static mio_fd_t _mio_listen(mio_t m, int port, const char *sourceip, mio_handler_t app, void *arg)
{
    int fd, flag = 1;
    mio_fd_t mio_fd;
    struct sockaddr_storage sa;

    if(m == NULL) return NULL;

    mio_debug(ZONE, "mio to listen on %d [%s]", port, sourceip);

    memset(&sa, 0, sizeof(sa));

    /* if we specified an ip to bind to */
    if(sourceip != NULL && !j_inet_pton(sourceip, &sa))
        return NULL;

    if(sa.ss_family == 0)
        sa.ss_family = AF_INET;
    
    /* attempt to create a socket */
    if((fd = socket(sa.ss_family,SOCK_STREAM,0)) < 0) return NULL;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0) return NULL;

    /* set up and bind address info */
    j_inet_setport(&sa, port);
    if(bind(fd,(struct sockaddr*)&sa,j_inet_addrlen(&sa)) < 0)
    {
        close(fd);
        return NULL;
    }

    /* start listening with a max accept queue specified by kern.ipc.somaxconn sysctl */
    if(listen(fd, -1) < 0)
    {
        close(fd);
        return NULL;
    }

    /* now set us up the bomb */
    mio_fd = _mio_setup_fd(m, fd, app, arg);
    if(mio_fd == NULL)
    {
        close(fd);
        return NULL;
    }
    FD(m,mio_fd)->type = type_LISTEN;
    /* by default we read for new sockets */
    mio_read(m,mio_fd);

    return mio_fd;
}

/** create an fd and connect to the given ip/port */
static mio_fd_t _mio_connect(mio_t m, int port, const char *hostip, const char *srcip, mio_handler_t app, void *arg)
{
    int fd, flag, flags;
    mio_fd_t mio_fd;
    struct sockaddr_storage sa, src;

    memset(&sa, 0, sizeof(sa));

    if(m == NULL || port <= 0 || hostip == NULL) return NULL;

    mio_debug(ZONE, "mio connecting to %s, port=%d",hostip,port);

    /* convert the hostip */
    if(j_inet_pton(hostip, &sa)<=0) {
        MIO_SETERROR(EFAULT);
        return NULL;
    }

    if(!sa.ss_family) sa.ss_family = AF_INET;
    
    /* attempt to create a socket */
    if((fd = socket(sa.ss_family,SOCK_STREAM,0)) < 0) return NULL;

    /* Bind to the given source IP if it was specified */
    if (srcip != NULL) {
        /* convert the srcip */
        if(j_inet_pton(srcip, &src)<=0) {
            MIO_SETERROR(EFAULT);
            return NULL;
        }
        if(!src.ss_family) src.ss_family = AF_INET;
        j_inet_setport(&src, INADDR_ANY);
        if(bind(fd,(struct sockaddr*)&src,j_inet_addrlen(&src)) < 0) {
            close(fd);
            return NULL;
        }
    }

    /* set the socket to non-blocking before connecting */
#if defined(HAVE_FCNTL)
    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
#elif defined(HAVE_IOCTL)
    flags = 1;
    ioctl(fd, FIONBIO, &flags);
#endif

    /* set up address info */
    j_inet_setport(&sa, port);

    /* try to connect */
    flag = connect(fd,(struct sockaddr*)&sa,j_inet_addrlen(&sa));

    mio_debug(ZONE, "connect returned %d and %s", flag, MIO_STRERROR(MIO_ERROR));

    /* already connected?  great! */
    if(flag == 0)
    {
        mio_fd = _mio_setup_fd(m,fd,app,arg);
        if(mio_fd != NULL) return mio_fd;
    }

    /* gotta wait till later */
#ifdef _WIN32
    if(flag == -1 && WSAGetLastError() == WSAEWOULDBLOCK)
#else
    if(flag == -1 && errno == EINPROGRESS)
#endif
    {
        mio_fd = _mio_setup_fd(m,fd,app,arg);
        if(mio_fd != NULL)
        {
            mio_debug(ZONE, "connect processing non-blocking mode");

            FD(m,mio_fd)->type = type_CONNECT;
            MIO_SET_WRITE(m,FD(m,mio_fd));
            return mio_fd;
        }
    }

    /* bummer dude */
    close(fd);
    return NULL;
}


/** adam */
static void _mio_free(mio_t m)
{
    MIO_FREE_VARS(m);

    free(m);
}

/** eve */
static mio_t _mio_new(int maxfd)
{
    static struct mio_st mio_impl = {
        _mio_free,
        _mio_listen, _mio_connect, _mio_setup_fd,
        _mio_app,
        _mio_close,
        _mio_write, _mio_read,
        _mio_run
    };
    mio_t m;

    /* init winsock if we are in Windows */
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD( 1, 1 ), &wsaData))
        return NULL;
#endif

    /* allocate and zero out main memory */
    if((m = calloc(1, sizeof(struct mio_priv_st))) == NULL) {
        fprintf(stderr,"Cannot allocate MIO memory! Exiting.\n");
        exit(EXIT_FAILURE);
    }

    /* set up our internal vars */
    *m = &mio_impl;
    MIO(m)->maxfd = maxfd;

    MIO_INIT_VARS(m);

    return m;
}
