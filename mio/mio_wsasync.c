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

/*
   MIO -- Managed Input/Output
   ---------------------------
*/

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "mio.h"


#ifdef MIO_WSASYNC
#include "mio_wsasync.h"
#include "mio_impl.h"

mio_t mio_wsasync_new(int maxfd)
{
  return _mio_new(maxfd);
}

LONG CALLBACK _mio_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LONG lParam)
{
    if(msg == WM_TIMER) {
        return 1;
    } else if(msg >= WM_MIO_EVENT) {
        mio_priv_t m = (mio_priv_t)(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if(msg - WM_MIO_EVENT >= m->count) {
            mio_debug(ZONE, "mio event %d on socket id %d out of socket bounds %d", WSAGETSELECTEVENT(lParam), msg - WM_MIO_EVENT, m->count);
            return 0;
        }
        if(!m->fds[msg - WM_MIO_EVENT].event & WSAGETSELECTEVENT(lParam)) {
            mio_debug(ZONE, "unmatched mio event %d on socket #%d", WSAGETSELECTEVENT(lParam), m->fds[msg - WM_MIO_EVENT].mio_fd.fd);
            return 0;
        }
        m->select_fd = &m->fds[msg - WM_MIO_EVENT];
        m->select_fd->revent = WSAGETSELECTEVENT(lParam);
        mio_debug(ZONE, "get mio event %d on socket #%d", m->select_fd->revent, m->select_fd->mio_fd.fd); \
        return 1;
    } else if(msg == WM_CREATE) {
        SetWindowLongPtr(hwnd, GWLP_USERDATA,
            (LONG_PTR)((LPCREATESTRUCT)lParam)->lpCreateParams);
    } else {
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

#endif
