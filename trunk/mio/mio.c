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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "mio.h"


mio_t mio_epoll_new(int maxfd);
mio_t mio_poll_new(int maxfd);
mio_t mio_select_new(int maxfd);
mio_t mio_wsasync_new(int maxfd);

mio_t mio_new(int maxfd)
{
  mio_t m = NULL;

#ifdef MIO_EPOLL
  m = mio_epoll_new(maxfd);
  if (m != NULL) return m;
#endif

#ifdef MIO_WSASYNC
  m = mio_wsasync_new(maxfd);
  if (m != NULL) return m;
#endif

#ifdef MIO_SELECT
  m = mio_select_new(maxfd);
  if (m != NULL) return m;
#endif

#ifdef MIO_POLL
  m = mio_poll_new(maxfd);
  if (m != NULL) return m;
#endif

  return m;
}
