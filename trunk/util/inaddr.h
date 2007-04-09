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

#ifndef INCL_INADDR_H
#define INCL_INADDR_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "ac-stdint.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "subst/subst.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * helpers for ip addresses
 */

#include <util/util_compat.h>

int         j_inet_pton(char *src, struct sockaddr_storage *dst);
const char  *j_inet_ntop(struct sockaddr_storage *src, char *dst, size_t size);
int         j_inet_getport(struct sockaddr_storage *sa);
int	    j_inet_setport(struct sockaddr_storage *sa, in_port_t port);
socklen_t   j_inet_addrlen(struct sockaddr_storage *sa);

#ifdef __cplusplus
}
#endif

#endif    /* INCL_UTIL_H */


