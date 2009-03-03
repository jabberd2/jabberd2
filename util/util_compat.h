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

#ifndef INCL_UTIL_COMPAT_H
#define INCL_UTIL_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file util/util_compat.h
 * @brief define the structures that could be missing in old libc implementations
 */

#ifndef PF_INET6
# define PF_INET6    10		/**< protcol family for IPv6 */
#endif

#ifndef AF_INET6
# define AF_INET6    PF_INET6	/**< address family for IPv6 */
#endif

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 46	/**< maximum length of the string
				  representation of an IPv6 address */
#endif


#ifndef IN6_IS_ADDR_V4MAPPED
    /** check if an IPv6 is just a mapped IPv4 address */
#define IN6_IS_ADDR_V4MAPPED(a) \
    ((*(const uint32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
    (*(const uint32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
    (*(const uint32_t *)(const void *)(&(a)->s6_addr[8]) == ntohl(0x0000ffff)))
#endif

#ifndef HAVE_SA_FAMILY_T
typedef unsigned short  sa_family_t;
#endif

#ifndef HAVE_STRUCT_IN6_ADDR
/**
 * structure that contains a plain IPv6 address (only defined if
 * not contained in the libc
 */
struct in6_addr {
    uint8_t        s6_addr[16];    /**< IPv6 address */
};
#endif /* NO_IN6_ADDR */

#ifndef HAVE_STRUCT_SOCKADDR_IN6
/**
 * structure that contains an IPv6 including some additional attributes
 * (only defined if not contained in the libc)
 */
struct sockaddr_in6 {
#ifdef SIN6_LEN
    uint8_t        sin6_len;    /**< length of this struct */
#endif /* SIN6_LEN */
    sa_family_t        sin6_family;    /**< address family (AF_INET6) */
    in_port_t        sin6_port;    /**< transport layer port # */
    uint32_t        sin6_flowinfo;    /**< IPv6 traffic class and flow info */
    struct in6_addr    sin6_addr;    /**< IPv6 address */
    uint32_t        sin6_scope_id;    /**< set of interfaces for a scope */
};
#endif /* NO_SOCKADDR_IN6 */

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
/**
 * container for sockaddr_in and sockaddr_in6 structures, handled like
 * an object in jabberd2 code
 * (this definition is not fully compatible with RFC 2553,
 * but it is enough for us) */
#define _SS_PADSIZE (128-sizeof(sa_family_t))
struct sockaddr_storage {
    sa_family_t        ss_family;    /**< address family */
    char        __ss_pad[_SS_PADSIZE]; /**< padding to a size of 128 bytes */
};
#endif /* NO_SOCKADDR_STORAGE */

#ifndef SSL_OP_NO_TICKET 
#define SSL_OP_NO_TICKET		0x00004000L
#endif

#ifdef __cplusplus
}
#endif

#endif    /* INCL_UTIL_H */
