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

/* this implements allow/deny filters for IP address */

#include "util.h"

access_t access_new(int order)
{
    access_t access = (access_t) calloc(1, sizeof(struct access_st));

    access->order = order;

    return access;
}

void access_free(access_t access)
{
    if(access->allow != NULL) free(access->allow);
    if(access->deny != NULL) free(access->deny);
    free(access);
}

static int _access_calc_netsize(const char *mask, int defaultsize)
{
    struct in_addr legacy_mask;
    int netsize;

#ifndef HAVE_INET_PTON
    if(strchr(mask, '.') && inet_aton(mask, &legacy_mask))
#else
    if(inet_pton(AF_INET, mask, &legacy_mask.s_addr) > 0)
#endif
    {
        /* netmask has been given in dotted decimal form */
        int temp = ntohl(legacy_mask.s_addr);
        netsize = 32;

        while(netsize && temp%2==0)
        {
            netsize--;
            temp /= 2;
        }
    } else {
        /* numerical netsize */
        netsize = j_atoi(mask, defaultsize);
    }

    return netsize;
}

/** convert a IPv6 mapped IPv4 address to a real IPv4 address */
static void _access_unmap_v4(struct sockaddr_in6 *src, struct sockaddr_in *dst)
{
    memset(dst, 0, sizeof(struct sockaddr_in));
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = htonl((((int)src->sin6_addr.s6_addr[12]*256+src->sin6_addr.s6_addr[13])*256+src->sin6_addr.s6_addr[14])*256+(int)src->sin6_addr.s6_addr[15]);
}

/** check if two ip addresses are within the same subnet */
static int _access_check_match(struct sockaddr_storage *ip_1, struct sockaddr_storage *ip_2, int netsize)
{
    struct sockaddr_in *sin_1;
    struct sockaddr_in *sin_2;
    struct sockaddr_in6 *sin6_1;
    struct sockaddr_in6 *sin6_2;
    int i;

    sin_1 = (struct sockaddr_in *)ip_1;
    sin_2 = (struct sockaddr_in *)ip_2;
    sin6_1 = (struct sockaddr_in6 *)ip_1;
    sin6_2 = (struct sockaddr_in6 *)ip_2;

    /* addresses of different families */
    if(ip_1->ss_family != ip_2->ss_family)
    {
        /* maybe on of the addresses is just a IPv6 mapped IPv4 address */
        if (ip_1->ss_family == AF_INET && ip_2->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&sin6_2->sin6_addr))
        {
            struct sockaddr_storage t;
            struct sockaddr_in *temp;

            temp = (struct sockaddr_in *)&t;

            _access_unmap_v4(sin6_2, temp);
            if(netsize>96)
                netsize -= 96;

            return _access_check_match(ip_1, &t, netsize);
        }

        if (ip_1->ss_family == AF_INET6 && ip_2->ss_family == AF_INET && IN6_IS_ADDR_V4MAPPED(&sin6_1->sin6_addr))
        {
            struct sockaddr_storage t;
            struct sockaddr_in *temp;

            temp = (struct sockaddr_in *)&t;
        
            _access_unmap_v4(sin6_1, temp);
            if(netsize>96)
                netsize -= 96;

            return _access_check_match(&t, ip_2, netsize);
        }

        return 0;
    }

    /* IPv4? */
    if(ip_1->ss_family == AF_INET)
    {
        int netmask;

        if(netsize > 32)
            netsize = 32;

        netmask = htonl(-1 << (32-netsize));

        return ((sin_1->sin_addr.s_addr&netmask) == (sin_2->sin_addr.s_addr&netmask));
    }

    /* IPv6? */
    if(ip_1->ss_family == AF_INET6)
    {
        unsigned char bytemask;

        if(netsize > 128)
            netsize = 128;

        for(i=0; i<netsize/8; i++)
            if(sin6_1->sin6_addr.s6_addr[i] != sin6_2->sin6_addr.s6_addr[i])
                return 0;
    
        if(netsize%8 == 0)
            return 1;

        bytemask = 0xff << (8 - netsize%8);

        return ((sin6_1->sin6_addr.s6_addr[i]&bytemask) == (sin6_2->sin6_addr.s6_addr[i]&bytemask));
    }

    /* unknown address family */
    return 0;
}

int access_allow(access_t access, const char *ip, const char *mask)
{
    struct sockaddr_storage ip_addr;
    int netsize;

    if(j_inet_pton(ip, &ip_addr) <= 0)
        return 1;

    netsize = _access_calc_netsize(mask, ip_addr.ss_family==AF_INET ? 32 : 128);

    access->allow = (access_rule_t) realloc(access->allow, sizeof(struct access_rule_st) * (access->nallow + 1));

    memcpy(&access->allow[access->nallow].ip, &ip_addr, sizeof(ip_addr));
    access->allow[access->nallow].mask = netsize;

    access->nallow++;

    return 0;
}

int access_deny(access_t access, const char *ip, const char *mask)
{
    struct sockaddr_storage ip_addr;
    int netsize;

    if(j_inet_pton(ip, &ip_addr) <= 0)
        return 1;

    netsize = _access_calc_netsize(mask, ip_addr.ss_family==AF_INET ? 32 : 128);

    access->deny = (access_rule_t) realloc(access->deny, sizeof(struct access_rule_st) * (access->ndeny + 1));

    memcpy(&access->deny[access->ndeny].ip, &ip_addr, sizeof(ip_addr));
    access->deny[access->ndeny].mask = netsize;

    access->ndeny++;

    return 0;
}

int access_check(access_t access, const char *ip)
{
    struct sockaddr_storage addr;
    access_rule_t rule;
    int i, allow = 0, deny = 0;

    if(j_inet_pton(ip, &addr) <= 0)
        return 0;

    /* first, search the allow list */
    for(i = 0; !allow && i < access->nallow; i++)
    {
        rule = &access->allow[i];
        if(_access_check_match(&addr, &rule->ip, rule->mask))
            allow = 1;
    }

    /* now the deny list */
    for(i = 0; !deny && i < access->ndeny; i++)
    {
        rule = &access->deny[i];
        if(_access_check_match(&addr, &rule->ip, rule->mask))
            deny = 1;
    }

    /* allow then deny */
    if(access->order == 0)
    {
        if(allow)
            return 1;

        if(deny)
            return 0;

        /* allow by default */
        return 1;
    }

    /* deny then allow */
    if(deny)
        return 0;

    if(allow)
        return 1;

    /* deny by default */
    return 0;
}
