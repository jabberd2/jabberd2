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

#include "resolver.h"
#include "dns.h"

/* Mac OS X 10.3 needs this - I don't think it will break anything else */
#define BIND_8_COMPAT (1)

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_WINDNS_H
# include <windns.h>
#endif


/* compare two srv structures, order by priority then by randomised weight */
static int _srv_compare(const void *a, const void *b) {
    dns_host_t ah = * (dns_host_t *) a, bh = * (dns_host_t *) b;
    dns_srv_t arr, brr;

    if(ah == NULL) return 1;
    if(bh == NULL) return -1;

    arr = (dns_srv_t) ah->rr;
    brr = (dns_srv_t) bh->rr;

    if(arr->priority > brr->priority) return 1;
    if(arr->priority < brr->priority) return -1;

    if(arr->rweight > brr->rweight) return -1;
    if(arr->rweight < brr->rweight) return 1;
    
    return 0;
}


/* unix implementation */
#if defined(HAVE_RES_QUERY) || defined(HAVE___RES_QUERY)

/* older systems might not have these */
#ifndef T_SRV
# define T_SRV (33)
#endif
#ifndef T_AAAA
# define T_AAAA (28)
#endif

/* the largest packet we'll send and receive */
#if PACKETSZ > 1024
# define MAX_PACKET PACKETSZ
#else
# define MAX_PACKET (1024)
#endif

typedef union {
    HEADER          hdr;
    unsigned char   buf[MAX_PACKET];
} dns_packet_t;

static void *_a_rr(dns_packet_t *packet, unsigned char *eom, unsigned char **scan) {
    struct in_addr in;

    GETLONG(in.s_addr, *scan);
    in.s_addr = ntohl(in.s_addr);

    return strdup(inet_ntoa(in));
}

static void *_aaaa_rr(dns_packet_t *packet, unsigned char *eom, unsigned char **scan) {
    char addr[INET6_ADDRSTRLEN];
    struct sockaddr_in6 sa6;
    int i;

    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sa6.sin6_len = sizeof(sa6);
#endif
    
    for(i = 0; i < 16; i++) {
        sa6.sin6_addr.s6_addr[i] = (*scan)[i];
    }

    j_inet_ntop((struct sockaddr_storage *)&sa6, addr, sizeof(addr));

    return strdup(addr);
}

static void *_srv_rr(dns_packet_t *packet, unsigned char *eom, unsigned char **scan) {
    unsigned int priority, weight, port;
    int len;
    char host[256];
    dns_srv_t srv;

    GETSHORT(priority, *scan);
    GETSHORT(weight, *scan);
    GETSHORT(port, *scan);

    len = dn_expand(packet->buf, eom, *scan, host, 256);
    if (len < 0)
        return NULL;
    *scan = (unsigned char *) (*scan + len);

    srv = (dns_srv_t) malloc(sizeof(struct dns_srv_st));

    srv->priority = priority;
    srv->weight = weight;
    srv->port = port;

    /* add a random factor to the weight, for load balancing and such */
    if(weight != 0)
        srv->rweight = 1 + rand() % (10000 * weight);
    else
        srv->rweight = 0;

    strcpy(srv->name, host);

    return (void *) srv;
}

/** the actual resolver function */
dns_host_t dns_resolve(const char *zone, int query_type) {
    char host[256];
    dns_packet_t packet;
    int len, qdcount, ancount, an, n;
    unsigned char *eom, *scan;
    dns_host_t *reply, first;
    unsigned int t_type, type, class, ttl;

    if(zone == NULL || *zone == '\0')
        return NULL;

    switch(query_type)
    {
        case DNS_QUERY_TYPE_A:
            t_type = T_A;
            break;

        case DNS_QUERY_TYPE_AAAA:
            t_type = T_AAAA;
            break;

        case DNS_QUERY_TYPE_SRV:
            t_type = T_SRV;
            break;

        default:
            return NULL;
    }

    /* do the actual query */
    if((len = res_query(zone, C_IN, t_type, packet.buf, MAX_PACKET)) == -1 || len < sizeof(HEADER))
        return NULL;

    /* we got a valid result, containing two types of records - packet
     * and answer .. we have to skip over the packet records */

    /* no. of packets, no. of answers */
    qdcount = ntohs(packet.hdr.qdcount);
    ancount = ntohs(packet.hdr.ancount);

    /* end of the returned message */
    eom = (unsigned char *) (packet.buf + len);

    /* our current location */
    scan = (unsigned char *) (packet.buf + sizeof(HEADER));

    /* skip over the packet records */
    while(qdcount > 0 && scan < eom) {
        qdcount--;
        if((len = dn_expand(packet.buf, eom, scan, host, 256)) < 0)
            return NULL;
        scan = (unsigned char *) (scan + len + QFIXEDSZ);
    }

    /* create an array to store the replies in */
    reply = (dns_host_t *) calloc(1, sizeof(dns_host_t) * ancount);

    an = 0;
    /* loop through the answer buffer and extract SRV records */
    while(ancount > 0 && scan < eom ) {
        ancount--;
        len = dn_expand(packet.buf, eom, scan, host, 256);
        if(len < 0) {
            for(n = 0; n < an; n++)
                free(reply[n]);
            free(reply);
            return NULL;
        }

        scan += len;

        /* extract the various parts of the record */
        GETSHORT(type, scan);
        GETSHORT(class, scan);
        GETLONG(ttl, scan);
        GETSHORT(len, scan);

        /* skip records we're not interested in */
        if(type != t_type) {
            scan = (unsigned char *) (scan + len);
            continue;
        }

        /* create a new reply structure to save it in */
        reply[an] = (dns_host_t) malloc(sizeof(struct dns_host_st));

        reply[an]->type = type;
        reply[an]->class = class;
        reply[an]->ttl = ttl;

        reply[an]->next = NULL;

        /* type-specific processing */
        switch(type)
        {
            case T_A:
                reply[an]->rr = _a_rr(&packet, eom, &scan);
                break;

            case T_AAAA:
                reply[an]->rr = _aaaa_rr(&packet, eom, &scan);
                break;

            case T_SRV:
                reply[an]->rr = _srv_rr(&packet, eom, &scan);
                break;

            default:
                scan = (unsigned char *) (scan + len);
                continue;
        }

        /* fell short, we're done */
        if(reply[an]->rr == NULL)
        {
            free(reply[an]);
            reply[an] = NULL;
            break;
        }

        /* on to the next one */
        an++;
    }

    /* sort srv records them */
    if(t_type == T_SRV)
        qsort(reply, an, sizeof(dns_host_t), _srv_compare);

    /* build a linked list out of the array elements */
    for(n = 0; n < an - 1; n++)
        reply[n]->next = reply[n + 1];

    first = reply[0];

    free(reply);

    return first;
}

#endif /* HAVE_RES_QUERY */

/* windows implementation */
#ifdef HAVE_DNSQUERY

/* mingw doesn't have these, and msdn doesn't document them. hmph. */
#ifndef DNS_TYPE_SRV
# define DNS_TYPE_SRV (33)
#endif
#ifndef DNS_TYPE_AAAA
# define DNS_TYPE_AAAA (28)
#endif

static void *_a_rr(DNS_A_DATA *data) {
    struct in_addr in;

    in.s_addr = data->IpAddress;
    
    return strdup(inet_ntoa(in));
}

static void *_aaaa_rr(DNS_AAAA_DATA *data) {
    char addr[INET6_ADDRSTRLEN];
    struct sockaddr_in6 sa6;
    int i;

    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sa6.sin6_len = sizeof(sa6);
#endif

    for(i = 0; i < 4; i++)
#ifdef _WIN32
        ((DWORD *)&sa6.sin6_addr)[i] = data->Ip6Address.IP6Dword[i];
#else
        sa6.sin6_addr.s6_addr32[i] = data->Ip6Address.IP6Dword[i];
#endif

    j_inet_ntop((struct sockaddr_storage *) &sa6, addr, sizeof(addr));

    return strdup(addr);
}

static void *_srv_rr(DNS_SRV_DATA *data) {
    dns_srv_t srv;

    srv = (dns_srv_t) malloc(sizeof(struct dns_srv_st));

    srv->priority = data->wPriority;
    srv->weight = data->wWeight;
    srv->port = data->wPort;

    if(srv->weight != 0)
        srv->rweight = 1 + rand() % (10000 * srv->weight);
    else
        srv->rweight = 0;

    strncpy(srv->name, data->pNameTarget, 255);
    srv->name[255] = 0;

    return (void *) srv;
}

dns_host_t dns_resolve(const char *zone, int query_type) {
    int type, num, i;
    PDNS_RECORD rr, scan;
    dns_host_t *reply, first;

    if(zone == NULL || *zone == '\0')
        return NULL;

    switch(query_type) {
        case DNS_QUERY_TYPE_A:
            type = DNS_TYPE_A;
            break;

        case DNS_QUERY_TYPE_AAAA:
            type = DNS_TYPE_AAAA;
            break;

        case DNS_QUERY_TYPE_SRV:
            type = DNS_TYPE_SRV;
            break;

        default:
            return NULL;
    }

    if(DnsQuery(zone, type, DNS_QUERY_STANDARD, NULL, &rr, NULL) != 0)
        return NULL;

    num = 0;
    for(scan = rr; scan != NULL; scan = scan->pNext)
        num++;

    reply = (dns_host_t *) calloc(1, sizeof(dns_host_t) * num);

    num = 0;
    for(scan = rr; scan != NULL; scan = scan->pNext) {
        if(scan->wType != type || stricmp(scan->pName, zone) != 0)
            continue;

        reply[num] = (dns_host_t) malloc(sizeof(struct dns_host_st));

        reply[num]->type = scan->wType;
        reply[num]->class = 0;
        reply[num]->ttl = scan->dwTtl;

        reply[num]->next = NULL;

        switch(type) {
            case DNS_TYPE_A:
                reply[num]->rr = _a_rr(&scan->Data.A);
                break;

            case DNS_TYPE_AAAA:
                reply[num]->rr = _aaaa_rr(&scan->Data.AAAA);
                break;

            case DNS_TYPE_SRV:
                reply[num]->rr = _srv_rr(&scan->Data.SRV);
                break;
        }

        num++;
    }

    if(type == DNS_TYPE_SRV)
        qsort(reply, num, sizeof(dns_host_t), _srv_compare);

    for(i = 0; i < num - 1; i++)
        reply[i]->next = reply[i + 1];

    first = reply[0];

    free(reply);

    return first;
}
#endif /* HAVE_DNSQUERY */

/** free an srv structure */
void dns_free(dns_host_t dns) {
    dns_host_t next;

    while(dns != NULL) {
        next = dns->next;
        free(dns->rr);
        free(dns);
        dns = next;
    }
}
