#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if !defined(HAVE_INET_NTOP) && defined(_WIN32)
#ifdef JABBERD2_EXPORTS
# define JABBERD2_API  __declspec(dllexport)
#else /* JABBERD2_EXPORTS */
# define JABBERD2_API  __declspec(dllimport)
#endif /* JABBERD2_EXPORTS */

#include "ac-stdint.h"

#include "ip6_misc.h"

#include <stdio.h>
#include <errno.h>

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN    16
#endif

static const char *
inet_ntop_v4 (const void *src, char *dst, size_t size)
{
    const char digits[] = "0123456789";
    int i;
    struct in_addr *addr = (struct in_addr *)src;
    u_long a = ntohl(addr->s_addr);
    const char *orig_dst = dst;

    if (size < INET_ADDRSTRLEN) {
	errno = ENOSPC;
	return NULL;
    }
    for (i = 0; i < 4; ++i) {
	int n = (a >> (24 - i * 8)) & 0xFF;
	int non_zerop = 0;

	if (non_zerop || n / 100 > 0) {
	    *dst++ = digits[n / 100];
	    n %= 100;
	    non_zerop = 1;
	}
	if (non_zerop || n / 10 > 0) {
	    *dst++ = digits[n / 10];
	    n %= 10;
	    non_zerop = 1;
	}
	*dst++ = digits[n];
	if (i != 3)
	    *dst++ = '.';
    }
    *dst++ = '\0';
    return orig_dst;
}

JABBERD2_API const char *
inet_ntop(int af, const void *src, char *dst, size_t size)
{
    switch (af) {
    case AF_INET :
	return inet_ntop_v4 (src, dst, size);
    default :
	errno = WSAEAFNOSUPPORT;
	return NULL;
    }
}

#endif
