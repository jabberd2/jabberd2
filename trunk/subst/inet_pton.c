#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if !defined(HAVE_INET_PTON) && defined(WIN32)

#include "ac-stdint.h"

#include "ip6_misc.h"

#include <errno.h>

#ifndef EAFNOSUPPORT
#define	EAFNOSUPPORT	97	/* not present in errno.h provided with VC */
#endif

int
inet_pton(int af, const char *src, void *dst)
{
    if (af != AF_INET) {
	errno = EAFNOSUPPORT;
	return -1;
    }
    return inet_aton (src, dst);
}

#endif
