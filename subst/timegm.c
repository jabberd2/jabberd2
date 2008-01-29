#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#if !defined(HAVE_SNPRINTF) || defined(HAVE_BROKEN_SNPRINTF)
int ap_snprintf(char *, size_t, const char *, ...);
# define snprintf ap_snprintf
#endif

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

JABBERD2_API time_t timegm(struct tm *tm)
{
    time_t ret;
    char *tz;
    
    /* save current timezone and set UTC */
    tz = getenv("TZ");
    putenv("TZ=UTC");   /* use Coordinated Universal Time (i.e. zero offset) */
    tzset();
    
    ret = mktime(tm);
    if(tz)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "TZ=%s", tz);
        putenv(buf);
    } else
        putenv("TZ=");
    tzset();
    
    return ret;
}
#endif
