#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
#include <stdlib.h>

time_t my_timegm (struct tm *tm) {
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();
    return ret;
}
#endif
