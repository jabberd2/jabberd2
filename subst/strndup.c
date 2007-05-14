#ifndef HAVE_STRNDUP

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stddef.h>

char *strndup(char *str, size_t len)
{
    char *dup = (char *)malloc(len+1);
    if (dup) {
        strncpy(dup,str,len);
        dup[len]= '\0';
    }
    return dup;
}
#endif
