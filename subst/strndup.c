#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_STRNDUP
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
