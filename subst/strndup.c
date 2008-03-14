#ifdef HAVE_CONFIG_H
# include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef HAVE_STRNDUP

#include <stddef.h>

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

JABBERD2_API char *strndup(char *str, size_t len)
{
    char *dup = (char *)malloc(len+1);
    if (dup) {
        strncpy(dup,str,len);
        dup[len]= '\0';
    }
    return dup;
}
#endif /* HAVE_STRNDUP */
