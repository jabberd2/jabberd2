#ifndef INCL_UTIL_SERIAL_H
#define INCL_UTIL_SERIAL_H 1

#include "util.h"
#include <stddef.h>

/**
 * serialisation helper functions
 */

JABBERD2_API int         ser_string_get(char **dest, int *source, const char *buf, int len);
JABBERD2_API int         ser_int_get(int *dest, int *source, const char *buf, int len);
JABBERD2_API void        ser_string_set(const char *source, int *dest, char **buf, int *len);
JABBERD2_API void        ser_string_setx(const char *source, size_t slen, int *dest, char **buf, int *len);
JABBERD2_API void        ser_int_set(int source, int *dest, char **buf, int *len);

#endif
