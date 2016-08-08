#ifndef INCL_UTIL_H
#define INCL_UTIL_H 1

#ifdef HAVE_CONFIG_H
# include "../config.h"
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

#if XML_MAJOR_VERSION > 1
/* XML_StopParser is present in expat 2.x */
#define HAVE_XML_STOPPARSER
#if XML_MINOR_VERSION > 0
/* XML_SetHashSalt is present in expat 2.1.x */
#define HAVE_XML_SETHASHSALT
#endif
#endif

#ifdef _WIN32
  #ifdef _USRDLL
    #define DLLEXPORT  __declspec(dllexport)
    #define SM_API     __declspec(dllimport)
  #else
    #define DLLEXPORT  __declspec(dllimport)
    #define SM_API     __declspec(dllexport)
  #endif
#else
  #define DLLEXPORT
  #define SM_API
#endif

/* misc macros */
#define countof(x)  (sizeof(x) / sizeof((x)[0]))
#define new(type)           calloc(1, sizeof(type))
#define pnew(pool, type)    pmalloco((pool), sizeof(type))

#endif    /* INCL_UTIL_H */
