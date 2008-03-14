#ifndef DIRENT_INCLUDED
#define DIRENT_INCLUDED

#ifdef HAVE_CONFIG_H
# include "config.h"
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

#if !defined(HAVE_DIRENT_H) && !defined(HAVE_NDIR_H) && !defined(HAVE_SYS_DIR_H) && !defined(HAVE_SYS_NDIR_H)
#ifdef HAVE__FINDFIRST

/*

    Declaration of POSIX directory browsing functions and types for Win32.

    Author:  Kevlin Henney (kevlin@acm.org, kevlin@curbralan.com)
    History: Created March 1997. Updated June 2003.
    Rights:  See end of file.
    
*/

#ifdef __cplusplus
extern "C"
{
#endif

#include <direct.h>

typedef struct DIR DIR;

struct dirent
{
    char *d_name;
};

JABBERD2_API DIR           *opendir(const char *);
JABBERD2_API int           closedir(DIR *);
JABBERD2_API struct dirent *readdir(DIR *);
JABBERD2_API void          rewinddir(DIR *);

/*

    Copyright Kevlin Henney, 1997, 2003. All rights reserved.

    Permission to use, copy, modify, and distribute this software and its
    documentation for any purpose is hereby granted without fee, provided
    that this copyright and permissions notice appear in all copies and
    derivatives.
    
    This software is supplied "as is" without express or implied warranty.

    But that said, if there are any problems please get in touch.

*/

#ifdef __cplusplus
}
#endif

#endif
#endif

#endif
