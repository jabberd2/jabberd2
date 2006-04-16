#ifndef DIRENT_INCLUDED
#define DIRENT_INCLUDED

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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

DIR           *opendir(const char *);
int           closedir(DIR *);
struct dirent *readdir(DIR *);
void          rewinddir(DIR *);

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
