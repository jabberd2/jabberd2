#ifndef EXPAT_CONFIG_H
#define EXPAT_CONFIG_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(WIN32) && !defined(__MINGW32__)
#include "winconfig.h"
#else
#define XML_DTD 1
#define XML_MIN_SIZE 1
#endif

#endif
