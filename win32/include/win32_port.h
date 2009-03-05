#ifndef _WIN32_PORT_H
#define _WIN32_PORT_H

#define FD_SETSIZE 16384

/* Declare we support Win2000 & IE4.
 * Needed to avoid inet_ntop & inet_ption Vista SDK inclusion. */
#define WINVER			0x0500
#define _WIN32_WINNT	0x0500
#define _WIN32_IE		0x0400
#define _RICHEDIT_VER	0x0100

#include <winsock2.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>

#define CONFIG_DIR "."
#define LIBRARY_DIR "."

#ifndef S_IRUSR
#define S_IRUSR 0
#endif
#ifndef S_IWUSR
#define S_IWUSR 0
#endif
#ifndef S_IRGRP
#define S_IRGRP 0
#endif

#ifdef _DEBUG
#define DEBUG 1
#endif

#endif
