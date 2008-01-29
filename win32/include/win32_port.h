#ifndef _WIN32_PORT_H
#define _WIN32_PORT_H

#define FD_SETSIZE 16384

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

/*
#define sleep Sleep
#define strcasecmp	stricmp
#define strncasecmp	strnicmp
#define off_t		_off_t

#define socket(af,type,protocol) WSASocket(af,type,protocol,0,0,WSA_FLAG_OVERLAPPED)
#define write(handle,buf,len) send(handle,(void *)buf,len,0)
#define read(handle,buf,len) recv(handle,(void *)buf,len,0)
#define close(handle) closesocket(handle)
*/

/* getopt is defined inside Cyrus SASL library, include optarg */
/*
#ifdef _WIN32
__declspec(dllimport) char *optarg;
#endif
*/

#ifdef _DEBUG
#define DEBUG 1
#endif

#endif
