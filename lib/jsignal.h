/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#ifndef INCL_UTIL_JSIGNAL_H
#define INCL_UTIL_JSIGNAL_H 1

#include "util.h"

/* Portable signal function */
typedef void jsighandler_t(int);
JABBERD2_API jsighandler_t* jabber_signal(int signo, jsighandler_t *func);

#ifdef _WIN32
/* Windows service wrapper function */
typedef int (jmainhandler_t)(int argc, char** argv);
JABBERD2_API int jabber_wrap_service(int argc, char** argv, jmainhandler_t *wrapper, LPCTSTR name, LPCTSTR display, LPCTSTR description, LPCTSTR depends);
#define JABBER_MAIN(name, display, description, depends) jabber_main(int argc, char** argv); \
                    main(int argc, char** argv) { return jabber_wrap_service(argc, argv, jabber_main, name, display, description, depends); } \
                    jabber_main(int argc, char** argv)
#else /* _WIN32 */
#define JABBER_MAIN(name, display, description, depends) int main(int argc, char** argv)
#endif /* _WIN32 */

#endif
