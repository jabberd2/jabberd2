/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file util/datetime.h
  * @brief ISO 8610 / JEP 82 date/time manipulation
  * @author Robert Norris
  */

#ifndef INCL_UTIL_DATETIME_H
#define INCL_UTIL_DATETIME_H 1

#include "util.h"

#include <time.h>

typedef enum {
    dt_DATE     = 1,
    dt_TIME     = 2,
    dt_DATETIME = 3,
    dt_LEGACY   = 4
} datetime_t;

JABBERD2_API time_t  datetime_in(const char * const date);
JABBERD2_API void    datetime_out(time_t t, datetime_t type, char * const date, int datelen);

#endif
