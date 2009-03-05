/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

#include "util.h"

/* ISO 8601 / JEP-0082 date/time manipulation */

/* formats */
#define DT_DATETIME_P       "%04d-%02d-%02dT%02d:%02d:%lf+%02d:%02d"
#define DT_DATETIME_M       "%04d-%02d-%02dT%02d:%02d:%lf-%02d:%02d"
#define DT_DATETIME_Z       "%04d-%02d-%02dT%02d:%02d:%lfZ"
#define DT_TIME_P           "%02d:%02d:%lf+%02d:%02d"
#define DT_TIME_M           "%02d:%02d:%lf-%02d:%02d"
#define DT_TIME_Z           "%02d:%02d:%lfZ"
#define DT_LEGACY           "%04d%02d%02dT%02d:%02d:%lf"

time_t datetime_in(char *date) {
    struct tm gmt, off;
    double sec;
    off_t fix = 0;
    struct timeval tv;
    struct timezone tz;

    assert((int) (date != NULL));

    /* !!! sucks having to call this each time */
    tzset();

    memset(&gmt, 0, sizeof(struct tm));
    memset(&off, 0, sizeof(struct tm));

    if(sscanf(date, DT_DATETIME_P,
                   &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
                   &gmt.tm_hour, &gmt.tm_min, &sec,
                   &off.tm_hour, &off.tm_min) == 8) {
        gmt.tm_sec = (int) sec;
        gmt.tm_year -= 1900;
        gmt.tm_mon--;
        fix = off.tm_hour * 3600 + off.tm_min * 60;
    }

    else if(sscanf(date, DT_DATETIME_M,
                   &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
                   &gmt.tm_hour, &gmt.tm_min, &sec,
                   &off.tm_hour, &off.tm_min) == 8) {
        gmt.tm_sec = (int) sec;
        gmt.tm_year -= 1900;
        gmt.tm_mon--;
        fix = - off.tm_hour * 3600 - off.tm_min * 60;
    }

    else if(sscanf(date, DT_DATETIME_Z,
                   &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
                   &gmt.tm_hour, &gmt.tm_min, &sec) == 6) {
        gmt.tm_sec = (int) sec;
        gmt.tm_year -= 1900;
        gmt.tm_mon--;
        fix = 0;
    }

    else if(sscanf(date, DT_TIME_P,
                   &gmt.tm_hour, &gmt.tm_min, &sec,
                   &off.tm_hour, &off.tm_min) == 5) {
        gmt.tm_sec = (int) sec;
        fix = off.tm_hour * 3600 + off.tm_min * 60;
    }

    else if(sscanf(date, DT_TIME_M,
                   &gmt.tm_hour, &gmt.tm_min, &sec,
                   &off.tm_hour, &off.tm_min) == 5) {
        gmt.tm_sec = (int) sec;
        fix = - off.tm_hour * 3600 - off.tm_min * 60;
    }

    else if(sscanf(date, DT_TIME_Z,
                   &gmt.tm_hour, &gmt.tm_min, &sec) == 3) {
        gmt.tm_sec = (int) sec;
        fix = - off.tm_hour * 3600 - off.tm_min * 60;
    }

    else if(sscanf(date, DT_LEGACY,
                   &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
                   &gmt.tm_hour, &gmt.tm_min, &sec) == 6) {
        gmt.tm_sec = (int) sec;
        gmt.tm_year -= 1900;
        gmt.tm_mon--;
        fix = 0;
    }

    gmt.tm_isdst = -1;

    gettimeofday(&tv, &tz);

    return mktime(&gmt) + fix - (tz.tz_minuteswest * 60);
}

void datetime_out(time_t t, datetime_t type, char *date, int datelen) {
    struct tm *gmt;

    assert((int) type);
    assert((int) (date != NULL));
    assert((int) datelen);

    gmt = gmtime(&t);

    switch(type) {
        case dt_DATE:
            snprintf(date, datelen, "%04d-%02d-%02d", gmt->tm_year + 1900, gmt->tm_mon + 1, gmt->tm_mday);
            break;

        case dt_TIME:
            snprintf(date, datelen, "%02d:%02d:%02dZ", gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
            break;

        case dt_DATETIME:
            snprintf(date, datelen, "%04d-%02d-%02dT%02d:%02d:%02dZ", gmt->tm_year + 1900, gmt->tm_mon + 1, gmt->tm_mday, gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
            break;

        case dt_LEGACY:
            snprintf(date, datelen, "%04d%02d%02dT%02d:%02d:%02d", gmt->tm_year + 1900, gmt->tm_mon + 1, gmt->tm_mday, gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
            break;
    }
}
