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

#include "sm.h"

/** @file sm/mod_iq_version.c
  * @brief software version
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.16 $
  */

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#define uri_VERSION     "jabber:iq:version"
static int ns_VERSION = 0;

static mod_ret_t _iq_version_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    char buf[256];

#if defined(HAVE_UNAME)
    struct utsname un;

#elif defined(_WIN32)
    char sysname[64];
    char release[64];
    char version[64];

    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;
    BOOL bSomeError = FALSE;

    sysname[0] = 0;
    release[0] = 0;
    version[0] = 0;
#endif

    /* we only want to play with iq:version gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_VERSION)
        return mod_PASS;

    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "name", "jabberd session manager");
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "version", mi->sm->signature);

    /* figure out the os type */
#if defined(HAVE_UNAME)
    if(uname(&un) == 0) {
        snprintf(buf, 256, "%s %s", un.sysname, un.machine);
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "os", buf);
    }
#elif defined(_WIN32)
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
    {
        /* If OSVERSIONINFOEX doesn't work, try OSVERSIONINFO. */
        
        osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
        if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) 
        {
            snprintf(sysname, 64, "unknown");
            bSomeError = TRUE;
        }
    }
    if (!bSomeError)
    {
        switch (osvi.dwPlatformId)
        {
        case VER_PLATFORM_WIN32_NT:
            /* Test for the product. */
            if ( osvi.dwMajorVersion <= 4 )
                snprintf(sysname, 64, "Microsoft Windows NT");
            
            if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
                snprintf(sysname, 64, "Microsoft Windows 2000");
            
            if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
                snprintf(sysname, 64, "Microsoft Windows XP");
            
            /* Test for product type. */
            
            if( bOsVersionInfoEx )
            {
                if ( osvi.wProductType == VER_NT_WORKSTATION )
                {
                    if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
                        snprintf(release, 64,  "Personal" );
                    else
                        snprintf(release, 64,  "Professional" );
                }
                
                else if ( osvi.wProductType == VER_NT_SERVER )
                {
                    if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                        snprintf(release, 64,  "DataCenter Server" );
                    else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                        snprintf(release, 64,  "Advanced Server" );
                    else
                        snprintf(release, 64,  "Server" );
                }
            }
            else
            {
                HKEY hKey;
                char szProductType[80];
                DWORD dwBufLen;
                
                RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
                    0, KEY_QUERY_VALUE, &hKey );
                RegQueryValueEx( hKey, "ProductType", NULL, NULL,
                    (LPBYTE) szProductType, &dwBufLen);
                RegCloseKey( hKey );
                if ( lstrcmpi( "WINNT", szProductType) == 0 )
                    snprintf(release, 64,  "Professional" );
                if ( lstrcmpi( "LANMANNT", szProductType) == 0 )
                    snprintf(release, 64, "Server" );
                if ( lstrcmpi( "SERVERNT", szProductType) == 0 )
                    snprintf(release, 64, "Advanced Server" );
            }
            
            /* Display version, service pack (if any), and build number. */
            
            if ( osvi.dwMajorVersion <= 4 )
            {
                snprintf(version, 64, "version %d.%d %s (Build %d)",
                    osvi.dwMajorVersion,
                    osvi.dwMinorVersion,
                    osvi.szCSDVersion,
                    osvi.dwBuildNumber & 0xFFFF);
            }
            else
            { 
                snprintf(version, 64, "%s (Build %d)",
                    osvi.szCSDVersion,
                    osvi.dwBuildNumber & 0xFFFF);
            }
            break;
            
        case VER_PLATFORM_WIN32_WINDOWS:
            
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
            {
                snprintf(sysname, 64, "Microsoft Windows 95");
                if ( osvi.szCSDVersion[1] == 'C' || osvi.szCSDVersion[1] == 'B' )
                    snprintf(release, 64, "OSR2" );
            } 
            
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
            {
                snprintf(sysname, 64, "Microsoft Windows 98");
                if ( osvi.szCSDVersion[1] == 'A' )
                    snprintf(release, 64, "SE" );
            } 
            
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
            {
                snprintf(sysname, 64, "Microsoft Windows Me");
            } 
            break;
            
        case VER_PLATFORM_WIN32s:
            
            snprintf(sysname, 64, "Microsoft Win32s");
            break;
        }
    }

    snprintf(buf, 256, "%s %s %s", sysname, release, version);
    buf[256] = '\0';
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "os", buf);

#else
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "os", "unknown");
#endif

    /* tell them */
    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
    pkt_router(pkt_tofrom(pkt));

    return mod_HANDLED;
}

static void _iq_version_free(module_t mod) {
     sm_unregister_ns(mod->mm->sm, uri_VERSION);
     feature_unregister(mod->mm->sm, uri_VERSION);
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->pkt_sm = _iq_version_pkt_sm;
    mod->free = _iq_version_free;

    ns_VERSION = sm_register_ns(mod->mm->sm, uri_VERSION);
    feature_register(mod->mm->sm, uri_VERSION);

    return 0;
}
