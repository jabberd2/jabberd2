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

typedef struct _mod_iq_version_config_st {
    char   *app_name;
    char   *app_version;
    char   *app_signature;
    char   *os_name;
    char   *os_release;
} *mod_iq_version_config_t;

static int ns_VERSION = 0;

void _iq_version_get_os_version(mod_iq_version_config_t config) {
#if defined(HAVE_UNAME)
    struct utsname un;

#elif defined(_WIN32)
    char sysname[64];
    char release[64];

    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;
    BOOL bSomeError = FALSE;

    sysname[0] = '\0';
    release[0] = '\0';
#endif

    /* figure out the os type */
#if defined(HAVE_UNAME)
    if(uname(&un) == 0) {
        config->os_name = strdup(un.sysname);
        config->os_release = strdup(un.machine);

        return;
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

    config->os_name = strdup(sysname);
    config->os_release = strdup(release);

    return;
#endif
}

static mod_ret_t _iq_version_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    mod_iq_version_config_t config = (mod_iq_version_config_t) mod->private;
    char buf[256];

    /* we only want to play with iq:version gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_VERSION)
        return mod_PASS;

    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "name", config->app_name);
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "version", config->app_version);

    /* figure out the os type */
    if(config->os_name != NULL) {
        if(config->os_release)
            snprintf(buf, 256, "%s %s", config->os_name, config->os_release);
        else
            snprintf(buf, 256, "%s", config->os_name);
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "os", buf);
    }

    /* tell them */
    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
    pkt_router(pkt_tofrom(pkt));

    return mod_HANDLED;
}

static void _iq_version_disco_extend(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    mod_iq_version_config_t config = (mod_iq_version_config_t) mod->private;
    int ns;

    log_debug(ZONE, "in mod_iq_version disco-extend");

    ns = nad_add_namespace(pkt->nad, uri_XDATA, NULL);
    /* there may be several XDATA siblings, so need to enforce the NS */
    pkt->nad->scope = ns;

    nad_append_elem(pkt->nad, ns, "x", 3);
    nad_append_attr(pkt->nad, -1, "type", "result");
    /* hidden form type field*/
    nad_append_elem(pkt->nad, -1, "field", 4);
    nad_append_attr(pkt->nad, -1, "var", "FORM_TYPE");
    nad_append_attr(pkt->nad, -1, "type", "hidden");
    nad_append_elem(pkt->nad, -1, "value", 5);
    nad_append_cdata(pkt->nad, urn_SOFTWAREINFO, strlen(urn_SOFTWAREINFO), 6);

    nad_append_elem(pkt->nad, -1, "field", 4);
    nad_append_attr(pkt->nad, -1, "var", "software");
    nad_append_elem(pkt->nad, -1, "value", 5);
    nad_append_cdata(pkt->nad, config->app_name, strlen(config->app_name), 6);

    nad_append_elem(pkt->nad, -1, "field", 4);
    nad_append_attr(pkt->nad, -1, "var", "software_version");
    nad_append_elem(pkt->nad, -1, "value", 5);
    nad_append_cdata(pkt->nad, config->app_version, strlen(config->app_version), 6);

    if(config->os_name != NULL) {
        nad_append_elem(pkt->nad, -1, "field", 4);
        nad_append_attr(pkt->nad, -1, "var", "os");
        nad_append_elem(pkt->nad, -1, "value", 5);
        nad_append_cdata(pkt->nad, config->os_name, strlen(config->os_name), 6);
    }

    if(config->os_name != NULL) {
        nad_append_elem(pkt->nad, -1, "field", 4);
        nad_append_attr(pkt->nad, -1, "var", "os_version");
        nad_append_elem(pkt->nad, -1, "value", 5);
        nad_append_cdata(pkt->nad, config->os_release, strlen(config->os_release), 6);
    }
}

static void _iq_version_free(module_t mod) {
    mod_iq_version_config_t config = (mod_iq_version_config_t) mod->private;

    sm_unregister_ns(mod->mm->sm, uri_VERSION);
    feature_unregister(mod->mm->sm, uri_VERSION);

    if(config->os_name != NULL) free(config->os_name);
    if(config->os_release != NULL) free(config->os_release);

    free(config);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    mod_iq_version_config_t config;
    module_t mod = mi->mod;

    if(mod->init) return 0;

    config = (mod_iq_version_config_t) calloc(1, sizeof(struct _mod_iq_version_config_st));
    config->app_name = PACKAGE;
    config->app_version = VERSION;
    config->app_signature = mi->sm->signature;
    _iq_version_get_os_version(config);

    mod->private = config;    

    mod->pkt_sm = _iq_version_pkt_sm;
    mod->disco_extend = _iq_version_disco_extend;
    mod->free = _iq_version_free;

    ns_VERSION = sm_register_ns(mod->mm->sm, uri_VERSION);
    feature_register(mod->mm->sm, uri_VERSION);

    return 0;
}
