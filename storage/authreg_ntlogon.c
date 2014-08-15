/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2005 Adam Strzelecki
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

/* this plugin uses NT logon LogonUser authentication */

#include "c2s.h"

#ifdef _WIN32

typedef BOOL (CALLBACK FNLOGONUSERA)(LPTSTR, LPTSTR, LPTSTR, DWORD, DWORD, PHANDLE);
FNLOGONUSERA *_LogonUserA = NULL;
HANDLE hModule = NULL;

static int _ar_ntlogon_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
	/* we can't check if a user exists, so we just assume we have them all the time */
	return 1;
}

static int _ar_ntlogon_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
	HANDLE hToken = NULL;
	if(!_LogonUserA) return 1;
	if(!_LogonUserA(username, realm, password, 
			LOGON32_LOGON_NETWORK, 
			LOGON32_PROVIDER_DEFAULT, &hToken))
	{
		log_write(ar->c2s->log, LOG_ERR, "ntlogon: user '%s', realm '%s' logon failed", username, realm);
		return 1;
	}

	log_write(ar->c2s->log, LOG_NOTICE, "ntlogon: user '%s', realm '%s' logged in", username, realm);
	CloseHandle(hToken);
	return 0;
}

static void _ar_ntlogon_free(authreg_t ar) 
{
	if(hModule) FreeLibrary(hModule);
}

/** start me up */
DLLEXPORT int ar_init(authreg_t ar)
{
	if(!(hModule = LoadLibraryA("Advapi32.dll")))
	{
		log_write(ar->c2s->log, LOG_ERR, "ntlogon: module requires Windows NT or higher OS");
		return 1;
	}

	if(!(_LogonUserA = (FNLOGONUSERA *)GetProcAddress(hModule, "LogonUserA")))
	{
		log_write(ar->c2s->log, LOG_ERR, "ntlogon: entry point for LogonUserA cannot be found");
		return 1;
	}

	ar->user_exists = _ar_ntlogon_user_exists;
	ar->check_password = _ar_ntlogon_check_password;
	ar->free = _ar_ntlogon_free;

	/* reset mechanism to digest only */
	/*
	ar->c2s->ar_mechanisms &= AR_MECH_TRAD_PLAIN;
	ar->c2s->ar_ssl_mechanisms &= AR_MECH_TRAD_PLAIN;
	*/

	log_write(ar->c2s->log, LOG_NOTICE, "ntlogon: module initialised");

	return 0;
}

#else /* _WIN32 */

DLLEXPORT int ar_init(authreg_t ar)
{
	log_write(ar->c2s->log, LOG_ERR, "ntlogon: module is not supported on non-Windows platforms");
	return 1;
}

#endif
