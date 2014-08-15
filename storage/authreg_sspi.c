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

/* this plugin uses SSPI for Windows authentication */

#include "c2s.h"

#ifdef _WIN32

#define SECURITY_WIN32
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <sspi.h>

// Older versions of WinError.h does not have SEC_I_COMPLETE_NEEDED #define.
// So, in such SDK environment setup, we will include issperr.h which has the
// definition for SEC_I_COMPLETE_NEEDED. Include issperr.h only if
// SEC_I_COMPLETE_NEEDED is not defined.
#ifndef SEC_I_COMPLETE_NEEDED
#include <issperr.h>
#endif

typedef struct _AUTH_SEQ {
   BOOL fInitialized;
   BOOL fHaveCredHandle;
   BOOL fHaveCtxtHandle;
   CredHandle hcred;
   struct _SecHandle hctxt;
} AUTH_SEQ, *PAUTH_SEQ;


// Function pointers
ACCEPT_SECURITY_CONTEXT_FN       _AcceptSecurityContext     = NULL;
ACQUIRE_CREDENTIALS_HANDLE_FN    _AcquireCredentialsHandle  = NULL;
COMPLETE_AUTH_TOKEN_FN           _CompleteAuthToken         = NULL;
DELETE_SECURITY_CONTEXT_FN       _DeleteSecurityContext     = NULL;
FREE_CONTEXT_BUFFER_FN           _FreeContextBuffer         = NULL;
FREE_CREDENTIALS_HANDLE_FN       _FreeCredentialsHandle     = NULL;
INITIALIZE_SECURITY_CONTEXT_FN   _InitializeSecurityContext = NULL;
QUERY_SECURITY_PACKAGE_INFO_FN   _QuerySecurityPackageInfo  = NULL;


///////////////////////////////////////////////////////////////////////////////


void UnloadSecurityDll(HMODULE hModule) {

   if (hModule)
      FreeLibrary(hModule);

   _AcceptSecurityContext      = NULL;
   _AcquireCredentialsHandle   = NULL;
   _CompleteAuthToken          = NULL;
   _DeleteSecurityContext      = NULL;
   _FreeContextBuffer          = NULL;
   _FreeCredentialsHandle      = NULL;
   _InitializeSecurityContext  = NULL;
   _QuerySecurityPackageInfo   = NULL;
}


///////////////////////////////////////////////////////////////////////////////


HMODULE LoadSecurityDll() {

   HMODULE hModule;
   BOOL    fAllFunctionsLoaded = FALSE;
   TCHAR   lpszDLL[MAX_PATH];
   OSVERSIONINFO VerInfo;

   //
   //  Find out which security DLL to use, depending on
   //  whether we are on NT or Win95 or 2000 or XP or Windows Server 2003
   //  We have to use security.dll on Windows NT 4.0.
   //  All other operating systems, we have to use Secur32.dll
   //
   VerInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
   if (!GetVersionEx (&VerInfo))   // If this fails, something has gone wrong
   {
      return FALSE;
   }

   if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
      VerInfo.dwMajorVersion == 4 &&
      VerInfo.dwMinorVersion == 0)
   {
      lstrcpy (lpszDLL, _T("security.dll"));
   }
   else
   {
      lstrcpy (lpszDLL, _T("secur32.dll"));
   }


   hModule = LoadLibrary(lpszDLL);
   if (!hModule)
      return NULL;

   __try {

      _AcceptSecurityContext = (ACCEPT_SECURITY_CONTEXT_FN)
            GetProcAddress(hModule, "AcceptSecurityContext");
      if (!_AcceptSecurityContext)
         __leave;

#ifdef UNICODE
      _AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
            GetProcAddress(hModule, "AcquireCredentialsHandleW");
#else
      _AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
            GetProcAddress(hModule, "AcquireCredentialsHandleA");
#endif
      if (!_AcquireCredentialsHandle)
         __leave;

      // CompleteAuthToken is not present on Windows 9x Secur32.dll
      // Do not check for the availablity of the function if it is NULL;
      _CompleteAuthToken = (COMPLETE_AUTH_TOKEN_FN)
            GetProcAddress(hModule, "CompleteAuthToken");

      _DeleteSecurityContext = (DELETE_SECURITY_CONTEXT_FN)
            GetProcAddress(hModule, "DeleteSecurityContext");
      if (!_DeleteSecurityContext)
         __leave;

      _FreeContextBuffer = (FREE_CONTEXT_BUFFER_FN)
            GetProcAddress(hModule, "FreeContextBuffer");
      if (!_FreeContextBuffer)
         __leave;

      _FreeCredentialsHandle = (FREE_CREDENTIALS_HANDLE_FN)
            GetProcAddress(hModule, "FreeCredentialsHandle");
      if (!_FreeCredentialsHandle)
         __leave;

#ifdef UNICODE
      _InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
            GetProcAddress(hModule, "InitializeSecurityContextW");
#else
      _InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
            GetProcAddress(hModule, "InitializeSecurityContextA");
#endif
      if (!_InitializeSecurityContext)
         __leave;

#ifdef UNICODE
      _QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
            GetProcAddress(hModule, "QuerySecurityPackageInfoW");
#else
      _QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
            GetProcAddress(hModule, "QuerySecurityPackageInfoA");
#endif
      if (!_QuerySecurityPackageInfo)
         __leave;

      fAllFunctionsLoaded = TRUE;

   } __finally {

      if (!fAllFunctionsLoaded) {
         UnloadSecurityDll(hModule);
         hModule = NULL;
      }

   }

   return hModule;
}


///////////////////////////////////////////////////////////////////////////////


BOOL GenClientContext(authreg_t ar, PAUTH_SEQ pAS, PSEC_WINNT_AUTH_IDENTITY pAuthIdentity,
      PVOID pIn, DWORD cbIn, PVOID pOut, PDWORD pcbOut, PBOOL pfDone) {

/*++

 Routine Description:

   Optionally takes an input buffer coming from the server and returns
   a buffer of information to send back to the server.  Also returns
   an indication of whether or not the context is complete.

 Return Value:

   Returns TRUE if successful; otherwise FALSE.

--*/

   SECURITY_STATUS ss;
   TimeStamp       tsExpiry;
   SecBufferDesc   sbdOut;
   SecBuffer       sbOut;
   SecBufferDesc   sbdIn;
   SecBuffer       sbIn;
   ULONG           fContextAttr;

   if (!pAS->fInitialized) {

      ss = _AcquireCredentialsHandle(NULL, _T("NTLM"),
            SECPKG_CRED_OUTBOUND, NULL, pAuthIdentity, NULL, NULL,
            &pAS->hcred, &tsExpiry);
      if (ss < 0) {
         log_write(ar->c2s->log, LOG_ERR, "sspi: AcquireCredentialsHandle failed with %08X", ss);
         return FALSE;
      }

      pAS->fHaveCredHandle = TRUE;
   }

   // Prepare output buffer
   sbdOut.ulVersion = 0;
   sbdOut.cBuffers = 1;
   sbdOut.pBuffers = &sbOut;

   sbOut.cbBuffer = *pcbOut;
   sbOut.BufferType = SECBUFFER_TOKEN;
   sbOut.pvBuffer = pOut;

   // Prepare input buffer
   if (pAS->fInitialized)  {
      sbdIn.ulVersion = 0;
      sbdIn.cBuffers = 1;
      sbdIn.pBuffers = &sbIn;

      sbIn.cbBuffer = cbIn;
      sbIn.BufferType = SECBUFFER_TOKEN;
      sbIn.pvBuffer = pIn;
   }

   ss = _InitializeSecurityContext(&pAS->hcred,
         pAS->fInitialized ? &pAS->hctxt : NULL, NULL, 0, 0,
         SECURITY_NATIVE_DREP, pAS->fInitialized ? &sbdIn : NULL,
         0, &pAS->hctxt, &sbdOut, &fContextAttr, &tsExpiry);
   if (ss < 0)  {
      // <winerror.h>
      log_write(ar->c2s->log, LOG_ERR, "sspi: InitializeSecurityContext failed with %08X", ss);
      return FALSE;
   }

   pAS->fHaveCtxtHandle = TRUE;

   // If necessary, complete token
   if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {

      if (_CompleteAuthToken) {
         ss = _CompleteAuthToken(&pAS->hctxt, &sbdOut);
         if (ss < 0)  {
            log_write(ar->c2s->log, LOG_ERR, "sspi: CompleteAuthToken failed with %08X", ss);
            return FALSE;
         }
      }
      else {
         log_write(ar->c2s->log, LOG_ERR, "sspi: CompleteAuthToken not supported");
         return FALSE;
      }
   }

   *pcbOut = sbOut.cbBuffer;

   if (!pAS->fInitialized)
      pAS->fInitialized = TRUE;

   *pfDone = !(ss == SEC_I_CONTINUE_NEEDED
         || ss == SEC_I_COMPLETE_AND_CONTINUE );

   return TRUE;
}


///////////////////////////////////////////////////////////////////////////////


BOOL GenServerContext(authreg_t ar, PAUTH_SEQ pAS, PVOID pIn, DWORD cbIn, PVOID pOut,
      PDWORD pcbOut, PBOOL pfDone) {

/*++

 Routine Description:

    Takes an input buffer coming from the client and returns a buffer
    to be sent to the client.  Also returns an indication of whether or
    not the context is complete.

 Return Value:

    Returns TRUE if successful; otherwise FALSE.

--*/

   SECURITY_STATUS ss;
   TimeStamp       tsExpiry;
   SecBufferDesc   sbdOut;
   SecBuffer       sbOut;
   SecBufferDesc   sbdIn;
   SecBuffer       sbIn;
   ULONG           fContextAttr;

   if (!pAS->fInitialized)  {

      ss = _AcquireCredentialsHandle(NULL, _T("NTLM"),
            SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &pAS->hcred,
            &tsExpiry);
      if (ss < 0) {
         log_write(ar->c2s->log, LOG_ERR, "sspi: AcquireCredentialsHandle failed with %08X", ss);
         return FALSE;
      }

      pAS->fHaveCredHandle = TRUE;
   }

   // Prepare output buffer
   sbdOut.ulVersion = 0;
   sbdOut.cBuffers = 1;
   sbdOut.pBuffers = &sbOut;

   sbOut.cbBuffer = *pcbOut;
   sbOut.BufferType = SECBUFFER_TOKEN;
   sbOut.pvBuffer = pOut;

   // Prepare input buffer
   sbdIn.ulVersion = 0;
   sbdIn.cBuffers = 1;
   sbdIn.pBuffers = &sbIn;

   sbIn.cbBuffer = cbIn;
   sbIn.BufferType = SECBUFFER_TOKEN;
   sbIn.pvBuffer = pIn;

   ss = _AcceptSecurityContext(&pAS->hcred,
         pAS->fInitialized ? &pAS->hctxt : NULL, &sbdIn, 0,
         SECURITY_NATIVE_DREP, &pAS->hctxt, &sbdOut, &fContextAttr,
         &tsExpiry);
   if (ss < 0)  {
      log_write(ar->c2s->log, LOG_ERR, "sspi: AcceptSecurityContext failed with %08X", ss);
      return FALSE;
   }

   pAS->fHaveCtxtHandle = TRUE;

   // If necessary, complete token
   if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {

      if (_CompleteAuthToken) {
         ss = _CompleteAuthToken(&pAS->hctxt, &sbdOut);
         if (ss < 0)  {
            log_write(ar->c2s->log, LOG_ERR, "sspi: CompleteAuthToken failed with %08X", ss);
            return FALSE;
         }
      }
      else {
         log_write(ar->c2s->log, LOG_ERR, "sspi: CompleteAuthToken not supported");
         return FALSE;
      }
   }

   *pcbOut = sbOut.cbBuffer;

   if (!pAS->fInitialized)
      pAS->fInitialized = TRUE;

   *pfDone = !(ss = SEC_I_CONTINUE_NEEDED
         || ss == SEC_I_COMPLETE_AND_CONTINUE);

   return TRUE;
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI SSPLogonUser(authreg_t ar, LPTSTR szDomain, LPTSTR szUser, LPTSTR szPassword) {

   AUTH_SEQ    asServer   = {0};
   AUTH_SEQ    asClient   = {0};
   BOOL        fDone      = FALSE;
   BOOL        fResult    = FALSE;
   DWORD       cbOut      = 0;
   DWORD       cbIn       = 0;
   DWORD       cbMaxToken = 0;
   PVOID       pClientBuf = NULL;
   PVOID       pServerBuf = NULL;
   PSecPkgInfo pSPI       = NULL;
   HMODULE     hModule    = NULL;

   SEC_WINNT_AUTH_IDENTITY ai;

   __try {

      hModule = LoadSecurityDll();
      if (!hModule)
         __leave;

      // Get max token size
      _QuerySecurityPackageInfo(_T("NTLM"), &pSPI);
      cbMaxToken = pSPI->cbMaxToken;
      _FreeContextBuffer(pSPI);

      // Allocate buffers for client and server messages
      pClientBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbMaxToken);
      pServerBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbMaxToken);

      // Initialize auth identity structure
      ZeroMemory(&ai, sizeof(ai));
#if defined(UNICODE) || defined(_UNICODE)
      ai.Domain = szDomain;
      ai.DomainLength = lstrlen(szDomain);
      ai.User = szUser;
      ai.UserLength = lstrlen(szUser);
      ai.Password = szPassword;
      ai.PasswordLength = lstrlen(szPassword);
      ai.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
      ai.Domain = (unsigned char *)szDomain;
      ai.DomainLength = lstrlen(szDomain);
      ai.User = (unsigned char *)szUser;
      ai.UserLength = lstrlen(szUser);
      ai.Password = (unsigned char *)szPassword;
      ai.PasswordLength = lstrlen(szPassword);
      ai.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif

      // Prepare client message (negotiate) .
      cbOut = cbMaxToken;
      if (!GenClientContext(ar, &asClient, &ai, NULL, 0, pClientBuf, &cbOut, &fDone))
         __leave;

      // Prepare server message (challenge) .
      cbIn = cbOut;
      cbOut = cbMaxToken;
      if (!GenServerContext(ar, &asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
            &fDone))
         __leave;
         // Most likely failure: AcceptServerContext fails with SEC_E_LOGON_DENIED
         // in the case of bad szUser or szPassword.
         // Unexpected Result: Logon will succeed if you pass in a bad szUser and
         // the guest account is enabled in the specified domain.

      // Prepare client message (authenticate) .
      cbIn = cbOut;
      cbOut = cbMaxToken;
      if (!GenClientContext(ar, &asClient, &ai, pServerBuf, cbIn, pClientBuf, &cbOut,
            &fDone))
         __leave;

      // Prepare server message (authentication) .
      cbIn = cbOut;
      cbOut = cbMaxToken;
      if (!GenServerContext(ar, &asServer, pClientBuf, cbIn, pServerBuf, &cbOut,
            &fDone))
         __leave;

      fResult = TRUE;

   } __finally {

      // Clean up resources
      if (asClient.fHaveCtxtHandle)
         _DeleteSecurityContext(&asClient.hctxt);

      if (asClient.fHaveCredHandle)
         _FreeCredentialsHandle(&asClient.hcred);

      if (asServer.fHaveCtxtHandle)
         _DeleteSecurityContext(&asServer.hctxt);

      if (asServer.fHaveCredHandle)
         _FreeCredentialsHandle(&asServer.hcred);

      if (hModule)
         UnloadSecurityDll(hModule);

      HeapFree(GetProcessHeap(), 0, pClientBuf);
      HeapFree(GetProcessHeap(), 0, pServerBuf);

   }

   return fResult;
}

///////////////////////////////////////////////////////////////////////////////
// Main jabber wrapper functions

static int _ar_sspi_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
	/* we can't check if a user exists, so we just assume we have them all the time */
	return 1;
}

static int _ar_sspi_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
	return !SSPLogonUser(ar, realm ? realm : "localhost", username, password);
}

/** start me up */
DLLEXPORT int ar_init(authreg_t ar)
{
	ar->user_exists = _ar_sspi_user_exists;
	ar->check_password = _ar_sspi_check_password;

	return 0;
}

#else /* _WIN32 */

DLLEXPORT int ar_init(authreg_t ar)
{
	log_write(ar->c2s->log, LOG_ERR, "sspi: module is not supported on non-Windows platforms");
	return 1;
}

#endif
