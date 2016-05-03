/*
 * A compatible implementation of signal which relies of sigaction.
 * More or less taken from teh Stevens book.
 */

#include <signal.h>
#include "util.h"

#ifdef _WIN32
/* Those routines define Windows jabberd2 services */

#include <windows.h>
#include <winsvc.h>
#include <time.h>

SERVICE_STATUS jabber_service_status;
SERVICE_STATUS_HANDLE jabber_service_status_handle;

LPCTSTR jabber_service_name = NULL;
LPCTSTR jabber_service_display = NULL;
LPCTSTR jabber_service_description = NULL;
LPCTSTR jabber_service_depends = NULL;
jmainhandler_t *jabber_service_wrapper = NULL;

void WINAPI jabber_service_main(DWORD argc, LPTSTR *argv);
void WINAPI jabber_service_ctrl_handler(DWORD Opcode);
BOOL jabber_install_service();
BOOL jabber_delete_service();

jsighandler_t *jabber_term_handler = NULL;
#endif /* _WIN32 */

jsighandler_t* jabber_signal(int signo, jsighandler_t *func)
{
#ifdef _WIN32
    if(signo == SIGTERM) jabber_term_handler = func;
    return NULL;
#else
    struct sigaction act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef SA_RESTART
    if (signo != SIGALRM)
        act.sa_flags |= SA_RESTART;
#endif
    if (sigaction(signo, &act, &oact) < 0)
        return (SIG_ERR);
    return (oact.sa_handler);
#endif
}


#ifdef _WIN32
BOOL WINAPI jabber_ctrl_handler(DWORD dwCtrlType)
{
    if(jabber_term_handler) jabber_term_handler(0);
    return TRUE;
}

int jabber_wrap_service(int argc, char** argv, jmainhandler_t *wrapper, LPCTSTR name, LPCTSTR display, LPCTSTR description, LPCTSTR depends)
{
    jabber_service_wrapper = wrapper;
    jabber_service_name = name;
    jabber_service_display = display;
    jabber_service_description = description;
    jabber_service_depends = depends;

    if((argc == 2) && !strcmp(argv[1], "-I"))
    {
        // Jabber service installation requested
        if(jabber_install_service())
            printf("Service %s installed sucessfully.\n", jabber_service_name);
        else
            printf("Error installing service %s.\n", jabber_service_name);
        return 0;
    }
    if((argc == 2) && !strcmp(argv[1], "-U"))
    {
        // Jabber service removal requested
        if(jabber_delete_service())
            printf("Service %s uninstalled sucessfully.\n", jabber_service_name);
        else
            printf("Error uninstalling service %s.\n", jabber_service_name);
        return 0;
    }
    if((argc == 2) && !strcmp(argv[1], "-S"))
    {
        TCHAR szPathName[MAX_PATH]; LPTSTR slash = NULL;
        SERVICE_TABLE_ENTRY DispatchTable[] = {{(LPTSTR)jabber_service_name, jabber_service_main}, {NULL, NULL}};

        GetModuleFileName(NULL, szPathName, sizeof(szPathName));

        // Set working directory to the service path
        if(slash = strrchr(szPathName, '\\'))
        {
            *slash = 0;
            SetCurrentDirectory(szPathName);
        }

        // Run service dispatcher
        StartServiceCtrlDispatcher(DispatchTable);
        return 0;
    }
    // If we are not in the service, register console handle for shutdown
    SetConsoleCtrlHandler(jabber_ctrl_handler, TRUE);

    // Wrap original main function
    if(jabber_service_wrapper) return jabber_service_wrapper(argc, argv);
    return 0;
}


void WINAPI jabber_service_main(DWORD argc, LPTSTR *argv)
{
    jabber_service_status.dwServiceType        = SERVICE_WIN32;
    jabber_service_status.dwCurrentState       = SERVICE_START_PENDING;
    jabber_service_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP;
    jabber_service_status.dwWin32ExitCode      = 0;
    jabber_service_status.dwServiceSpecificExitCode = 0;
    jabber_service_status.dwCheckPoint         = 0;
    jabber_service_status.dwWaitHint           = 0;

    jabber_service_status_handle = RegisterServiceCtrlHandler(jabber_service_name, jabber_service_ctrl_handler);
    if (jabber_service_status_handle == (SERVICE_STATUS_HANDLE)0)
        return;

    jabber_service_status.dwCurrentState       = SERVICE_RUNNING;
    jabber_service_status.dwCheckPoint         = 0;
    jabber_service_status.dwWaitHint           = 0;
    SetServiceStatus(jabber_service_status_handle, &jabber_service_status);

    if(jabber_service_wrapper) jabber_service_wrapper(argc, argv);

    jabber_service_status.dwWin32ExitCode      = 0;
    jabber_service_status.dwCurrentState       = SERVICE_STOPPED;
    jabber_service_status.dwCheckPoint         = 0;
    jabber_service_status.dwWaitHint           = 0;
    SetServiceStatus(jabber_service_status_handle, &jabber_service_status);

    return;
}

void WINAPI jabber_service_ctrl_handler(DWORD Opcode)
{
    switch(Opcode)
    {
        case SERVICE_CONTROL_PAUSE:
            jabber_service_status.dwCurrentState = SERVICE_PAUSED;
            break;

        case SERVICE_CONTROL_CONTINUE:
            jabber_service_status.dwCurrentState = SERVICE_RUNNING;
            break;

        case SERVICE_CONTROL_STOP:
            jabber_service_status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(jabber_service_status_handle, &jabber_service_status);

            // Call int signal
            if(jabber_term_handler) jabber_term_handler(0);
            break;

        case SERVICE_CONTROL_INTERROGATE:
            break;
    }
    return;
}

BOOL jabber_install_service()
{

    TCHAR szPathName[MAX_PATH];
    TCHAR szCmd[MAX_PATH + 16];
    HANDLE schSCManager, schService;
    SERVICE_DESCRIPTION sdServiceDescription = { jabber_service_description };

    GetModuleFileName(NULL, szPathName, sizeof(szPathName));
    sprintf(szCmd, "\"%s\" -S", szPathName);

    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (schSCManager == NULL)
        return FALSE;

    schService = CreateService(schSCManager,
        jabber_service_name,       // service name (alias)
        jabber_service_display,    // service name to display
        SERVICE_ALL_ACCESS,        // desired access
        SERVICE_WIN32_OWN_PROCESS, // service type
        SERVICE_AUTO_START,        // start type
        SERVICE_ERROR_NORMAL,      // error control type
        szCmd,                     // service's binary
        NULL,                      // no load ordering group
        NULL,                      // no tag identifier
        jabber_service_depends,    // dependencies
        NULL,                      // LocalSystem account
        NULL);                     // no password

    if (schService == NULL)
        return FALSE;

    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&sdServiceDescription);

    CloseServiceHandle(schService);

    return TRUE;
}

BOOL jabber_delete_service()
{
    HANDLE schSCManager;
    SC_HANDLE hService;

    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

    if (schSCManager == NULL)
        return FALSE;

    hService=OpenService(schSCManager, jabber_service_name, SERVICE_ALL_ACCESS);

    if (hService == NULL)
        return FALSE;

    if(DeleteService(hService)==0)
        return FALSE;

    if(CloseServiceHandle(hService)==0)
        return FALSE;
    else
        return TRUE;
}
#endif /* _WIN32 */
