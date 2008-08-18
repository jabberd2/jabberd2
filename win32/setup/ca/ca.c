#include <windows.h>

#undef RtlZeroMemory
NTSYSAPI VOID NTAPI RtlZeroMemory(VOID UNALIGNED *Destination, SIZE_T Length);

#include <msi.h>
#include <msiquery.h>

#pragma comment(linker, "/EXPORT:CheckPaths=_CheckPaths@4")

BOOL __stdcall _DllMainCRTStartup(HINSTANCE hInstance, DWORD dwReason, LPVOID lpData)
{
	return TRUE;
}

struct
{
	LPCTSTR file;
	LPCTSTR var;
} filesTest[] = {
	{"c2s.xml",				"C2S.XML.EXISTS"},
	{"resolver.xml",		"RESOLVER.XML.EXISTS"},
	{"router.xml",			"ROUTER.XML.EXISTS"},
	{"router-filter.xml",	"ROUTER_FILTER.XML.EXISTS"},
	{"router-users.xml",	"ROUTER_USERS.XML.EXISTS"},
	{"s2s.xml",				"S2S.XML.EXISTS"},
	{"sm.xml",				"SM.XML.EXISTS"},
	{"server.pem",			"SERVER.PEM.EXISTS"},
	{"sqlite.db",			"SQLITE.DB.EXISTS"},
	{NULL, NULL}
};

UINT __stdcall CheckPaths(MSIHANDLE hInstall)
{
	TCHAR installDir[MAX_PATH], filePath[MAX_PATH];
	DWORD installDirLen = MAX_PATH;
	int i;

	MsiGetProperty(hInstall, "INSTALLDIR", installDir, &installDirLen);
	installDir[installDirLen] = 0;
	for(i = 0; filesTest[i].file; i++)
	{
		WIN32_FIND_DATA fd;
		HANDLE hff;
		BOOL bFound = FALSE;

		if(installDirLen > 0 && installDirLen + lstrlen(filesTest[i].file) + 2 < MAX_PATH)
		{
			wsprintf(filePath, "%s%s%s",
				installDir,
				installDir[installDirLen - 1] == '\\' ? "" : "\\",
				filesTest[i].file);

			ZeroMemory(&fd, sizeof(fd));
			if(INVALID_HANDLE_VALUE != (hff = FindFirstFile(filePath, &fd)))
			{
				FindClose(hff);
				if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
					bFound = TRUE;
			}
		}
		MsiSetProperty(hInstall, filesTest[i].var, bFound ? filePath : "");
	}

	return ERROR_SUCCESS;
}
