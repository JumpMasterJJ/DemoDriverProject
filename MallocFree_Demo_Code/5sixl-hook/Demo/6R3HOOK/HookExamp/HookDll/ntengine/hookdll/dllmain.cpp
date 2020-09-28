// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>

BOOL (__cdecl *HookFunction)(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction);
VOID (__cdecl *UnhookFunction)(ULONG_PTR Function);
ULONG_PTR (__cdecl *GetOriginalFunction)(ULONG_PTR Hook);

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
						 UINT uType, WORD wLanguageId, DWORD dwMilliseconds);

typedef DWORD (WINAPI *CREATPROCESSW)(
									  LPCWSTR lpApplicationName,
									  LPWSTR lpCommandLine, 
									  LPSECURITY_ATTRIBUTES lpProcessAttributes,
									  LPSECURITY_ATTRIBUTES lpThreadAttributes,
									  BOOL bInheritHandles,
									  DWORD dwCreationFlags,
									  LPVOID lpEnvironment,
									  LPCWSTR lpCurrentDirectory,
									  LPSTARTUPINFOW lpStartupInfo,
									  LPPROCESS_INFORMATION lpProcessInformation
									  );

typedef DWORD (WINAPI *CREATPROCESSA)(
									  LPCSTR lpApplicationName,
									  LPSTR lpCommandLine, 
									  LPSECURITY_ATTRIBUTES lpProcessAttributes,
									  LPSECURITY_ATTRIBUTES lpThreadAttributes,
									  BOOL bInheritHandles,
									  DWORD dwCreationFlags,
									  LPVOID lpEnvironment,
									  LPCSTR lpCurrentDirectory,
									  LPSTARTUPINFO lpStartupInfo,
									  LPPROCESS_INFORMATION lpProcessInformation
									  );

typedef int (WINAPI *MESSAGEBOXW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
						 UINT uType, WORD wLanguageId, DWORD dwMilliseconds);

CREATPROCESSW OldCreateProcessW = NULL;
CREATPROCESSA OldCreateProcessA = NULL;
MESSAGEBOXW OldMessageBoxW = NULL;

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType,
						 WORD wLanguageId, DWORD dwMilliseconds)
{
	return OldMessageBoxW(hWnd, lpText, L"Hooked MessageBox",
		uType, wLanguageId, dwMilliseconds);
}


DWORD WINAPI myCreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine, 
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{

	WCHAR wszInfo[2*MAX_PATH] = {0};

	_stprintf_s(wszInfo,sizeof(wszInfo)/sizeof(WCHAR),  _T("将要创建进程：%s,阻止吗？"), lpApplicationName);
	if (MessageBoxW(NULL, wszInfo, lpApplicationName, MB_YESNO)==IDYES)
	{
		return FALSE;
	}

	return OldCreateProcessW(lpApplicationName,
		lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

}

DWORD WINAPI myCreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine, 
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	CHAR szInfo[2*MAX_PATH] = {0};

	sprintf_s(szInfo, sizeof(szInfo), ("将要创建进程：%s,阻止吗？"), lpApplicationName);
	if (MessageBoxA(NULL, lpApplicationName, lpApplicationName, MB_YESNO)==IDYES)
	{
		return FALSE;
	}

	return OldCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

}


VOID HookIt(VOID)
{
	HMODULE hHookEngineDll = LoadLibrary(_T("NtHookEngine.dll"));

	HookFunction = (BOOL (__cdecl *)(ULONG_PTR, ULONG_PTR))
		GetProcAddress(hHookEngineDll, "HookFunction");

	UnhookFunction = (VOID (__cdecl *)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "UnhookFunction");

	GetOriginalFunction = (ULONG_PTR (__cdecl *)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "GetOriginalFunction");

	if (HookFunction == NULL || UnhookFunction == NULL || 
		GetOriginalFunction == NULL)
		return;

	//
	// Hook ALL the apis you want here
	//

	HookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("User32.dll")),
		"MessageBoxTimeoutW"), 
		(ULONG_PTR) &MyMessageBoxW);
	HookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")),
		"CreateProcessA"), 
		(ULONG_PTR) &myCreateProcessA);

	HookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")),
		"CreateProcessW"), 
		(ULONG_PTR) &myCreateProcessW);

	// save the original api address

	OldCreateProcessW = (CREATPROCESSW) GetOriginalFunction((ULONG_PTR) myCreateProcessW);
	OldCreateProcessA = (CREATPROCESSA) GetOriginalFunction((ULONG_PTR) myCreateProcessA);
	OldMessageBoxW = (MESSAGEBOXW)GetOriginalFunction((ULONG_PTR) MyMessageBoxW);


}
VOID UnHook()
{
	UnhookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("User32.dll")), 
		"MessageBoxTimeoutW"));
	UnhookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")), 
		"CreateProcessA"));
	UnhookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")), 
		"CreateProcessW"));
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
		HookIt();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//UnHook();
		break;
	}
	return TRUE;
}

