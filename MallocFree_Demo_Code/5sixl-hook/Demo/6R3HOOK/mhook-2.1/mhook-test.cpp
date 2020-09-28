//Copyright (c) 2007, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a 
//copy of this software and associated documentation files (the "Software"), 
//to deal in the Software without restriction, including without limitation 
//the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//and/or sell copies of the Software, and to permit persons to whom the 
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included 
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
//IN THE SOFTWARE.

#include "stdafx.h"
#include "mhook-lib/mhook.h"

//=========================================================================
// Define _NtOpenProcess so we can dynamically bind to the function
//
typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;
	DWORD_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG (WINAPI* _NtOpenProcess)(OUT PHANDLE ProcessHandle, 
	     IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, 
		 IN PCLIENT_ID ClientId ); 

//=========================================================================
// Get the current (original) address to the function to be hooked
//
_NtOpenProcess TrueNtOpenProcess = (_NtOpenProcess)
	GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");

//=========================================================================
// This is the function that will replace NtOpenProcess once the hook 
// is in place
//
ULONG WINAPI HookNtOpenProcess(OUT PHANDLE ProcessHandle, 
							   IN ACCESS_MASK AccessMask, 
							   IN PVOID ObjectAttributes, 
							   IN PCLIENT_ID ClientId)
{
	printf("***** Call to open process %d\n", ClientId->UniqueProcess);
	return TrueNtOpenProcess(ProcessHandle, AccessMask, 
		ObjectAttributes, ClientId);
}

//=========================================================================
// This is where the work gets done.
//
int wmain(int argc, WCHAR* argv[])
{
	HANDLE hProc = NULL;

	// Set the hook
	if (Mhook_SetHook((PVOID*)&TrueNtOpenProcess, HookNtOpenProcess)) {
		// Now call OpenProcess and observe NtOpenProcess being redirected
		// under the hood.
		hProc = OpenProcess(PROCESS_ALL_ACCESS, 
			FALSE, GetCurrentProcessId());
		if (hProc) {
			printf("Successfully opened self: %p\n", hProc);
			CloseHandle(hProc);
		} else {
			printf("Could not open self: %d\n", GetLastError());
		}
		// Remove the hook
		Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
	}

	// Call OpenProces again - this time there won't be a redirection as
	// the hook has bee removed.
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProc) {
		printf("Successfully opened self: %p\n", hProc);
		CloseHandle(hProc);
	} else {
		printf("Could not open self: %d\n", GetLastError());
	}
	
	return 0;
}

