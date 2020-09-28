/***************************************************************
Module name: LibSpyDll.cpp
Copyright (c) 2003 Robert Kuster

Notice:	If this code works, it was written by Robert Kuster.
		Else, I don't know who wrote it.

		Use it on your own risk. No responsibilities for
		possible damages of even functionality can be taken.
***************************************************************/

#include <windows.h>
#include "LibSpyDll.h"

//-------------------------------------------------------
// shared data 
// Notice:	seen by both: the instance of "LibSpy.dll" mapped
//			into the remote process as well as by the instance
//			mapped into our "LibSpy.exe"
#pragma data_seg (".shared")
HWND	g_hPwdEdit = 0;
char	g_szPassword [128] = { '\0' };
#pragma data_seg ()

#pragma comment(linker,"/SECTION:.shared,RWS") 


//-------------------------------------------------------
// DllMain
// Notice: retrieves the password, when mapped into the 
//		   remote process (g_hPwdEdit != 0);
//
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{	
	if( (ul_reason_for_call == DLL_PROCESS_ATTACH) && g_hPwdEdit ) {
		::MessageBeep(MB_OK);
		::SendMessage( g_hPwdEdit,WM_GETTEXT,128,(LPARAM)g_szPassword );
	}
		
    return TRUE;
}

