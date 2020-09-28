// mousehook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#include<iostream>
#include<windows.h>
using namespace std;

/* LPARAM type
typedef struct tagMSLLHOOKSTRUCT {
  POINT     pt;
  DWORD     mouseData;
  DWORD     flags;
  DWORD     time;
  ULONG_PTR dwExtraInfo;
} MSLLHOOKSTRUCT, *PMSLLHOOKSTRUCT, *LPMSLLHOOKSTRUCT;
*/



LRESULT CALLBACK LowLevelMouseProc(
								   int nCode,
								   WPARAM wParam,
								   LPARAM lParam
								   )
{
	if(nCode==HC_ACTION)
	{
		if(wParam==WM_LBUTTONDOWN)
		{
			return 1;
		}
	}
	return CallNextHookEx(0,nCode,wParam,lParam);
}

int _tmain(int argc, _TCHAR* argv[])
{
	MSG msg;
	SetWindowsHookExW(WH_MOUSE_LL,LowLevelMouseProc,GetModuleHandleW(0),0);
	while(GetMessageW(&msg,0,0,0))DispatchMessageW(&msg);
	return 0;
}
