// keyboardhook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include<iostream>
#include<windows.h>
using namespace std;

HHOOK g_Hook;
LRESULT CALLBACK LowLevelKeyboardProc(INT nCode, WPARAM wParam, LPARAM lParam)
{
	KBDLLHOOKSTRUCT *pkbhs = (KBDLLHOOKSTRUCT *)lParam;
	BOOL bControlKeyDown = 0;
	
    switch (nCode)
	{
	case HC_ACTION:
		{
			// Check to see if the CTRL key is pressed
			bControlKeyDown = GetAsyncKeyState (VK_CONTROL) >> ((sizeof(SHORT) * 8) - 1);

			//Disable CTRL+ESC
			if (pkbhs->vkCode == VK_ESCAPE && bControlKeyDown)
				return 1;
			if(wParam == WM_KEYUP)
				printf("%c", pkbhs->vkCode);

			break;
		}
	}
	return CallNextHookEx(g_Hook, nCode, wParam, lParam); //»Øµ÷
	//return 1;
}


int _tmain(int argc, _TCHAR* argv[])
{
	MSG msg;
	g_Hook=(HHOOK)SetWindowsHookEx(WH_KEYBOARD_LL,
		(HOOKPROC)LowLevelKeyboardProc, GetModuleHandleW(0),0); 
	while(GetMessageW(&msg,0,0,0))DispatchMessageW(&msg);
	return 0;
}
