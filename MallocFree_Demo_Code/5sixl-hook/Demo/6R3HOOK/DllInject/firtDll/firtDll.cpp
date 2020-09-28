// firtDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "firtDll.h"

#pragma data_seg("Shared") //创建名为Shared的数据段
int a = 0; //数据段Shared中的变量a，此处a必须进行初始化
#pragma data_seg()

#pragma comment(linker, "/SECTION:Shared,RWS") //为数据段Shared指定读，写及共享属性。

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}


// This is an example of an exported variable
FIRTDLL_API int nFirtDll=0; //普通全局变量

// This is an example of an exported function.
FIRTDLL_API int fnFirtDll(void)
{
	MessageBox(NULL, "HI", "HI", MB_OK);
	return 42;
}

// This is the constructor of a class that has been exported.
// see firtDll.h for the class definition
CFirtDll::CFirtDll()
{ 
	return; 
}

