// firtDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "firtDll.h"

#pragma data_seg("Shared") //������ΪShared�����ݶ�
int a = 0; //���ݶ�Shared�еı���a���˴�a������г�ʼ��
#pragma data_seg()

#pragma comment(linker, "/SECTION:Shared,RWS") //Ϊ���ݶ�Sharedָ������д���������ԡ�

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
FIRTDLL_API int nFirtDll=0; //��ͨȫ�ֱ���

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

