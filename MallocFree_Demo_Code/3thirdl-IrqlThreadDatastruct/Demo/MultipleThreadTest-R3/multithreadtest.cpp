// multithreadtest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

CRITICAL_SECTION 	cs;//ÁÙ½çÇø
int critical_value = 0; 

ULONG WINAPI ThreadProc1(void* arg)
{
	//EnterCriticalSection(&cs);
    //for (int i = 0; i < 5; i++)
    {   
        //EnterCriticalSection(&cs);
        critical_value++;
        printf("ThreadProc1 critical_value = %d\n", critical_value);
		//LeaveCriticalSection(&cs);
     
    }
	//LeaveCriticalSection(&cs);
    return 1;
}

ULONG WINAPI ThreadProc2(void* arg)
{
	//EnterCriticalSection(&cs);
    //for (int i = 0; i < 5; i++)
    {   
       //EnterCriticalSection(&cs);
        critical_value++;
        printf("ThreadProc2 critical_value = %d\n", critical_value); 
        //LeaveCriticalSection(&cs);
    }
	//LeaveCriticalSection(&cs);
    return 1;
}



int main(int argc, char* argv[])
{


	HANDLE hArray[2] = {0};
	
    InitializeCriticalSection(&cs);
	
    hArray[0] =CreateThread(NULL,0,ThreadProc1,NULL,0,NULL);
    hArray[1]=CreateThread(NULL,0,ThreadProc2,NULL,0,NULL);
	//Sleep(1000);

	WaitForMultipleObjects(2, hArray, TRUE, INFINITE);
	//WaitForSingleObject(hArray[0], INFINITE);

    CloseHandle(hArray[0]);
    CloseHandle(hArray[1]);
	
    DeleteCriticalSection(&cs);
    return 0;

}
