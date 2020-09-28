#include "precomp.h"

#define MAX_PROCESS_NO		1024


ULONG g_PIDProtectArray[MAX_PROCESS_NO];

ULONG g_currProtectPostion = 0;

ULONG ValidateProcessNeedProtect(ULONG uPID)
{
	ULONG i = 0;
	
	if(uPID == 0)
	{
		return -1;
	}
	
	for(i=0; i<g_currProtectPostion && i<MAX_PROCESS_NO;i++)
	{
		if(g_PIDProtectArray[i] == uPID)
		{
			return i;
		}
	}
	return -1;
}


ULONG InsertProtectProcess(ULONG uPID)
{
	if(ValidateProcessNeedProtect(uPID) == -1 && g_currProtectPostion < MAX_PROCESS_NO)
	{
		g_PIDProtectArray[g_currProtectPostion++] = uPID;

		return TRUE;
	}
	return FALSE;
}

ULONG RemoveProtectProcess(ULONG uPID)
{
	ULONG uIndex = ValidateProcessNeedProtect(uPID);
	if(uIndex != -1)
	{
		g_PIDProtectArray[uIndex] = g_PIDProtectArray[g_currProtectPostion--];
		
		return TRUE;
	}
	return FALSE;
}
