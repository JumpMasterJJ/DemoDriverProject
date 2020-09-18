#include <ntddk.h>

ULONG	g_ulTotal = 0;
ULONG	g_ulAnother = 10;
FAST_MUTEX g_anLock;
FAST_MUTEX g_fmLock;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye, driver\n");
}

VOID ThreadProc1(IN PVOID pContext)
{
	ULONG i = 1000;
	//while(i > 0)
	{
		ExAcquireFastMutex(&g_fmLock);
		ExAcquireFastMutex(&g_anLock);

	

		g_ulTotal++;
		g_ulAnother--;
		DbgPrint("ThreadProc1 g_ulTotal:%x, g_ulAnother:%x\n", g_ulTotal, g_ulAnother);
				
		ExReleaseFastMutex(&g_anLock);
		ExReleaseFastMutex(&g_fmLock);
		


		i--;
		
	}

}

VOID ThreadProc2(IN PVOID pContext)
{
	ULONG i = 1000;
	//while(i > 0)
	{
		ExAcquireFastMutex(&g_anLock);
		ExAcquireFastMutex(&g_fmLock);

		g_ulTotal++;
		g_ulAnother--;
		DbgPrint("ThreadProc2 g_ulTotal:%x, g_ulAnother:%x\n", g_ulTotal, g_ulAnother);

		ExReleaseFastMutex(&g_fmLock);
		ExReleaseFastMutex(&g_anLock);
		i--;
	}

	
}

void StartThreads()
{
	HANDLE hThread1 	 = NULL;
	HANDLE hThread2 	 = NULL;

	PVOID  objtowait[2] = {NULL};
	NTSTATUS ntStatus = 
		PsCreateSystemThread(
		&hThread1,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		ThreadProc1,
		NULL
		);
	if (!NT_SUCCESS(ntStatus))
	{
		return;
	}

	ntStatus = 
		PsCreateSystemThread(
		&hThread2,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		ThreadProc2,
		NULL
		);
	if (!NT_SUCCESS(ntStatus))
	{
		return;
	}

	if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
	{
		ntStatus = KfRaiseIrql(PASSIVE_LEVEL);
	}
	if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
	{
		return;
	}	
	ntStatus = ObReferenceObjectByHandle(
		hThread1,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait[0],
		NULL
		); 
	if (!NT_SUCCESS(ntStatus))
	{
		return;
	}

	ntStatus = ObReferenceObjectByHandle(
		hThread1,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait[1],
		NULL
		); 
	if (!NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(objtowait[0]);
		return;
	}

	KeWaitForMultipleObjects(
		2, 
		objtowait,  
		WaitAll,
		Executive,
		KernelMode,
		FALSE,
		NULL,
		NULL);

	ObDereferenceObject(objtowait[0]);
	ObDereferenceObject(objtowait[1]);

	//KeWaitForSingleObject(objtowait,Executive,KernelMode,FALSE,NULL); 
	return;
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload;

	ExInitializeFastMutex(&g_fmLock);
	ExInitializeFastMutex(&g_anLock);

	StartThreads();


	return STATUS_SUCCESS;
}