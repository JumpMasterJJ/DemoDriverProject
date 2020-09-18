#include <ntddk.h>

ULONG	g_ulTotal = 0;
//InterlockedIncrement(g_ulTotal);
FAST_MUTEX g_fmLock;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye, driver\n");
}

VOID ThreadProc1(IN PVOID pContext)
{
	ULONG i = 0;
	ExAcquireFastMutex(&g_fmLock);

	g_ulTotal++;
	DbgPrint("ThreadProc1:%x\n", g_ulTotal);


	ExReleaseFastMutex(&g_fmLock);

}

VOID ThreadProc2(IN PVOID pContext)
{
	ULONG i = 0;
	ExAcquireFastMutex(&g_fmLock);

	g_ulTotal++;
	DbgPrint("ThreadProc2:%x\n", g_ulTotal);

	ExReleaseFastMutex(&g_fmLock);
	
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

	StartThreads();


	return STATUS_SUCCESS;
}