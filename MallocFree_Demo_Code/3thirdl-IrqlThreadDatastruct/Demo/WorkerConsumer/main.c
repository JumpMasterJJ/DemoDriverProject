#include <ntddk.h>

ULONG	g_ulTotal = 0;
KSEMAPHORE g_kSemaphore;



VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye, driver\n");
}

VOID Worker(IN PVOID pContext)
{
	ULONG i = 0;
	LARGE_INTEGER waitTime = {0};
	waitTime.QuadPart = -3*10000000i64;

	while(i < 10)
	{
		g_ulTotal++;
		KeReleaseSemaphore(&g_kSemaphore ,IO_NO_INCREMENT , 1 , FALSE );//增加一个资源semaphore
		DbgPrint("Worker:produced 1, total:%x\n", g_ulTotal);
		i++;
		KeDelayExecutionThread(KernelMode, FALSE, &waitTime);//延迟3秒
	}

}

VOID Consumer(IN PVOID pContext)
{
	ULONG i = 10;
	LARGE_INTEGER waitTime = {0};
	waitTime.QuadPart = -3*10000000i64;

	while(i > 0)
	{
		
		KeWaitForSingleObject(&g_kSemaphore, Executive, KernelMode, FALSE, NULL);//等待资源并减少一个semaphore
		g_ulTotal--;
		DbgPrint("Consumer:consumed 1, total:%x\n", g_ulTotal);
		i--;
		KeDelayExecutionThread(KernelMode, FALSE, &waitTime);//延迟3秒

	}

}

void StartThreads()
{
	HANDLE hThread1 	 = NULL;
	HANDLE hThread2 	 = NULL;

	PVOID  objtowait[2] = {NULL};
	NTSTATUS ntStatus = 
		PsCreateSystemThread(//创建工作者线程
		&hThread1,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		Worker,
		NULL
		);
	if (!NT_SUCCESS(ntStatus))
	{
		return;
	}

	ntStatus = 
		PsCreateSystemThread(//创建消费者线程
		&hThread2,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		Consumer,
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
		hThread2,
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

	KeWaitForMultipleObjects(//等待两个线程结束
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
	KeInitializeSemaphore(
		&g_kSemaphore,
		0,//信号量的初始值
		10 //信号量的最大值
		);


	StartThreads();


	return STATUS_SUCCESS;
}