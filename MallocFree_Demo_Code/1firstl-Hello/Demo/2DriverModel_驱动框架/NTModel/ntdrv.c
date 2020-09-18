#include <ntddk.h>

#define DEVICE_NAME L"\\device\\ntmodeldrv"
#define LINK_NAME L"\\dosdevices\\ntmodeldrv"

#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)

//通用Dispatch函数
NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{


	//GetLastError()获取的返回状态
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	//返回给三环的函数的信息
	pIrp->IoStatus.Information = 0;
	//Complete an IRP in a Dispatch Routine (不太明白)
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	//返回给NT框架的返回状态
	return STATUS_SUCCESS;
}

//对应着三环的CreateFile
NTSTATUS DispatchCreate(PDEVICE_OBJECT pObject, PIRP pIrp)
{


	//GetLastError()获取的返回状态
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	//返回给三环的函数的信息
	pIrp->IoStatus.Information = 0;
	//Complete an IRP in a Dispatch Routine (不太明白)
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	//返回给NT框架的返回状态
	return STATUS_SUCCESS;
}

//对应着三环的ReadFile
NTSTATUS DispatchRead(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	PVOID pReadBuffer = NULL;
	ULONG uReadLength = 0;
	PIO_STACK_LOCATION pStack = NULL;
	ULONG uMin = 0;
	ULONG uHelloStr = 0;

	uHelloStr = (wcslen(L"hello world")+1)*sizeof(WCHAR);

	//第一步，拿到缓存的地址和长度
	//从头部拿缓存地址
	pReadBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//从栈上拿缓存长度
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uReadLength = pStack->Parameters.Read.Length;

	//第二步：读，写等操作
	uMin = uReadLength>uHelloStr?uHelloStr:uReadLength;
	RtlCopyMemory(pReadBuffer, L"hello world",uMin);

	//第三步，完成IRP
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uMin;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}

//对应着三环的WriteFile
NTSTATUS DispatchWrite(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	PVOID pWriteBuff = NULL;
	ULONG uWriteLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	PVOID pBuffer = NULL;

	//从IRP中取出Buffer
	pWriteBuff = pIrp->AssociatedIrp.SystemBuffer;

	//从IRP中取出BufferLength
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uWriteLength = pStack->Parameters.Write.Length;

	//申请内存
	pBuffer = ExAllocatePoolWithTag(PagedPool, uWriteLength, 'TSET');
	if(pBuffer == NULL)
	{
		pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp,IO_NO_INCREMENT);
		//返回内存资源不足的状态
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset(pBuffer, 0, uWriteLength);

	RtlCopyMemory(pBuffer, pWriteBuff, uWriteLength);

	ExFreePool(pBuffer);
	pBuffer=NULL;


	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uWriteLength;

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}

//对应着三环的DeviceIocontrol
NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	ULONG uIoctrlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuff = NULL;

	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;


	uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch(uIoctrlCode)
	{
	case CTL_HELLO:
		DbgPrint("Hello iocontrol\n");
		break;
	case CTL_PRINT:
		DbgPrint("%ws\n", pInputBuff);
		break;
	case CTL_BYE:
		DbgPrint("Goodbye iocontrol\n");
		break;
	default:
		DbgPrint("Unknown iocontrol\n");

	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}

NTSTATUS DispatchClean(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//对应着三环的CloseHandle
NTSTATUS DispatchClose(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING uLinkName={0};
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uLinkName);

	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Driver unloaded\n");

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
					 PUNICODE_STRING pRegPath)
{
	UNICODE_STRING uDeviceName = {0};
	UNICODE_STRING uLinkName={0};
	NTSTATUS ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i=0;

	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName,LINK_NAME);

	ntStatus = IoCreateDevice(pDriverObject,
	 0,&uDeviceName,FILE_DEVICE_UNKNOWN,0,FALSE,&pDeviceObject);
	
	if(!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed:%x", ntStatus);
		return ntStatus;
	}

	//DO_BUFFERED_IO规定R3和R0之间read和write通信的方式：
	//1,buffered io
	//2,direct io
	//3,neither io
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	ntStatus = IoCreateSymbolicLink(&uLinkName,&uDeviceName);
	if(!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed:%x\n", ntStatus);
		return ntStatus;
	}

	for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION+1;i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE]=DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ]=DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE]=DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DispatchIoctrl;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP]=DispatchClean;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]=DispatchClose;

	pDriverObject->DriverUnload=DriverUnload;

	DbgPrint("Driver load ok!\n");

	return STATUS_SUCCESS;
}
