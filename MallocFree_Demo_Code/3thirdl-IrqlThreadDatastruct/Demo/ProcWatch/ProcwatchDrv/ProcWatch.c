#include "ntddk.h"
#include "windef.h"

#define EVENT_NAME    L"\\BaseNamedObjects\\ProcEvent"
#define DEVICE_NAME	  L"\\Device\\ProcWatch"
#define LINK_NAME	  L"\\DosDevices\\ProcWatch"

#define		CTRLCODE_BASE 0x8000
#define		MYCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN,CTRLCODE_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define		IOCTL_PROCWATCH		MYCTRL_CODE(0)

typedef struct _ProcMonData
{
    HANDLE  hParentId;
    HANDLE  hProcessId;
    BOOLEAN bCreate;
}ProcMonData, *PProcMonData;


VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

NTSTATUS CommonDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS IoctrlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

VOID ProcessCreateMon( IN HANDLE hParentId, IN HANDLE PId, IN BOOLEAN bCreate);


typedef struct _DEVICE_EXTENSION
{
    HANDLE             hProcessHandle;        // �¼�������
    PKEVENT            ProcessEvent;          // �û����ں�ͨ�ŵ��¼�����ָ��
    HANDLE             hParentId;             // �ڻص������б��������Ϣ
    HANDLE             hProcessId;
    BOOLEAN            bCreate;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

PDEVICE_OBJECT g_pDeviceObject = NULL;

// �������
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath ) 

{
	UNICODE_STRING	ustrDeviceName = {0};
	UNICODE_STRING	ustrLinkName = {0};
	PDEVICE_OBJECT	deviceObject = NULL;
	NTSTATUS		status = STATUS_SUCCESS;
	int				i = 0;
	UNICODE_STRING	ustrEventStr = {0};	
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	//�����豸

	RtlInitUnicodeString( &ustrDeviceName, DEVICE_NAME );
	status = IoCreateDevice( DriverObject,
	  sizeof(DEVICE_EXTENSION),
	  &ustrDeviceName,
	  FILE_DEVICE_UNKNOWN,
	  0,
	  FALSE,
	  &deviceObject
	  ); 
	
	if (!NT_SUCCESS( status ))
	{
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	g_pDeviceObject = deviceObject;

	// �����¼�������Ӧ�ò�ͨ��
	RtlInitUnicodeString(&ustrEventStr, EVENT_NAME);
	pDeviceExtension = (PDEVICE_EXTENSION)deviceObject->DeviceExtension;
    
	pDeviceExtension->ProcessEvent = 
		IoCreateNotificationEvent(&ustrEventStr, 
		&pDeviceExtension->hProcessHandle);
	KeClearEvent(pDeviceExtension->ProcessEvent);            // ����Ϊ������״̬

	RtlInitUnicodeString( &ustrLinkName, LINK_NAME);
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDeviceName);

	if (!NT_SUCCESS( status ))
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	} 

	status = PsSetCreateProcessNotifyRoutine(ProcessCreateMon, FALSE);
	if (!NT_SUCCESS( status ))
	{
		  IoDeleteDevice(DriverObject->DeviceObject);
		  DbgPrint("PsSetCreateProcessNotifyRoutine()\n");
		  return status;
	}  

	for ( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)  
	{
		  DriverObject->MajorFunction[i] = CommonDispatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctrlDispatch;

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS; 
} 

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING ustrLinkName;
	PsSetCreateProcessNotifyRoutine(ProcessCreateMon, TRUE);
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&ustrLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

//�����豸�������
NTSTATUS CommonDispatch (IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)

{ 
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0L;
	IoCompleteRequest( Irp, 0 );
	return Irp->IoStatus.Status;
}

NTSTATUS IoctrlDispatch(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS			ntStatus = STATUS_SUCCESS;
	PVOID				pUserBuffer = NULL;
	ULONG				ulInputSize = 0;
	ULONG				ulOutputSize = 0;
	PIO_STACK_LOCATION	pIrpStack = NULL;
	ULONG				ulIoCtrlCode = 0;
	PProcMonData		pProcMonData = NULL;
	PDEVICE_EXTENSION	pDeviceExtension  = NULL;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	pUserBuffer = pIrp->AssociatedIrp.SystemBuffer;

	pProcMonData = (PProcMonData)pUserBuffer;

	ulIoCtrlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	ulInputSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ulOutputSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch(ulIoCtrlCode)
	{
	case IOCTL_PROCWATCH:

		pDeviceExtension = (PDEVICE_EXTENSION)g_pDeviceObject->DeviceExtension;

		pProcMonData->bCreate = pDeviceExtension->bCreate;
		pProcMonData->hParentId = pDeviceExtension->hParentId;
		pProcMonData->hProcessId = pDeviceExtension->hProcessId;

		break;
	default:
		ntStatus = STATUS_INVALID_PARAMETER;
		ulOutputSize = 0;
		break;
	}

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = ulOutputSize;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

VOID ProcessCreateMon ( IN HANDLE hParentId, IN HANDLE PId,IN BOOLEAN bCreate )
{
    // ���DEVICE_EXTENSION�ṹ
    PDEVICE_EXTENSION deviceExtension = 
		(PDEVICE_EXTENSION)g_pDeviceObject->DeviceExtension;
    // ������Ϣ
    deviceExtension->hParentId = hParentId;
    deviceExtension->hProcessId = PId;
    deviceExtension->bCreate = bCreate;
    // �����¼���֪ͨӦ�ó���
    KeSetEvent(deviceExtension->ProcessEvent, 0, FALSE);
    KeClearEvent(deviceExtension->ProcessEvent);
}

