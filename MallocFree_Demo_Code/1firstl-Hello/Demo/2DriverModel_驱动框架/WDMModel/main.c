#include <wdm.h>

typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT fdo;
	PDEVICE_OBJECT NextStackDevice;
	UNICODE_STRING ustrDeviceName;	// 设备名
	UNICODE_STRING ustrSymLinkName;	// 符号链接名
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

NTSTATUS WDMAddDevice(IN PDRIVER_OBJECT DriverObject,
                      IN PDEVICE_OBJECT PhysicalDeviceObject)
{ 
	NTSTATUS			status;
	PDEVICE_OBJECT		fdo;
	UNICODE_STRING		devName;
	PDEVICE_EXTENSION	pdx;
	UNICODE_STRING		symLinkName;

	PAGED_CODE();
	KdPrint(("Enter HelloWDMAddDevice\n"));
	RtlInitUnicodeString(&devName,L"\\Device\\WDMModelDrv");
	status = IoCreateDevice(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&devName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&fdo);
	if( !NT_SUCCESS(status))
		return status;
	pdx = (PDEVICE_EXTENSION)fdo->DeviceExtension;
	pdx->fdo = fdo;
	pdx->NextStackDevice = IoAttachDeviceToDeviceStack(fdo, PhysicalDeviceObject);

	RtlInitUnicodeString(&symLinkName,L"\\DosDevices\\WDMModelDrv");

	pdx->ustrDeviceName = devName;
	pdx->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName,&devName);

	if( !NT_SUCCESS(status))
	{
		IoDeleteSymbolicLink(&pdx->ustrSymLinkName);
		status = IoCreateSymbolicLink(&symLinkName,&devName);
		if( !NT_SUCCESS(status))
		{
			return status;
		}
	}

	fdo->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
	fdo->Flags &= ~DO_DEVICE_INITIALIZING;

	KdPrint(("Leave HelloWDMAddDevice\n"));
	return STATUS_SUCCESS;
}


NTSTATUS DefaultPnpHandler(PDEVICE_EXTENSION pdx, PIRP Irp)
{
	PAGED_CODE();
	KdPrint(("Enter DefaultPnpHandler\n"));
	IoSkipCurrentIrpStackLocation(Irp);
	KdPrint(("Leave DefaultPnpHandler\n"));
	return IoCallDriver(pdx->NextStackDevice, Irp);
}

NTSTATUS HandleRemoveDevice(PDEVICE_EXTENSION pdx, PIRP Irp)
{

	NTSTATUS status;

	PAGED_CODE();
	KdPrint(("Enter HandleRemoveDevice\n"));

	Irp->IoStatus.Status = STATUS_SUCCESS;
	status = DefaultPnpHandler(pdx, Irp);
	IoDeleteSymbolicLink(&pdx->ustrSymLinkName);

    	//调用IoDetachDevice()把fdo从设备栈中脱开：
    if (pdx->NextStackDevice)
        IoDetachDevice(pdx->NextStackDevice);
	
    //删除fdo：
    IoDeleteDevice(pdx->fdo);
    KdPrint(("Leave HandleRemoveDevice\n"));
	return status;
}


NTSTATUS WDMPnp(IN PDEVICE_OBJECT fdo,
                     IN PIRP Irp)
{


	ULONG fcn;
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION) fdo->DeviceExtension;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	static NTSTATUS (*fcntab[])(PDEVICE_EXTENSION pdx, PIRP Irp) = 
	{
		DefaultPnpHandler,		// IRP_MN_START_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_REMOVE_DEVICE
		HandleRemoveDevice,		// IRP_MN_REMOVE_DEVICE
		DefaultPnpHandler,		// IRP_MN_CANCEL_REMOVE_DEVICE
		DefaultPnpHandler,		// IRP_MN_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_CANCEL_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_DEVICE_RELATIONS
		DefaultPnpHandler,		// IRP_MN_QUERY_INTERFACE
		DefaultPnpHandler,		// IRP_MN_QUERY_CAPABILITIES
		DefaultPnpHandler,		// IRP_MN_QUERY_RESOURCES
		DefaultPnpHandler,		// IRP_MN_QUERY_RESOURCE_REQUIREMENTS
		DefaultPnpHandler,		// IRP_MN_QUERY_DEVICE_TEXT
		DefaultPnpHandler,		// IRP_MN_FILTER_RESOURCE_REQUIREMENTS
		DefaultPnpHandler,		// 
		DefaultPnpHandler,		// IRP_MN_READ_CONFIG
		DefaultPnpHandler,		// IRP_MN_WRITE_CONFIG
		DefaultPnpHandler,		// IRP_MN_EJECT
		DefaultPnpHandler,		// IRP_MN_SET_LOCK
		DefaultPnpHandler,		// IRP_MN_QUERY_ID
		DefaultPnpHandler,		// IRP_MN_QUERY_PNP_DEVICE_STATE
		DefaultPnpHandler,		// IRP_MN_QUERY_BUS_INFORMATION
		DefaultPnpHandler,		// IRP_MN_DEVICE_USAGE_NOTIFICATION
		DefaultPnpHandler,		// IRP_MN_SURPRISE_REMOVAL
	};

	PAGED_CODE();
	KdPrint(("Enter WDMPnp\n"));

	fcn = stack->MinorFunction;
	if (fcn >= arraysize(fcntab))
	{	// unknown function
		status = DefaultPnpHandler(pdx, Irp); // some function we don't know about
		return status;
	}						// unknown function

	status = (*fcntab[fcn])(pdx, Irp);
	KdPrint(("Leave WDMPnp\n"));
	return status;
}


NTSTATUS WDMDispatchRoutine(IN PDEVICE_OBJECT fdo,
				 IN PIRP Irp)
{
	PAGED_CODE();
	KdPrint(("Enter WDMDispatchRoutine\n"));
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;	// no bytes xfered
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	KdPrint(("Leave WDMDispatchRoutine\n"));
	return STATUS_SUCCESS;
}

void WDMUnload(IN PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	KdPrint(("Enter WDMUnload\n"));
	KdPrint(("Leave WDMUnload\n"));
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
				  IN PUNICODE_STRING pRegistryPath)
{
	KdPrint(("Enter DriverEntry\n"));

	pDriverObject->DriverExtension->AddDevice = WDMAddDevice;
	pDriverObject->MajorFunction[IRP_MJ_PNP] = WDMPnp;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = 
	pDriverObject->MajorFunction[IRP_MJ_READ] = 
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WDMDispatchRoutine;
	pDriverObject->DriverUnload = WDMUnload;

	KdPrint(("Leave DriverEntry\n"));
	return STATUS_SUCCESS;
}
