#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye world!\n");
}


NTSTATUS DriverEntry(
IN PDRIVER_OBJECT pDriverObject,
IN PUNICODE_STRING pRegistryPath)
{
	DbgPrint("Hello, world\n");
	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}