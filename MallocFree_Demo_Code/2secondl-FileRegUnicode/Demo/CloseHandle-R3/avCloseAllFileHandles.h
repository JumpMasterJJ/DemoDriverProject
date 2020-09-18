#ifndef _AVCLOSEALLFILEHANDLES_H_
#define	_AVCLOSEALLFILEHANDLES_H_

#include <windows.h>
#include <stdio.h>
#include <conio.h>  
#include <stdlib.h>   

#define DebugPrint						printf
#define NT_SUCCESS(Status)				((NTSTATUS)(Status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH		((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_DENIED			((NTSTATUS)0xC0000022L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001)
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000)

typedef LONG  NTSTATUS;
typedef struct _IO_STATUS_BLOCK
{
	NTSTATUS		Status;
	ULONG			Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
	USHORT				Length;
	USHORT				MaximumLength;
	PWSTR				Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


#define	SystemHandleInformation 16
#define	FileNameInformation		1

typedef struct _OBJECT_ATTRIBUTES
{
   ULONG			Length;
   HANDLE			RootDirectory;
   PUNICODE_STRING	ObjectName;
   ULONG			Attributes;
   PVOID			SecurityDescriptor;
   PVOID			SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;  

typedef struct _OBJECT_NAME_INformATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (CALLBACK* ZWQUERYSYSTEMINFORMATION)(
	IN  ULONG SystemInformationClass,
	IN  OUT PVOID SystemInformation,
	IN  ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS (CALLBACK* ZWOPENFILE)(
	OUT PHANDLE FileHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN  ULONG ShareAccess,
	IN  ULONG OpenOptions
);

typedef NTSTATUS (CALLBACK* ZWQUERYOBJECT)(
	IN HANDLE ObjectHandle,
	IN ULONG ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);
BOOL avCloseAllHandlesForFile(wchar_t *filename);

#endif