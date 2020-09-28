#include <ntddk.h>

#define NUMBER_HASH_BUCKETS 37

#define OBJECT_TO_OBJECT_HEADER(o)\
      CONTAINING_RECORD((o),OBJECT_HEADER,Body)

typedef struct _OBJECT_TYPE_INITIALIZER 
{
  USHORT Length;
  BOOLEAN UseDefaultObject;
  BOOLEAN CaseInsensitive;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  BOOLEAN MaintainTypeList;
  POOL_TYPE PoolType;
  ULONG DefaultPagedPoolCharge;
  ULONG DefaultNonPagedPoolCharge;
  PVOID DumpProcedure;
  PVOID OpenProcedure;
  PVOID CloseProcedure;
  PVOID DeleteProcedure;
  PVOID ParseProcedure;
  PVOID SecurityProcedure;
  PVOID QueryNameProcedure;
  PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;


typedef struct _OBJECT_TYPE 
{ 
  ERESOURCE Mutex; 
  LIST_ENTRY TypeList; 
  UNICODE_STRING Name; 
  PVOID DefaultObject; 
  ULONG Index; 
  ULONG TotalNumberOfObjects; 
  ULONG TotalNumberOfHandles; 
  ULONG HighWaterNumberOfObjects; 
  ULONG HighWaterNumberOfHandles; 
  OBJECT_TYPE_INITIALIZER TypeInfo; 
#ifdef POOL_TAGGING 
  ULONG Key; 
#endif 
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_CREATE_INFORMATION 
{ 
  ULONG Attributes; 
  HANDLE RootDirectory; 
  PVOID ParseContext; 
  KPROCESSOR_MODE ProbeMode; 
  ULONG PagedPoolCharge; 
  ULONG NonPagedPoolCharge; 
  ULONG SecurityDescriptorCharge; 
  PSECURITY_DESCRIPTOR SecurityDescriptor; 
  PSECURITY_QUALITY_OF_SERVICE SecurityQos; 
  SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; 
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;



typedef struct _OBJECT_HEADER 
{ 
  LONG PointerCount; 
  union { 
    LONG HandleCount; 
    PSINGLE_LIST_ENTRY SEntry; 
  }; 
  POBJECT_TYPE Type; 
  UCHAR NameInfoOffset; 
  UCHAR HandleInfoOffset; 
  UCHAR QuotaInfoOffset; 
  UCHAR Flags; 
  union 
  { 
    POBJECT_CREATE_INFORMATION ObjectCreateInfo; 
    PVOID QuotaBlockCharged; 
  };
  
  PSECURITY_DESCRIPTOR SecurityDescriptor; 
  QUAD Body; 
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _OBJECT_DIRECTORY_ENTRY 
{
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY 
{
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[ NUMBER_HASH_BUCKETS ];
    struct _OBJECT_DIRECTORY_ENTRY **LookupBucket;
    BOOLEAN LookupFound;
    USHORT SymbolicLinkUsageCount;
    struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP {
    ULONG ReferenceCount;
    POBJECT_DIRECTORY DosDevicesDirectory;
    ULONG DriveMap;
    UCHAR DriveType[ 32 ];
} DEVICE_MAP, *PDEVICE_MAP;


PVOID OldParseKey;

//HOOKº¯Êý

NTSTATUS FakeParseKey(POBJECT_DIRECTORY RootDirectory,
					  POBJECT_TYPE ObjectType,
					  PACCESS_STATE AccessState,
					  KPROCESSOR_MODE AccessCheckMode,
					  ULONG Attributes,
					  PUNICODE_STRING ObjectName,
					  PUNICODE_STRING RemainingName,
					  PVOID ParseContext ,
					  PSECURITY_QUALITY_OF_SERVICE SecurityQos ,
					  PVOID *Object)
{
	NTSTATUS stat ;
	WCHAR Name[300];
	RtlCopyMemory(Name , ObjectName->Buffer , ObjectName->MaximumLength );
	_wcsupr(Name);
	
	if (wcsstr(Name , L"RUN"))
	{
		return STATUS_OBJECT_NAME_NOT_FOUND ;
	}
	
	__asm
	{
		push eax
			push Object
			push SecurityQos
			push ParseContext
			push RemainingName
			push ObjectName
			push Attributes
			movzx eax, AccessCheckMode
			push eax
			push AccessState
			push ObjectType
			push RootDirectory
			call OldParseKey
			
			mov stat, eax
			pop eax
			
	} 
	return stat ;
} 

//°²×°HOOK
void InstallAdvRegHook()
{

	UNICODE_STRING RegPath ;
	OBJECT_ATTRIBUTES oba ;
	HANDLE RegKeyHandle ;
	NTSTATUS status ;
	PVOID KeyObject ;

	POBJECT_TYPE CmpKeyObjectType ;


	RtlInitUnicodeString(&RegPath, L"\\Registry\\Machine\\Software" );
	InitializeObjectAttributes( &oba , 
								&RegPath , 
								OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE , 
								0 , 
								0 );

	RegKeyHandle=0;

	status=ZwOpenKey(&RegKeyHandle,KEY_QUERY_VALUE,&oba);

	if (!NT_SUCCESS(status ))
	{
		KdPrint(("open the software key failed!\n"));
		return ;
	}


	status=ObReferenceObjectByHandle(RegKeyHandle,
									GENERIC_READ,
									NULL,
									KernelMode,
									&KeyObject,
									0);

	if (!NT_SUCCESS(status ))
	{
		KdPrint(("reference the key object failed!\n"));
		ZwClose(RegKeyHandle);
		return ;
	}

	__asm
	{
		push eax
		mov eax,KeyObject
		mov eax,[eax-0x10]
		mov CmpKeyObjectType,eax
		pop eax
	}


	OldParseKey = CmpKeyObjectType->TypeInfo.ParseProcedure ;


	if (!MmIsAddressValid(OldParseKey))
	{
		ObDereferenceObject(KeyObject);
		ZwClose(RegKeyHandle);
		return;
	}



	CmpKeyObjectType->TypeInfo.ParseProcedure = FakeParseKey;

	ObDereferenceObject(KeyObject);
	ZwClose(RegKeyHandle);
	return ;


}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
  NTSTATUS Status = STATUS_SUCCESS;
  InstallAdvRegHook();
  return Status;
} 