#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

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
POBJECT_TYPE pType= NULL;
POBJECT_HEADER addrs=NULL;
PVOID OldParseProcedure = NULL;


BOOL MyObQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName)
{
	PVOID buffer = NULL;
	DWORD reqSize = 0;
	NTSTATUS status = 0;
	__try
	{
		reqSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);

		buffer = ExAllocatePoolWithTag(NonPagedPool, reqSize, 'CORP');

		if(buffer == NULL)
			return FALSE;

		status = ObQueryNameString(pObject, 
								   buffer,
								   reqSize,
								   &reqSize);

		if((status == STATUS_INFO_LENGTH_MISMATCH) ||
		   (status == STATUS_BUFFER_OVERFLOW) ||
		   (status == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(buffer);
			buffer = NULL;

			buffer = ExAllocatePoolWithTag(NonPagedPool, reqSize, 'rtpR');

			if(buffer == NULL)
			{
				return FALSE;
			}
			
			status = ObQueryNameString(pObject, 
								   buffer,
								   reqSize,
								   &reqSize);

		}

		if(NT_SUCCESS(status))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)buffer;

			if(allocateName)
			{
				objName->Buffer = ExAllocatePoolWithTag(NonPagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'rtpR');
		
				if(objName->Buffer)
				{
					RtlZeroMemory(objName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					objName->Length = 0;
					objName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(objName, &pNameInfo->Name);
				}
				else
					status = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(objName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}

	if(buffer)
	{
		ExFreePool(buffer);
		buffer = NULL;
	}

	return NT_SUCCESS(status);
}

NTSTATUS NewParseProcedure(IN PVOID ParseObject,
             IN PVOID ObjectType,
             IN OUT PACCESS_STATE AccessState,
             IN KPROCESSOR_MODE AccessMode,
             IN ULONG Attributes,
             IN OUT PUNICODE_STRING CompleteName,
             IN OUT PUNICODE_STRING RemainingName,
             IN OUT PVOID Context OPTIONAL,
             IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
             OUT PVOID *Object) 
{
     NTSTATUS Status;
     WCHAR szObjName[MAX_PATH] = {0};
     UNICODE_STRING ustrName = {0};

    ustrName.Length = 0;
    ustrName.Buffer = szObjName;
    ustrName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

 
  __asm
  {
      push eax
      push Object
      push SecurityQos
      push Context
      push RemainingName
      push CompleteName
      push Attributes
      movzx eax, AccessMode
      push eax
      push AccessState
      push ObjectType
      push ParseObject
      call OldParseProcedure
      mov Status, eax
      pop eax

      
  }
//   if (MyObQueryObjectName(Object, &ustrName, FALSE))
//   {
// 	DbgPrint("Name:%wZ\n", &ustrName);
//   }
  
  KdPrint(("object is hook:%wZ, %wZ\n", CompleteName, RemainingName));
  return Status;

}
NTSTATUS Hook()
{
	NTSTATUS			Status		= 0;
	HANDLE				hFile		= NULL;
	UNICODE_STRING		Name		={0};
	OBJECT_ATTRIBUTES	Attr		={0};
	IO_STATUS_BLOCK		ioStaBlock	={0};
	PVOID				pObject		= NULL;
  
  
	RtlInitUnicodeString(&Name,L"\\Device\\HarddiskVolume1\\1.txt");
	InitializeObjectAttributes(&Attr,&Name,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,\
								0,NULL);
	Status = ZwOpenFile(&hFile,GENERIC_ALL,&Attr,&ioStaBlock,\
						0,FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("File is Null\n"));
		return Status;
	}
 
	Status = ObReferenceObjectByHandle(hFile,GENERIC_ALL,NULL,KernelMode,&pObject,NULL);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Object is Null\n"));
		return Status;
	}
 
	KdPrint(("pobject is %08X\n",pObject));

	addrs=OBJECT_TO_OBJECT_HEADER(pObject);//获取对象头


	pType=addrs->Type;//获取对象类型结构 object-10h


	OldParseProcedure = pType->TypeInfo.ParseProcedure;//获取服务函数原始地址OBJECT_TYPE+9C位置为打开

// 	__asm
// 	  {
// 		cli;
// 		mov eax, cr0;
// 		and eax, not 10000h;
// 		mov cr0, eax;
// 	  }

	pType->TypeInfo.ParseProcedure = NewParseProcedure;//hook
// 	  __asm
// 	  {
// 		mov eax, cr0;
// 		or eax, 10000h;
// 		mov cr0, eax;
// 		sti;
// 	  }
	 Status = ZwClose(hFile);
	 return Status;
}
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	pType->TypeInfo.ParseProcedure = OldParseProcedure;
	DbgPrint("Goodbye!\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
  NTSTATUS Status = STATUS_SUCCESS;
  Status=Hook();
  DriverObject->DriverUnload = DriverUnload;
  return Status;
} 