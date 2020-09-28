#include <ntifs.h>
#include <ntddk.h>
#include <WINDEF.H>

#define SystemHandleInformation 16
#define ObjectNameInformation 1

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG            ProcessId;
    UCHAR            ObjectTypeNumber;
    UCHAR            Flags;
    USHORT          Handle;
    PVOID            Object;
    ACCESS_MASK      GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow = NULL;

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
											  IN ULONG SystemInformationClass,
											  OUT PVOID              SystemInformation,
											  IN ULONG                SystemInformationLength,
  OUT PULONG              ReturnLength OPTIONAL );

typedef BOOL (NTAPI *REAL_NtGdiStretchBlt)
(
	IN HDC   hdcDst,
	IN int   xDst,
	IN int   yDst,
	IN int   cxDst,
	IN int   cyDst,
	IN HDC   hdcSrc,
	IN int   xSrc,
	IN int   ySrc,
	IN int   cxSrc,
	IN int   cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor
);

typedef BOOL (NTAPI *REAL_NtGdiBitBlt)
(
	IN HDC    hdcDst,
	IN int    x,
	IN int    y,
	IN int    cx,
	IN int    cy,
	IN HDC    hdcSrc,
	IN int    xSrc,
	IN int    ySrc,
	IN DWORD  rop4,
	IN DWORD  crBackColor,
	IN FLONG  fl
);

REAL_NtGdiStretchBlt OldNtGdiStretchBlt;
REAL_NtGdiBitBlt OldNtGdiBitBlt = NULL;

BOOL NTAPI hook_NtGdiStretchBlt(
	IN HDC   hdcDst,
	IN int   xDst,
	IN int   yDst,
	IN int   cxDst,
	IN int   cyDst,
	IN HDC   hdcSrc,
	IN int   xSrc,
	IN int   ySrc,
	IN int   cxSrc,
	IN int   cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor
	)
{
	return TRUE;
	//DbgPrint("hook_NtGdiStretchBlt:%d", hdcDst);

	return OldNtGdiStretchBlt(
		hdcDst,
		xDst,
		yDst,
		cxDst,
		cyDst,
		hdcSrc,
		xSrc,
		ySrc,
		cxSrc,
		cySrc,
		dwRop,
		dwBackColor
	);
}

BOOL NTAPI hook_NtGdiBitBlt(
	IN HDC    hdcDst,
	IN int    x,
	IN int    y,
	IN int    cx,
	IN int    cy,
	IN HDC    hdcSrc,
	IN int    xSrc,
	IN int    ySrc,
	IN DWORD  rop4,
	IN DWORD  crBackColor,
	IN FLONG  fl
	)
{
	PEPROCESS pe = NULL;
	PCHAR pProcessName = NULL;
	PCHAR pIgnorePocess = "explorer.exe";

	pe = PsGetCurrentProcess();

	pProcessName = (PCHAR)((ULONG)pe + 0x174);

	if (RtlCompareMemory(pProcessName, pIgnorePocess, strlen(pIgnorePocess)) == strlen(pIgnorePocess))
	{
		return OldNtGdiBitBlt(
			hdcDst,
			x,
			y,
			cx,
			cy,
			hdcSrc,
			xSrc,
			ySrc,
			rop4,
			crBackColor,
			fl
		);
	}

	return TRUE;
}

PVOID GetInfoTable(ULONG ATableType)
{
	ULONG mSize = 0x4000;
    PVOID mPtr = NULL;
    NTSTATUS St;
	
    do
    {
        mPtr = ExAllocatePoolWithTag(PagedPool, mSize, 'GIT');
        memset(mPtr, 0,mSize);
		
        if (mPtr)
        {
            St = ZwQuerySystemInformation(ATableType, mPtr,mSize, NULL);
        } else return NULL;
		
        if (St == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePool(mPtr);
			
            mSize = mSize *2;
        }
		
    } while (St == STATUS_INFO_LENGTH_MISMATCH);
	
    if (St == STATUS_SUCCESS) return mPtr;
	
    ExFreePoolWithTag(mPtr, 'GIT');
	
    return NULL;
}

HANDLE GetCsrPid()
{
    HANDLE Process,hObject;
	
    HANDLE CsrId =(HANDLE)0;
	
    OBJECT_ATTRIBUTES obj;
	
    CLIENT_ID cid;
	
    UCHAR Buff[0x100];
	
    POBJECT_NAME_INFORMATION ObjName= (PVOID)&Buff;
	
    PSYSTEM_HANDLE_INFORMATION_EX Handles;
	
    ULONG r;
	
    Handles = GetInfoTable(SystemHandleInformation);
	
    if (!Handles) return CsrId;
	
    for (r = 0; r < Handles->NumberOfHandles; r++)
    {
        if (Handles->Information[r].ObjectTypeNumber == 21) //Portobject
        {
            InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL,NULL);
			
            cid.UniqueProcess= (HANDLE)Handles->Information[r].ProcessId;
			
            cid.UniqueThread= 0;
			
            if (NT_SUCCESS(NtOpenProcess(&Process,PROCESS_DUP_HANDLE, &obj, &cid)))
            {
                if (NT_SUCCESS(ZwDuplicateObject(Process,(HANDLE)Handles->Information[r].Handle,NtCurrentProcess(),&hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
                {
					if (NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation,ObjName, 0x100, NULL)))
                    {
                        if (ObjName->Name.Buffer&& !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
                        {
                            CsrId = (HANDLE)Handles->Information[r].ProcessId;
                        }
                    }
                    ZwClose(hObject);
                }
                ZwClose(Process);
            }
        }
    }
	
    ExFreePool(Handles);
	
    return CsrId;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PEPROCESS crsProcess = NULL;
	
	if (OldNtGdiBitBlt && OldNtGdiStretchBlt && KeServiceDescriptorTableShadow)
	{
		ntStatus = PsLookupProcessByProcessId(GetCsrPid(),&crsProcess);
		
		if (NT_SUCCESS(ntStatus))
		{
			KeAttachProcess(crsProcess);
			
			__asm
			{
				push    eax
					mov        eax, CR0
					and        eax, 0FFFEFFFFh
					mov        CR0, eax
					pop        eax
			}
			
			InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[13], (ULONG)OldNtGdiBitBlt);
			InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[292], (ULONG)OldNtGdiStretchBlt);
			
			__asm
			{
				push    eax
					mov        eax, CR0
					or        eax, NOT 0FFFEFFFFh
					mov        CR0, eax
					pop        eax
			}
		}
	}
}

NTSTATUS HookssdtShadow()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG BuildNumber  = 0;
    ULONG MinorVersion = 0;
    ULONG MajorVersion = 0;
	PEPROCESS crsProcess = NULL;
	
    PsGetVersion(&MajorVersion, &MinorVersion, &BuildNumber, NULL);

	DbgPrint("%d", BuildNumber);	

	if (BuildNumber == 2600) //XP
	{
		KeServiceDescriptorTableShadow = (PServiceDescriptorTableEntry_t)((ULONG)&KeServiceDescriptorTable - 0x40 + 0x10);

		DbgPrint("%d", KeServiceDescriptorTableShadow);	
		
		if (KeServiceDescriptorTableShadow)
		{
			ntStatus = PsLookupProcessByProcessId(GetCsrPid(),&crsProcess);

			if (NT_SUCCESS(ntStatus))
			{
				KeAttachProcess(crsProcess);
				
				__asm
				{
					push    eax
						mov        eax, CR0
						and        eax, 0FFFEFFFFh
						mov        CR0, eax
						pop        eax
				}
				
				OldNtGdiBitBlt = (REAL_NtGdiBitBlt)InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[13], (ULONG)hook_NtGdiBitBlt);
				OldNtGdiStretchBlt = (REAL_NtGdiStretchBlt)InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[292], (ULONG)hook_NtGdiStretchBlt);
				
				__asm
				{
					push    eax
						mov        eax, CR0
						or        eax, NOT 0FFFEFFFFh
						mov        CR0, eax
						pop        eax
				}
			}
		}
	}

	return ntStatus;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DriverUnload;

	HookssdtShadow();
	
	return STATUS_SUCCESS;
}