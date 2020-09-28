#include "precomp.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SDT     SYSTEMSERVICE
#define KSDT KeServiceDescriptorTable

void StartHook(void);
void RemoveHook(void);
NTKERNELAPI NTSTATUS ZwTerminateProcess(
  IN HANDLE              ProcessHandle OPTIONAL,
  IN NTSTATUS            ExitStatus );

NTSTATUS Hook_ZwTerminateProcess(
  IN HANDLE              ProcessHandle OPTIONAL,
  IN NTSTATUS            ExitStatus );

typedef NTSTATUS (*ZWTERMINATEPROCESS)(
  IN HANDLE              ProcessHandle OPTIONAL,
  IN NTSTATUS            ExitStatus );

static ZWTERMINATEPROCESS        OldZwTerminateProcess;


NTSTATUS Hook_ZwTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	)
{
	ULONG 			uPID = 0;
	NTSTATUS 		ntStatus = 0;
	PEPROCESS 		pEProcess = NULL;

	ntStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if(!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}


	uPID = (ULONG)PsGetProcessId(pEProcess);

	if(ValidateProcessNeedProtect(uPID) != -1)
	{
		if(uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			return STATUS_ACCESS_DENIED;
		}
	}
	ntStatus = OldZwTerminateProcess(ProcessHandle, ExitStatus);

	return ntStatus;
}

void StartHook (void)
{
    //获取未导出的服务函数索引号
    HANDLE    hFile;
    PCHAR    pDllFile;
    ULONG  ulSize;
    ULONG  ulByteReaded;

    __asm
    {
        push    eax
        mov        eax, CR0
        and        eax, 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
    
    OldZwTerminateProcess  = (ZWTERMINATEPROCESS)InterlockedExchange((PLONG)
                                                        &SDT(ZwTerminateProcess),
                                                        (LONG)Hook_ZwTerminateProcess);

    
    //关闭
    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
    return ;
}

void RemoveHook (void)
{
    __asm
    {
        push    eax
        mov        eax, CR0
        and        eax, 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
  InterlockedExchange( (PLONG) &SDT(ZwTerminateProcess),  (LONG) OldZwTerminateProcess);

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
}


