#include <ntddk.h>

typedef NTSTATUS (*PSPTERMINATETPROCESS)(
					PEPROCESS Process,
					NTSTATUS ExitStatus
					);
PSPTERMINATETPROCESS PspTerminateProcess;

typedef NTSTATUS (*NTQUERYSYSTEMINFORMATION)(
				IN ULONG    SystemInformationClass,
				OUT PVOID   SystemInformation,
				IN ULONG    SystemInformationLength,
				OUT PULONG  ReturnLength OPTIONAL);
typedef unsigned long DWORD;	
NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
#define	SystemModuleInformation	11	
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG  Reserved[2];
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


ULONG GetFunctionAddr( IN PCWSTR FunctionName)
	{
		UNICODE_STRING UniCodeFunctionName;
		
		RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
		return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );    
		
	}



VOID DoFind(IN PVOID pContext)
	{
		NTSTATUS ret;
		PSYSTEM_MODULE_INFORMATION  module = NULL;
		ULONG n=0;
		void  *buf    = NULL;
		ULONG ntosknlBase;
		ULONG ntosknlEndAddr;
		ULONG curAddr;
		ULONG code1_sp3=0x8b55ff8b,code2_sp3=0xA16456EC,code3_sp3=0x00000124,code4_sp3=0x3B08758B;
		ULONG i;
		
		NtQuerySystemInformation=(NTQUERYSYSTEMINFORMATION)GetFunctionAddr(L"NtQuerySystemInformation");
		if (!NtQuerySystemInformation) 
		{
			DbgPrint("Find NtQuerySystemInformation faild!");
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,&n,0,&n);
		if (NULL==( buf=ExAllocatePoolWithTag(NonPagedPool, n, 'DFSP')))
		{
			DbgPrint("ExAllocatePool() failed\n" );
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,buf,n,NULL);
		if (!NT_SUCCESS(ret))	{
			DbgPrint("NtQuerySystemInformation faild!");
			goto Ret;
		} 
		module=(PSYSTEM_MODULE_INFORMATION)((PULONG)buf+1);
		ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
		ntosknlBase=(ULONG)module->Base;
		curAddr=ntosknlBase;
		ExFreePool(buf);
		for (i=curAddr;i<=ntosknlEndAddr;i++)
		{
				if (*((ULONG *)i)==code1_sp3) 
				{
					if (*((ULONG *)(i+4))==code2_sp3) 
					{
						if (*((ULONG *)(i+8))==code3_sp3) 
						{
							if (*((ULONG *)(i+12))==code4_sp3) 
							{
								PspTerminateProcess=(PSPTERMINATETPROCESS)i;
								break;
							}
						}
					}
				}
		}
Ret:
	PsTerminateSystemThread(STATUS_SUCCESS);
	}


VOID GetPspAddr()
{
		HANDLE hThread;
		PVOID objtowait=0;
		NTSTATUS dwStatus = 
			PsCreateSystemThread(
			&hThread,
	              0,
		       NULL,
			(HANDLE)0,
	              NULL,
		       DoFind,
			NULL
			);
		NTSTATUS st;
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			st=KfRaiseIrql(PASSIVE_LEVEL);
		
		}
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			
			return;
		}
		
		ObReferenceObjectByHandle(
			hThread,
			THREAD_ALL_ACCESS,
			NULL,
			KernelMode,
			&objtowait,
			NULL
			); 

		st=KeWaitForSingleObject(objtowait,Executive,KernelMode,FALSE,NULL); //NULL表示无限期等待.
		return;
	
	
}

NTSTATUS CheckPspTerminateProcessIsHook()
{
	int				i		= 0;
	char			*addr	= (char *)PspTerminateProcess;
	char			code[]	= { 0x8b, 0xff, 0x55, 0x8b, 0xec};
	
	while(i<5)
	{
		DbgPrint("0x%02X", (unsigned char)addr[i]);
		if(addr[i] != code[i])
		{
			return STATUS_UNSUCCESSFUL;
		}
		i++;
	}
	return STATUS_SUCCESS;
}

int MyPspTerminateProcess(
						  PEPROCESS Process,
						  NTSTATUS ExitStatus
						  )
{
	DbgPrint("PspTerminateProcess hello\n");
	return 1;
}

_declspec(naked) T_PspTerminateProcess(
									   PEPROCESS Process,
									   NTSTATUS ExitStatus
									   )
{
	_asm
	{
		mov edi, edi
			push ebp
			mov ebp ,esp
			push [ebp+0ch]
			push [ebp+8]
			call MyPspTerminateProcess 
			cmp eax,1
			jz end
			mov eax,PspTerminateProcess 
			add eax,5 
			jmp eax
			
end:
		pop ebp
			retn 8
	}
}


VOID InlineHookPspTerminateProcess()
{ 

	int				JmpOffSet = 0;
	unsigned char	JmpCode[5] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };
	KIRQL			oldIrql;

	if (PspTerminateProcess == 0)
	{
		DbgPrint("PspTerminateProcess NOT FOUND\n");
		return;
	}

	DbgPrint("PspTerminateProcess is found at:0x%08x\n", (ULONG)PspTerminateProcess );

	DbgPrint("T_PspTerminateProcess is:%x\n",T_PspTerminateProcess);
	JmpOffSet= (char*)T_PspTerminateProcess - (char*)PspTerminateProcess - 5;
	DbgPrint("JmpOffSet is:%x\n",JmpOffSet);
	RtlCopyMemory ( JmpCode+1, &JmpOffSet, 4 );

	_asm
	{
		CLI
		MOV EAX, CR0
		AND EAX, NOT 10000H
		MOV CR0, EAX
	}
	oldIrql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory ( PspTerminateProcess, JmpCode, 5 );
	DbgPrint("PspTerminateProcess is hook now \n");
	KeLowerIrql(oldIrql);

	_asm
	{
		MOV EAX, CR0
		OR EAX, 10000H
		MOV CR0, EAX
		STI
	}

}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	// 	在win2000上是三字节
	// 	push ebp
	// 	mov ebp, esp
	// 		　　
	// 	到了winxp以及后续系统上，则变成了五字节
	// 	mov edi, edi
	// 	push ebp
	// 	mov ebp, esp
	// 	函数的序言

	unsigned char Code[5]={0x8b,0xff,0x55,0x8b,0xec};

	_asm
	{
		CLI
		MOV eax, CR0
		AND eax, NOT 10000H
		MOV CR0, eax

		pushad
		mov edi, PspTerminateProcess
		mov eax, dword ptr Code[0]
		mov [edi], eax
		mov al, byte ptr Code[4]
		mov [edi+4], al
		popad

		MOV eax, CR0
		OR eax, 10000H
		MOV CR0, eax
		STI
	}

	DbgPrint("Goodbye driver\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	GetPspAddr();
	if(PspTerminateProcess == NULL)
	{
		DbgPrint("PspFunc Not Find!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if(STATUS_SUCCESS != CheckPspTerminateProcessIsHook())
	{
		DbgPrint("PspTerminateProcess Match Failed !");
		return STATUS_UNSUCCESSFUL;
	}

	InlineHookPspTerminateProcess();

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
	
}