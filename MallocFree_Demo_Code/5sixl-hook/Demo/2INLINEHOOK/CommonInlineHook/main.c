#include <ntddk.h>

//��ζԺ�����inlinehook?
//���ȣ�Ū�����Ҫinlinehook�ĺ����Ķ��塣
//Ȼ�󣬻��Ҫinline hook�ĺ����ĵ�ַ��
//�����δ�����ģ����������룬���������ڴ棻
//����ǵ����ģ�����ֱ��ʹ�ú���������Ϊ���ĵ�ַ����ʹ��MmGetSystemRoutineAddress
//�õ����ĵ�ַ���磺
//NTKERNELAPI
//BOOLEAN
//KeInsertQueueApc (
//				  IN PKAPC        Apc,
//				  IN PVOID        SystemArgument1,
//				  IN PVOID        SystemArgument2,
//				  IN KPRIORITY    Increment
//				  );
//��ôKeInsertQueueApc���Ǹú������׵�ַ�ˡ�ע�����NTKERNELAPI���������MmGetSystemRoutineAddress���õ�ַ
//
//�õ���ַ�󣬾Ϳ�����inlineHOOK�ˡ�
//���õ�ַ��ǰ����ֽڣ�����jmp T_MyFunc - Func - 5����ط�
//��T_MyFunc��ѹջ����������MyFunc��ִ����MyFunc֮����JUMP��Func+5�ĵط�ִ�С�
//��ж�غ�����ָ�Func��ȥ��inline hook

//���ԣ�inlinehookһ��Func�����������¼�������
//1��Ū��Ҫhook�ĺ���Func�Ķ���
//2���ҵ��ú���Func�ĵ�ַ
//3��д��T_MyFunc,�����潫�������� MyFunc����Ȼ����ת��Func����ִ��
//4��ʵ�� MyFunc�����������Լ��Ĵ���
//5��inline hook������ʵ��inlinehook����Func������ת��T_MyFuncִ�С���DriverEntry�����
//6��inline hookж�غ�������DriverUnload�����



typedef NTSTATUS (*FuncDefine)(
					PEPROCESS Process,
					NTSTATUS ExitStatus
					);
FuncDefine FuncAddress= NULL;

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

PVOID GetFunctionAddressFromKernelMemory(VOID)
{

	ULONG						size			= 0;
	ULONG						index			= 0;
	PULONG						buf				= NULL;
	ULONG						i				= 0;
	PSYSTEM_MODULE_INFORMATION	module			= NULL;
	PVOID						driverAddress	= 0;
	ULONG						ntosknlBase		= 0;
	ULONG						ntosknlEndAddr	= 0;
	ULONG						curAddr			= 0;
	NTSTATUS					status			= 0;
	ULONG						retAddr			= 0;

	// ���ڴ��еĺ�����������
	ULONG code1_sp2=0x8b55ff8b,code2_sp2=0xa16456ec,code3_sp2=0x00000124,code4_sp2=0x3b08758b;

	NtQuerySystemInformation(SystemModuleInformation,&size, 0, &size);
	if(NULL==(buf = (PULONG)ExAllocatePoolWithTag(PagedPool, size, 'NLNI')))
	{
		DbgPrint("failed alloc memory failed \n");
		return 0;
	}

	status=NtQuerySystemInformation(SystemModuleInformation,buf, size , 0);
	if(!NT_SUCCESS( status ))
	{
		DbgPrint("failed query\n");
		return 0;
	}

	module = (PSYSTEM_MODULE_INFORMATION)(( PULONG )buf + 1);
	ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
	ntosknlBase=(ULONG)module->Base;
	curAddr=ntosknlBase;
	ExFreePool(buf);

	for (i=curAddr;i<=ntosknlEndAddr;i++)
	{
		if ((*((ULONG *)i)==code1_sp2)&&
			(*((ULONG *)(i+4))==code2_sp2)&&
			(*((ULONG *)(i+8))==code3_sp2)&&
			(*((ULONG*)(i+12))==code4_sp2)) 

		{
			retAddr=i;
			DbgPrint("adress is:%x",retAddr);
			return (PVOID)retAddr;
			
		}
	}
	return NULL;
}

ULONG GetFunctionAddr( IN PCWSTR FunctionName)

{
	UNICODE_STRING UniCodeFunctionName;

	RtlInitUnicodeString( &UniCodeFunctionName,FunctionName );
	return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );
}



NTSTATUS CheckFuncIsHook()
{
	int				i		= 0;
	char			*addr	= (char *)FuncAddress;
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

int MyFunc(PEPROCESS Process,
		   NTSTATUS ExitStatus
		   )
{
	DbgPrint("MyFunc hello\n");
	return 1;
}

_declspec(naked) T_MyFunc(
						PEPROCESS Process,
						NTSTATUS ExitStatus
						)
{
	_asm
	{
			mov edi, edi
			push ebp
			mov ebp ,esp
			//����ѹջ������MyFunc
			push [ebp+0ch]
			push [ebp+8]
			call MyFunc 
			cmp eax,1
			jz end
			mov eax,FuncAddress 
			add eax,5 
			jmp eax
			
end:
		//�ָ�ջ
		pop ebp
		retn 8
	}
}


VOID InlineHookFunc()
{ 

	int				JmpOffSet	= 0;
	unsigned char	JmpCode[5]	= { 0xe9, 0x00, 0x00, 0x00, 0x00 };
	KIRQL			oldIrql		= 0;

	if (FuncAddress == 0)
	{
		DbgPrint("Func NOT FOUND\n");
		return;
	}

	DbgPrint("Func is found at:0x%08x\n", (ULONG)FuncAddress );

	DbgPrint("T_MyFunc is:%x\n",T_MyFunc);
	JmpOffSet= (char*)T_MyFunc - (char*)FuncAddress - 5;
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
	RtlCopyMemory ( FuncAddress, JmpCode, 5 );
	DbgPrint("FuncAddress is hook now \n");
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
	// 	��win2000�������ֽ�
	// 	push ebp
	// 	mov ebp, esp
	// 		����
	// 	����winxp�Լ�����ϵͳ�ϣ����������ֽ�
	// 	mov edi, edi
	// 	push ebp
	// 	mov ebp, esp
	// 	����������

	//�ָ�HOOK

	KIRQL			oldIrql = 0;
	LARGE_INTEGER   Delay	= {0};
	unsigned char	Code[5]	= {0x8b,0xff,0x55,0x8b,0xec};
	
	Delay.QuadPart = -5000000;
    KeDelayExecutionThread(KernelMode, TRUE, &Delay);
	oldIrql = KeRaiseIrqlToDpcLevel();
	__asm
	{
		CLI             
		MOV   eax, CR0     
		AND   eax, NOT 10000H 
		MOV   CR0, eax
	}
	
	RtlCopyMemory ( FuncAddress, Code, 5 );
	__asm
	{
		MOV   eax, CR0
		OR    eax, 10000H
		MOV   CR0, eax
		STI
	}
	KeLowerIrql(oldIrql);

	DbgPrint("Goodbye driver\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	//δ�����ĺ���
	FuncAddress = GetFunctionAddressFromKernelMemory();
	//�����ĺ���
	//FuncAddress = GetFunctionAddr(L"FuncName");

	if(STATUS_SUCCESS != CheckFuncIsHook())
	{
		DbgPrint("Func Match Failed !");
		return STATUS_UNSUCCESSFUL;
	}
	//inline hook��
	InlineHookFunc();

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
	
}