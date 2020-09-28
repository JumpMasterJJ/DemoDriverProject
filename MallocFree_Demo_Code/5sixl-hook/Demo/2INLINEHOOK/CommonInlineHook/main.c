#include <ntddk.h>

//如何对函数做inlinehook?
//首先，弄清楚您要inlinehook的函数的定义。
//然后，获得要inline hook的函数的地址：
//如果是未导出的，根据特征码，暴力搜索内存；
//如果是导出的，可以直接使用函数名称做为它的地址或者使用MmGetSystemRoutineAddress
//拿到它的地址。如：
//NTKERNELAPI
//BOOLEAN
//KeInsertQueueApc (
//				  IN PKAPC        Apc,
//				  IN PVOID        SystemArgument1,
//				  IN PVOID        SystemArgument2,
//				  IN KPRIORITY    Increment
//				  );
//那么KeInsertQueueApc就是该函数的首地址了。注意加上NTKERNELAPI。否则得用MmGetSystemRoutineAddress来拿地址
//
//拿到地址后，就可以做inlineHOOK了。
//将该地址的前五个字节，换成jmp T_MyFunc - Func - 5这个地方
//在T_MyFunc里压栈参数，调用MyFunc。执行完MyFunc之后，再JUMP到Func+5的地方执行。
//在卸载函数里，恢复Func，去掉inline hook

//所以，inlinehook一个Func函数，有如下几个任务：
//1。弄清要hook的函数Func的定义
//2。找到该函数Func的地址
//3。写出T_MyFunc,在里面将参数传给 MyFunc处理，然后跳转到Func后面执行
//4。实现 MyFunc函数，做你自己的处理
//5。inline hook函数，实现inlinehook，将Func函数跳转到T_MyFunc执行。在DriverEntry里调用
//6。inline hook卸载函数，在DriverUnload里调用



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

	// 在内存中的函数的特征码
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
			//参数压栈，传给MyFunc
			push [ebp+0ch]
			push [ebp+8]
			call MyFunc 
			cmp eax,1
			jz end
			mov eax,FuncAddress 
			add eax,5 
			jmp eax
			
end:
		//恢复栈
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
	// 	在win2000上是三字节
	// 	push ebp
	// 	mov ebp, esp
	// 		　　
	// 	到了winxp以及后续系统上，则变成了五字节
	// 	mov edi, edi
	// 	push ebp
	// 	mov ebp, esp
	// 	函数的序言

	//恢复HOOK

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
	//未导出的函数
	FuncAddress = GetFunctionAddressFromKernelMemory();
	//导出的函数
	//FuncAddress = GetFunctionAddr(L"FuncName");

	if(STATUS_SUCCESS != CheckFuncIsHook())
	{
		DbgPrint("Func Match Failed !");
		return STATUS_UNSUCCESSFUL;
	}
	//inline hook它
	InlineHookFunc();

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
	
}