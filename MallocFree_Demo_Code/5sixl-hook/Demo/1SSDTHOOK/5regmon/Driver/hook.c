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

NTSTATUS Hook_NtSetValueKey(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN ULONG  TitleIndex  OPTIONAL,
    IN ULONG  Type,
    IN PVOID  Data,
    IN ULONG  DataSize);

typedef NTSTATUS (*ZWSETVALUEKEY)(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN ULONG  TitleIndex  OPTIONAL,
    IN ULONG  Type,
    IN PVOID  Data,
    IN ULONG  DataSize
);

static ZWSETVALUEKEY            OldZwSetValueKey;

NTSTATUS Hook_NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID Data,
	IN ULONG DataSize
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOL skipOriginal = FALSE;
	UNICODE_STRING CapturedName;
	WCHAR wszPath[MAX_PATH] = {0};
	R3_RESULT CallBackResult = R3Result_Pass;
	
	__try
	{
		UNICODE_STRING keyName;
		UNICODE_STRING uTarget;
		
		RtlZeroMemory(&keyName, sizeof(UNICODE_STRING));
		RtlZeroMemory(&uTarget, sizeof(UNICODE_STRING));
		
		if((ExGetPreviousMode() == KernelMode) || 
			(ValueName == NULL))
		{
			skipOriginal = TRUE;
			status =  OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);
			
			return status;
		}
		
		if(MyProbeKeyHandle(KeyHandle, KEY_SET_VALUE) == FALSE)
		{
			
			skipOriginal = TRUE;
			status =  OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);
			return status;
		}
		
		if(MyObQueryObjectName(KeyHandle, &keyName, TRUE) == FALSE)
		{
			skipOriginal = TRUE;
			status =  OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);
			return status;
		}
		
		
		uTarget.Buffer = wszPath;
		uTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		RtlCopyUnicodeString(&uTarget, &keyName);
		RtlFreeUnicodeString(&keyName);
		
		if (L'\\' != uTarget.Buffer[uTarget.Length/sizeof(WCHAR) - 1])
			RtlAppendUnicodeToString(&uTarget, L"\\");
		
		CapturedName = ProbeAndReadUnicodeString(ValueName);
		
		ProbeForRead(CapturedName.Buffer,
			CapturedName.Length,
			sizeof(WCHAR));
		
		RtlAppendUnicodeStringToString(&uTarget, &CapturedName);
		DbgPrint("Key:%wZ\n", &uTarget);
		
		
		if (CallBackResult == R3Result_Block)
		{
			return STATUS_ACCESS_DENIED;
		}
		
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		
	}
	
	if(skipOriginal)
		return status;
	
	return OldZwSetValueKey(KeyHandle,
		ValueName,
		TitleIndex,
		Type,
		Data,
		DataSize);
}

NTSTATUS Hook_ZwCreateFile(
						   OUT PHANDLE            FileHandle,
						   IN ACCESS_MASK          DesiredAccess,
						   IN POBJECT_ATTRIBUTES  ObjectAttributes,
						   OUT PIO_STATUS_BLOCK    IoStatusBlock,
						   IN PLARGE_INTEGER      AllocationSize OPTIONAL,
						   IN ULONG                FileAttributes,
						   IN ULONG                ShareAccess,
						   IN ULONG                CreateDisposition,
						   IN ULONG                CreateOptions,
						   IN PVOID                EaBuffer OPTIONAL,
  IN ULONG                EaLength );


#pragma alloc_text(PAGE, Hook_ZwCreateFile)

typedef NTSTATUS (*ZWCREATEFILE)(
								 OUT PHANDLE            FileHandle,
								 IN ACCESS_MASK          DesiredAccess,
								 IN POBJECT_ATTRIBUTES  ObjectAttributes,
								 OUT PIO_STATUS_BLOCK    IoStatusBlock,
								 IN PLARGE_INTEGER      AllocationSize OPTIONAL,
								 IN ULONG                FileAttributes,
								 IN ULONG                ShareAccess,
								 IN ULONG                CreateDisposition,
								 IN ULONG                CreateOptions,
								 IN PVOID                EaBuffer OPTIONAL,
  IN ULONG                EaLength );

static ZWCREATEFILE                OldZwCreateFile;

NTSTATUS Hook_ZwCreateFile(
						   OUT PHANDLE            FileHandle,
						   IN ACCESS_MASK          DesiredAccess,
						   IN POBJECT_ATTRIBUTES  ObjectAttributes,
						   OUT PIO_STATUS_BLOCK    IoStatusBlock,
						   IN PLARGE_INTEGER      AllocationSize OPTIONAL,
						   IN ULONG                FileAttributes,
						   IN ULONG                ShareAccess,
						   IN ULONG                CreateDisposition,
						   IN ULONG                CreateOptions,
						   IN PVOID                EaBuffer OPTIONAL,
						   IN ULONG                EaLength )
{
    NTSTATUS rc;
	
    rc = OldZwCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,
		AllocationSize,FileAttributes,ShareAccess,CreateDisposition,
		CreateOptions,EaBuffer,EaLength);
	
    return rc;
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
    

    OldZwSetValueKey                = (ZWSETVALUEKEY) InterlockedExchange((PLONG)
                                                        &SDT(ZwSetValueKey),   
                                                        (LONG)Hook_NtSetValueKey);
    OldZwCreateFile = (ZWCREATEFILE)InterlockedExchange((PLONG)&SDT(ZwCreateFile),
                                                        (LONG)Hook_ZwCreateFile);

    
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

    InterlockedExchange( (PLONG) &SDT(ZwSetValueKey),  (LONG) OldZwSetValueKey);
    InterlockedExchange( (PLONG) &SDT(ZwCreateFile),  (LONG) OldZwCreateFile);

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
}


