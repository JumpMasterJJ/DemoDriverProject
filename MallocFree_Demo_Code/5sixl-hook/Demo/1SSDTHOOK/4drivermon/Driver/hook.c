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


NTKERNELAPI NTSTATUS ZwLoadDriver(
  IN PUNICODE_STRING DriverServiceName );

NTSTATUS Hook_ZwLoadDriver(
  IN PUNICODE_STRING DriverServiceName );


typedef NTSTATUS (*ZWLOADDRIVER)(
  IN PUNICODE_STRING DriverServiceName );


static ZWLOADDRIVER                OldZwLoadDriver;


NTSTATUS Hook_ZwLoadDriver(
  IN PUNICODE_STRING DriverServiceName )
{
	UNICODE_STRING			uPath						= {0};
	NTSTATUS				status						= STATUS_SUCCESS;
	BOOL					skipOriginal				= FALSE;
	WCHAR					szTargetDriver[MAX_PATH]	= {0};
	WCHAR					szTarget[MAX_PATH]			= {0};
	R3_RESULT				CallBackResult				= R3Result_Pass;
	WCHAR					wszPath[MAX_PATH]			= {0};
	UNICODE_STRING ustrProcessPath = {0};
	WCHAR				wszProcessPath[MAX_PATH] = {0};
	__try
	{
		UNICODE_STRING CapturedName;
		
		if((ExGetPreviousMode() == KernelMode) || 
			(DriverServiceName == NULL))
		{
			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}
		
		uPath.Length = 0;
		uPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uPath.Buffer = wszPath;
		
		
		CapturedName = ProbeAndReadUnicodeString(DriverServiceName);
		
		ProbeForRead(CapturedName.Buffer, 
			CapturedName.Length,
			sizeof(WCHAR));
		
		RtlCopyUnicodeString(&uPath, &CapturedName);
		
		if(ntGetDriverImagePath(&uPath, szTargetDriver))
		{
			
// 			if(ntIsDosDeviceName(szTargetDriver))
// 			{
// 				if( ntGetNtDeviceName(szTargetDriver, 
// 					szTarget))
// 				{
// 					RtlStringCbCopyW(szTargetDriver, 
// 						sizeof(szTargetDriver), 
// 						szTarget);
// 				}
// 			}
			DbgPrint("Driver:%ws will be loaded\n", szTargetDriver);
			ustrProcessPath.Buffer = wszProcessPath;
			ustrProcessPath.Length = 0;
			ustrProcessPath.MaximumLength = sizeof(wszProcessPath);
			GetProcessFullNameByPid(PsGetCurrentProcessId(), &ustrProcessPath);
			DbgPrint("Parent:%wZ\n", &ustrProcessPath);

			//CallBackResult = hipsGetResultFromUser(L"加载", szTargetDriver, NULL,User_DefaultNon);
			if (CallBackResult == R3Result_Block)
			{
				return STATUS_ACCESS_DENIED;
			}
			
			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}
		
		
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		
	}
	
	if(skipOriginal)
		return status;
	
	return OldZwLoadDriver(DriverServiceName);
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
    
    OldZwLoadDriver                    = (ZWLOADDRIVER)InterlockedExchange((PLONG)
                                                        &SDT(ZwLoadDriver),
                                                        (LONG)Hook_ZwLoadDriver);

    
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

  InterlockedExchange( (PLONG) &SDT(ZwLoadDriver)                ,  (LONG) OldZwLoadDriver                );

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
}


