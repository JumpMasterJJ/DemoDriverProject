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



NTSTATUS Hook_ZwOpenSection(
  OUT PHANDLE            SectionHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes );

NTSTATUS Hook_ZwCreateSection(
  OUT PHANDLE            SectionHandle,
  IN ULONG                DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER      MaximumSize OPTIONAL,
  IN ULONG                PageAttributess,
  IN ULONG                SectionAttributes,
  IN HANDLE              FileHandle OPTIONAL );

typedef NTSTATUS (*ZWCREATESECTION)(
  OUT PHANDLE            SectionHandle,
  IN ULONG                DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER      MaximumSize OPTIONAL,
  IN ULONG                PageAttributess,
  IN ULONG                SectionAttributes,
  IN HANDLE              FileHandle OPTIONAL );

typedef NTSTATUS (*ZWOPENSECTION)(
  OUT PHANDLE            SectionHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes );


static ZWCREATESECTION            OldZwCreateSection;
static ZWOPENSECTION            OldZwOpenSection;


NTSTATUS Hook_ZwOpenSection(
  OUT PHANDLE            SectionHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes )
{
    NTSTATUS rc;
    rc = OldZwOpenSection(SectionHandle,DesiredAccess,ObjectAttributes);
    return rc;
}

NTSTATUS NTAPI HOOK_NtCreateSection(PHANDLE SectionHandle,
				  ACCESS_MASK DesiredAccess,
				  POBJECT_ATTRIBUTES ObjectAttributes,
				  PLARGE_INTEGER SectionSize,
				  ULONG Protect,
				  ULONG Attributes,
				  HANDLE FileHandle)//代理函数 
{
	PFILE_OBJECT    			FileObject = NULL; 
	POBJECT_NAME_INFORMATION 	wcFilePath = NULL;
	ANSI_STRING 				dst = {0};
	UNICODE_STRING				ustrProcessPath = {0};
	WCHAR						wszProcessPath[MAX_PATH] = {0};
	NTSTATUS					ntStatus = 0;

	__try
	{
		if (Protect & (PAGE_EXECUTE/*|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY*/)&&
			(Attributes == SEC_IMAGE) && 
		    FileHandle)
		{
			if (NT_SUCCESS(ObReferenceObjectByHandle(FileHandle,0,NULL,KernelMode,&FileObject,NULL)))//获取文件对象
			{
				//获取FileObject对应的文件全路径
				if (IoQueryFileDosDeviceName(FileObject, &wcFilePath)==STATUS_SUCCESS)//获取文件对象所对应的文件Dos设备名称,即是全路径
				{
					if (RtlCompareMemory(wcFilePath->Name.Buffer+wcFilePath->Name.Length/2-wcslen(L"Winobj.exe"),L"Winobj.exe",wcslen(L"Winobj.exe")*sizeof(WCHAR))==wcslen(L"Winobj.exe")*sizeof(WCHAR)
						&& RtlCompareMemory(wcFilePath->Name.Buffer+wcFilePath->Name.Length/2-wcslen(L"PopupClient.exe"),
						L"PopupClient.exe",wcslen(L"PopupClient.exe")*sizeof(WCHAR))!=wcslen(L"PopupClient.exe")*sizeof(WCHAR))
					{
						DbgPrint("Target:%wZ\n",&wcFilePath->Name);
						//PPID = HandleToUlong(PsGetCurrentProcessId());
						ustrProcessPath.Buffer = wszProcessPath;
						ustrProcessPath.Length = 0;
						ustrProcessPath.MaximumLength = sizeof(wszProcessPath);
						ntStatus = ntGetProcessFullNameByPid(PsGetCurrentProcessId(), &ustrProcessPath);
						DbgPrint("Parent:%wZ\n", &ustrProcessPath);
						if (NT_SUCCESS(ntStatus))
						{
							if (GetResultFromUser()==R3Result_Pass)
							{
								ntStatus = OldZwCreateSection(
												SectionHandle,
												DesiredAccess,
												ObjectAttributes,
												SectionSize,
												Protect,
												Attributes,
												FileHandle);
								ObDereferenceObject(FileObject);//放弃对FileObject的引用
								ExFreePool(wcFilePath);
								return ntStatus;	
							}
							ObDereferenceObject(FileObject);//放弃对FileObject的引用
							ExFreePool(wcFilePath);
							return STATUS_SUCCESS;
						}
					}
					ExFreePool(wcFilePath);//IoQueryFileDosDeviceName获取的OBJECT_NAME_INFORMATION 需要手动释放
				}
				ObDereferenceObject(FileObject);//放弃对FileObject的引用
			}        
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return OldZwCreateSection(SectionHandle,DesiredAccess,ObjectAttributes,SectionSize,Protect,Attributes,FileHandle);
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
    
    OldZwCreateSection                = (ZWCREATESECTION)InterlockedExchange((PLONG)
                                                        &SDT(ZwCreateSection),
                                                        (LONG)HOOK_NtCreateSection);
    OldZwOpenSection                = (ZWOPENSECTION)InterlockedExchange((PLONG)
                                                        &SDT(ZwOpenSection),
                                                        (LONG)Hook_ZwOpenSection);

    
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

    InterlockedExchange( (PLONG) &SDT(ZwCreateSection)            ,  (LONG) OldZwCreateSection            );
    InterlockedExchange( (PLONG) &SDT(ZwOpenSection)            ,  (LONG) OldZwOpenSection                );

    __asm
    {
        push    eax
        mov        eax, CR0
        or        eax, NOT 0FFFEFFFFh
        mov        CR0, eax
        pop        eax
    }
}


