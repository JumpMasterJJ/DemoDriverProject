#include "ntddk.h"
#include <windef.h>

extern POBJECT_TYPE *PsProcessType;

VOID InlineHookObReferenceObjectByHandle();
VOID UnHook();

T_ObReferenceObjectByHandle(
    IN HANDLE  Handle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_TYPE  ObjectType  OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    OUT PVOID  *Object,
    OUT POBJECT_HANDLE_INFORMATION  HandleInformation  OPTIONAL
    );

char* ProtectName = "notepad.exe";

int  MyObReferenceObjectByHandle(
    IN HANDLE  Handle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_TYPE  ObjectType  OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    OUT PVOID  *Object,
    OUT POBJECT_HANDLE_INFORMATION  HandleInformation  OPTIONAL
    )
{
 
	PEPROCESS			Process		= NULL;
	KIRQL				oldIrql		= 0;
	int					JmpOffSet	= 0;
	UCHAR				Code[5]		= {0x8b,0xff,0x55,0x8b,0xec};
	UCHAR				JmpCode[5]	= {0xe9,0x00,0x00,0x00,0x00 };

	
	if(*PsProcessType==ObjectType)
	{

	 	oldIrql = KeRaiseIrqlToDpcLevel();
		__asm
		{
			CLI             
			MOV		eax, CR0     
			AND		eax, NOT 10000H 
			MOV		CR0, eax
		}
	
		//·ÀÖ¹ÖØÈë
		RtlCopyMemory ( ObReferenceObjectByHandle, Code, 5 );
		
		
		ObReferenceObjectByHandle(Handle,
			DesiredAccess,
			ObjectType,
			AccessMode,
			&Process,
			NULL);
		if (_stricmp((char*)((char*)Process+0x174), 
			ProtectName) == 0 )
		  {
			  JmpOffSet= (char*)T_ObReferenceObjectByHandle - 
				  (char*)ObReferenceObjectByHandle - 5;
			  RtlCopyMemory ( JmpCode+1, &JmpOffSet, 4 );
			  RtlCopyMemory ( ObReferenceObjectByHandle, JmpCode, 5 );
		  	
		  
	   __asm
	   {
		   MOV		eax, CR0
		   OR		eax, 10000H
		   MOV		CR0, eax
		   STI
	   }
			
	   KeLowerIrql(oldIrql);
	   return 1;

	  }

	JmpOffSet= (char*)T_ObReferenceObjectByHandle - 
		(char*)ObReferenceObjectByHandle - 5;
	RtlCopyMemory ( JmpCode+1, &JmpOffSet, 4 );
	RtlCopyMemory ( ObReferenceObjectByHandle, JmpCode, 5 );
	
	__asm
	{
		MOV		eax, CR0
		OR		eax, 10000H
		MOV		CR0, eax
		STI
	}
	
	KeLowerIrql(oldIrql);

	}
	return 0;
}

__declspec(naked)  T_ObReferenceObjectByHandle(
    IN HANDLE  Handle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_TYPE  ObjectType  OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    OUT PVOID  *Object,
    OUT POBJECT_HANDLE_INFORMATION  HandleInformation  OPTIONAL
    )
{
	_asm
	{

	   mov     edi,edi
	   push    ebp
	   mov     ebp,esp
   
	   push   [ebp+0x1c]
	   push   [ebp+0x18]
	   push   [ebp+0x14]
	   push   [ebp+0x10]
	   push   [ebp+0xc]
	   push   [ebp+8]
  
	   call   MyObReferenceObjectByHandle   
	   cmp	  eax,1   
	   jz     end
   
	   mov   eax,ObReferenceObjectByHandle     
	   add   eax,5           
	   jmp   eax   
	end:
	   mov   [ebp+8],-1
	   mov   eax,ObReferenceObjectByHandle     
	   add   eax,5           
	   jmp   eax   
   
	}
}

VOID InlineHookObReferenceObjectByHandle()
{ 
    

	int				JmpOffSet	= 0;
	UCHAR			JmpCode[5]	= {0xe9, 0x00, 0x00, 0x00, 0x00 };
	KIRQL			oldIrql		= 0;
	
    JmpOffSet= (char*)T_ObReferenceObjectByHandle - (char*)ObReferenceObjectByHandle - 5;
    
	RtlCopyMemory ( JmpCode+1, &JmpOffSet, 4 );
    
	 oldIrql = KeRaiseIrqlToDpcLevel();
    _asm
	{
		CLI					
		MOV	EAX, CR0		
		AND EAX, NOT 10000H 
		MOV	CR0, EAX		
	}
   
    RtlCopyMemory( ObReferenceObjectByHandle, JmpCode, 5 );

    _asm 
	{
		MOV	EAX, CR0		
		OR	EAX, 10000H		
		MOV	CR0, EAX			
		STI					
	}
   KeLowerIrql(oldIrql);

}

VOID Unload(PDRIVER_OBJECT  DriverObject)
{  
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

  RtlCopyMemory ( ObReferenceObjectByHandle, Code, 5 );
  __asm
  {
	   MOV   eax, CR0
	   OR    eax, 10000H
	   MOV   CR0, eax
	   STI
	}
	KeLowerIrql(oldIrql);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING str)
{	
   DriverObject->DriverUnload = Unload;
   
   InlineHookObReferenceObjectByHandle();
   return STATUS_SUCCESS;
}