#include<ntddk.h>
#include "xde.h"

ULONG pSysenterAddr = 0;           //sysenter地址
UCHAR uOrigSysenterHead[8] = {0};//保存原来的八个字节函数头
PUCHAR pMovedSysenterCode = NULL; //把原来的KiFastCall函数头保存在这里，最后再跳回去
ULONG ulIndex = 0;                   //记录服务ID
__declspec(naked) void MyKiFastCallEntry(void)
{
  __asm{
            pop  edi     //因为用到了edi来跳转 这里恢复
             mov  ulIndex, eax  //得到服务ID
  }
  __asm{  
           pushad
           push fs
             push 0x30
            pop fs
  }
  
  DbgPrint("Service ID:%X",ulIndex);

  __asm{
             pop fs
             popad    
    jmp pMovedSysenterCode //第二跳,跳转到原来的函数头代码 
  }
  
}
//////////////////////////////////////////////////////
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{    
  __asm{
    cli
    mov  eax,cr0
    and  eax,not 10000h
    mov  cr0,eax
  }

  RtlCopyMemory((PVOID)pSysenterAddr,uOrigSysenterHead,8);//把原来函数头的八个字节恢复

  __asm
  {
    mov  eax,cr0
    or   eax,10000h
    mov  cr0,eax
    sti
  }
  ExFreePool(pMovedSysenterCode); // 释放分配的内存
  DbgPrint("Unload sysenterHook");
}
////////////////////////////////////////////////////////

NTSTATUS HookSysenter()
{
  UCHAR  JmpEnterCode[8] = { 0x57,          //push edi 
							 0xBF,0,0,0,0,  //mov  edi,0000-->要跳转的地址
                             0xFF,0xE7};    //jmp  edi

  UCHAR  JmpCode[]={0xE9,0,0,0,0};//跳转到原来执行的地址

  int				nCopyLen		= 0;
  int				nPos			= 0;
  int				length			= 0;
  struct xde_instr	instr			= {0};


  __asm
  {
          mov ecx,0x176
          rdmsr
          mov pSysenterAddr,eax  //得到KiFastCallEntry地址
  }
  DbgPrint("pSysenterAddr:0x%08X",pSysenterAddr);

  while (nCopyLen < 8)//我们要改写的函数头至少需要8字节 这里计算实际需要COPY的代码长度 因为我们不能把一条完整的指令打断
  {
	length = xde_disasm((unsigned char *)(pSysenterAddr + nCopyLen), &instr);
	if (length == 0)
	{
		DbgPrint("xde_disasm returned 0!\n");
		return STATUS_UNSUCCESSFUL;
	}
	nCopyLen += length;
  }
 
  //备份头上的指令+后面的跳转指令
 
  pMovedSysenterCode = ExAllocatePoolWithTag(NonPagedPool,20, 'TESS');

  RtlCopyMemory(uOrigSysenterHead,(PVOID)pSysenterAddr,8);

  *((ULONG*)(JmpCode+1)) = (pSysenterAddr + nCopyLen) - ((ULONG)pMovedSysenterCode + nCopyLen)- 5;//计算跳转地址

  RtlCopyMemory(pMovedSysenterCode,(PVOID)pSysenterAddr,nCopyLen); //把原来的函数头放到新分配的内存
  RtlCopyMemory((PVOID)(pMovedSysenterCode + nCopyLen),JmpCode,5);

  //开始HOOK

  *((ULONG*)(JmpEnterCode+2)) = (ULONG)MyKiFastCallEntry; //SYSENTER要跳转的地址
  

  __asm
  {
    cli
    mov  eax,cr0
    and  eax,not 10000h
    mov  cr0,eax
  }

  RtlCopyMemory((PVOID)pSysenterAddr,JmpEnterCode,8);//把改写原来函数头

  __asm
  {
    mov  eax,cr0
    or   eax,10000h
    mov  cr0,eax
    sti
  }

  return STATUS_SUCCESS;

}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
					 PUNICODE_STRING RegistryPath)
{

  DriverObject->DriverUnload = OnUnload;
  HookSysenter();
  return STATUS_SUCCESS;
}    
