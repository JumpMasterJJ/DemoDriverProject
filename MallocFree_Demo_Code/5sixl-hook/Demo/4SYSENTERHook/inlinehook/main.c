#include<ntddk.h>
#include "xde.h"

ULONG pSysenterAddr = 0;           //sysenter��ַ
UCHAR uOrigSysenterHead[8] = {0};//����ԭ���İ˸��ֽں���ͷ
PUCHAR pMovedSysenterCode = NULL; //��ԭ����KiFastCall����ͷ������������������ȥ
ULONG ulIndex = 0;                   //��¼����ID
__declspec(naked) void MyKiFastCallEntry(void)
{
  __asm{
            pop  edi     //��Ϊ�õ���edi����ת ����ָ�
             mov  ulIndex, eax  //�õ�����ID
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
    jmp pMovedSysenterCode //�ڶ���,��ת��ԭ���ĺ���ͷ���� 
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

  RtlCopyMemory((PVOID)pSysenterAddr,uOrigSysenterHead,8);//��ԭ������ͷ�İ˸��ֽڻָ�

  __asm
  {
    mov  eax,cr0
    or   eax,10000h
    mov  cr0,eax
    sti
  }
  ExFreePool(pMovedSysenterCode); // �ͷŷ�����ڴ�
  DbgPrint("Unload sysenterHook");
}
////////////////////////////////////////////////////////

NTSTATUS HookSysenter()
{
  UCHAR  JmpEnterCode[8] = { 0x57,          //push edi 
							 0xBF,0,0,0,0,  //mov  edi,0000-->Ҫ��ת�ĵ�ַ
                             0xFF,0xE7};    //jmp  edi

  UCHAR  JmpCode[]={0xE9,0,0,0,0};//��ת��ԭ��ִ�еĵ�ַ

  int				nCopyLen		= 0;
  int				nPos			= 0;
  int				length			= 0;
  struct xde_instr	instr			= {0};


  __asm
  {
          mov ecx,0x176
          rdmsr
          mov pSysenterAddr,eax  //�õ�KiFastCallEntry��ַ
  }
  DbgPrint("pSysenterAddr:0x%08X",pSysenterAddr);

  while (nCopyLen < 8)//����Ҫ��д�ĺ���ͷ������Ҫ8�ֽ� �������ʵ����ҪCOPY�Ĵ��볤�� ��Ϊ���ǲ��ܰ�һ��������ָ����
  {
	length = xde_disasm((unsigned char *)(pSysenterAddr + nCopyLen), &instr);
	if (length == 0)
	{
		DbgPrint("xde_disasm returned 0!\n");
		return STATUS_UNSUCCESSFUL;
	}
	nCopyLen += length;
  }
 
  //����ͷ�ϵ�ָ��+�������תָ��
 
  pMovedSysenterCode = ExAllocatePoolWithTag(NonPagedPool,20, 'TESS');

  RtlCopyMemory(uOrigSysenterHead,(PVOID)pSysenterAddr,8);

  *((ULONG*)(JmpCode+1)) = (pSysenterAddr + nCopyLen) - ((ULONG)pMovedSysenterCode + nCopyLen)- 5;//������ת��ַ

  RtlCopyMemory(pMovedSysenterCode,(PVOID)pSysenterAddr,nCopyLen); //��ԭ���ĺ���ͷ�ŵ��·�����ڴ�
  RtlCopyMemory((PVOID)(pMovedSysenterCode + nCopyLen),JmpCode,5);

  //��ʼHOOK

  *((ULONG*)(JmpEnterCode+2)) = (ULONG)MyKiFastCallEntry; //SYSENTERҪ��ת�ĵ�ַ
  

  __asm
  {
    cli
    mov  eax,cr0
    and  eax,not 10000h
    mov  cr0,eax
  }

  RtlCopyMemory((PVOID)pSysenterAddr,JmpEnterCode,8);//�Ѹ�дԭ������ͷ

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
