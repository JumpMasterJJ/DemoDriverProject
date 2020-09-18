#include <ntddk.h>

VOID OperUnicodeStr(VOID);
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverEntry(
		IN PDRIVER_OBJECT pDriverObject, 
		IN PUNICODE_STRING pRegPath)
{

	DbgPrint("Driver loaded\n");
	pDriverObject->DriverUnload = DriverUnload;

	OperUnicodeStr();

	return STATUS_SUCCESS;
}

VOID OperUnicodeStr(VOID)
{

	UNICODE_STRING 		uStr1 = {0};
	UNICODE_STRING 		uStr2 = {0};
	UNICODE_STRING		uStr3 = {0};
	UNICODE_STRING		uStr4 = {0};

	ANSI_STRING         aStr1 = {0};

	WCHAR				szHello[512] = L"Hello";
	WCHAR				szWorld[256] = L"World";
	WCHAR				szCopiedStr[1024] = L"";

	UNICODE_STRING		uHello = {0};
	UNICODE_STRING		uWorld = {0};
	UNICODE_STRING		uCopyiedStr = {0};
	

	RtlInitUnicodeString(&uStr1, L"hello"); //ֱ�ӽ�L"hello"�ַ�����ָ�븳����uStr.Buffer;
	RtlInitUnicodeString(&uStr2, L"Goodbye");

	DbgPrint("%ws\n", L"hello world");
	DbgPrint("uStr1=%wZ\n", &uStr1);
	DbgPrint("uStr2=%wZ\n", &uStr2);

	RtlInitAnsiString(&aStr1, "Ansi to unicode");
	DbgPrint("aStr1=%Z\n", &aStr1);

	RtlCopyUnicodeString(&uStr3, &uStr1);
	DbgPrint("uStr3=%wZ\n", &uStr3);//ʧ��
	//ʧ��ԭ��:MSDN��˵����.
	//RtlCopyUnicodeString��DestStr.Length�������SrcStr.Length
	//����ֻ�Ḵ��һ���ַ�

	RtlAppendUnicodeToString(&uStr1, L"world");
	DbgPrint("uStr1=%wZ\n", &uStr1);//ʧ��

	RtlAppendUnicodeStringToString(&uStr1, &uStr2);
	DbgPrint("uStr1=%wZ\n", &uStr1);//ʧ��


	if (RtlCompareUnicodeString(&uStr1, &uStr2, TRUE) == 0)//TRUE:case sensible
	{
		DbgPrint("%wZ == %wZ\n", &uStr1, &uStr2);
	}
	else
	{
		DbgPrint("%wZ != %wZ\n", &uStr1, &uStr2);
	}

	RtlAnsiStringToUnicodeString(&uStr3, &aStr1, TRUE);//TRUE: memory allocation for uStr1 and should be freed by RtlFreeUnicodeString
	DbgPrint("uStr3=%wZ\n", &uStr3);//�ɹ�
	RtlFreeUnicodeString(&uStr3);

// 	RtlAnsiStringToUnicodeString(&uStr3, &aStr1, FALSE);
// 	DbgPrint("uStr3=%wZ\n", &uStr3);//�ɹ�
// 	RtlFreeUnicodeString(&uStr3);

	RtlInitUnicodeString(&uHello, szHello);
	uHello.MaximumLength = sizeof(szHello);

	DbgPrint("uHello=%wZ\n", &uHello);
	RtlInitUnicodeString(&uWorld, szWorld);

	DbgPrint("uWorld=%wZ\n", &uWorld);
	RtlInitUnicodeString(&uCopyiedStr, szCopiedStr);
	uCopyiedStr.MaximumLength = sizeof(szCopiedStr);

	DbgPrint("uCopyiedStr=%wZ\n", &uCopyiedStr);

	RtlAppendUnicodeStringToString(&uHello, &uWorld);
	DbgPrint("uHello=%wZ\n", &uHello);

	RtlAppendUnicodeToString(&uHello, szWorld);
	DbgPrint("uHello=%wZ\n", &uHello);

	RtlCopyUnicodeString(&uCopyiedStr, &uHello);
	DbgPrint("uCopyiedStr=%wZ\n", &uCopyiedStr);

	uStr4.Buffer = ExAllocatePoolWithTag(PagedPool, (wcslen(L"Nice to meet u") + 1)*sizeof(WCHAR), 'POCU');
	if (uStr4.Buffer == NULL)
	{
		return;
	}
	RtlZeroMemory(uStr4.Buffer, (wcslen(L"Nice to meet u") + 1)*sizeof(WCHAR));
	uStr4.Length = uStr4.MaximumLength = (wcslen(L"Nice to meet u") + 1)*sizeof(WCHAR);

	//���ܵ���RtlIniUnicodeString()����ʼ��

	RtlCopyMemory(uStr4.Buffer, L"Nice to meet u", (wcslen(L"Nice to meet u")+1)*sizeof(WCHAR));
	DbgPrint("%wZ\n", &uStr4);

	ExFreePool(uStr4.Buffer);

}
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Driver unloaded!\n");
}