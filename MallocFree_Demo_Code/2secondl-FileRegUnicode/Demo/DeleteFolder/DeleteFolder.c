#include <ntddk.h>

//此驱动删除的文件夹是 C:\hello
#define folderName L"\\??\\C:\\hello"

typedef struct _FILE_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

NTKERNELAPI NTSTATUS ZwQueryDirectoryFile
(
 HANDLE FileHandle,
 HANDLE Event,
 PIO_APC_ROUTINE ApcRoutine,
 PVOID ApcContext,
 PIO_STATUS_BLOCK IoStatusBlock,
 PVOID FileInformation,
 ULONG Length,
 FILE_INFORMATION_CLASS FileInformationClass,
 BOOLEAN ReturnSingleEntry,
 PUNICODE_STRING FileName,
 BOOLEAN RestartScan
 );

NTSTATUS
ZwDeleteFile
(
IN POBJECT_ATTRIBUTES  ObjectAttributes
);



VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS myOpenFile(PUNICODE_STRING puFileName,PHANDLE hFile);
NTSTATUS myDeleteFile(PUNICODE_STRING puFileName);
NTSTATUS myDeleteFolder(PUNICODE_STRING puFolderName);
BOOLEAN myIsDirectory(PUNICODE_STRING puFileName);
NTSTATUS myQueryDirectoryFile(HANDLE hFolder,PUNICODE_STRING puFolderPath);
NTSTATUS myOpenFolder(PUNICODE_STRING puFolderName,PHANDLE hFolder);


NTSTATUS DriverEntry(
					 IN PDRIVER_OBJECT pDriverObject,
					 IN PUNICODE_STRING pRegistryPath)
{
	UNICODE_STRING uFolderName = {0};
	NTSTATUS		status = 0;
	WCHAR			fileFullPath[1024] = folderName;
	
	DbgPrint("Hello, world\n");

	RtlInitUnicodeString(&uFolderName,fileFullPath);
	status = myDeleteFolder(&uFolderName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Delete Folder Failed\n");
	}
	else
	{
		DbgPrint("Delete Folder Successfully\n");
	}
	

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye world!\n");
}


NTSTATUS myOpenFile(PUNICODE_STRING puFileName,PHANDLE hFile){

	OBJECT_ATTRIBUTES	objAttrib = {0};
	IO_STATUS_BLOCK		io_status = {0};
	//HANDLE				hFile = NULL;
	NTSTATUS			status = 0;


	InitializeObjectAttributes(
		&objAttrib,
		puFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	
	status = ZwCreateFile(
		hFile,
		GENERIC_ALL,
		&objAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	DbgPrint("%08X\n",status);
	return status;
}


NTSTATUS myOpenFolder(PUNICODE_STRING puFolderName,PHANDLE hFolder){

	OBJECT_ATTRIBUTES	objAttrib = {0};
	IO_STATUS_BLOCK		io_status = {0};
	//HANDLE				hFile = NULL;
	NTSTATUS			status = 0;


	InitializeObjectAttributes(
		&objAttrib,
		puFolderName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(
		hFolder, 
		GENERIC_ALL,
		&objAttrib, 
		&io_status, 
		NULL, 
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
		FILE_OPEN_IF,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 
		0);
	DbgPrint("%08X\n",status);
	return status;
}


//好像用不了 ZwDeleteFile
//我先试试吧
NTSTATUS myDeleteFile(PUNICODE_STRING puFileName) {

	NTSTATUS			status = 0;
	OBJECT_ATTRIBUTES	oa = {0};


	InitializeObjectAttributes(
		&oa,
		puFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwDeleteFile(&oa);
	DbgPrint("Deleting %wZ\n",puFileName);
	DbgPrint("Error Code %08X\n",status);
	return status;
}


BOOLEAN myIsDirectory(PUNICODE_STRING puFileName) {
	ULONG							dwRtn 		= 0;
	NTSTATUS						ntStatus	= STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES				objAttr		= {0};
	FILE_NETWORK_OPEN_INFORMATION 	info		= {0};


	RtlZeroMemory(&info, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	InitializeObjectAttributes(
		&objAttr,
		puFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);
	ntStatus = ZwQueryFullAttributesFile(
		&objAttr,
		&info);
	if (NT_SUCCESS(ntStatus))
	{
		dwRtn = info.FileAttributes;
	}

	return (dwRtn & FILE_ATTRIBUTE_DIRECTORY);
}


NTSTATUS myQueryDirectoryFile(HANDLE hFolder,PUNICODE_STRING puFolderPath){
	
	NTSTATUS			status = 0;
	IO_STATUS_BLOCK		ioStatus = {0};
	PFILE_BOTH_DIR_INFORMATION		fileInfo = NULL;
	ULONG				Length = 0;
	PVOID				fileInfoBase = NULL;
	WCHAR				wFileName[512] = {0};
	UNICODE_STRING		uTemp = {0};
	UNICODE_STRING		uOne = {0};
	UNICODE_STRING		uTwo = {0};
	WCHAR				wFullPath[512] = L"hello wolrd nihao shijie 123456789 123456789";
	//因为RtlCopyUnicodeString的特殊原因所以取了个特别长的名字
	UNICODE_STRING		uFullPath = {0};
	

	RtlInitUnicodeString(&uFullPath,wFullPath);
	RtlCopyUnicodeString(&uFullPath,puFolderPath);
	DbgPrint("after RtlCopyUnicodeString(%wZ)\n",&uFullPath);
	
	Length = (2 * 4096 + sizeof(FILE_BOTH_DIR_INFORMATION)) * 0x2000;

	fileInfoBase = ExAllocatePoolWithTag(PagedPool,Length,'fold');
	fileInfo = fileInfoBase;
	
	status = ZwQueryDirectoryFile(
		hFolder,
		NULL,
		NULL,
		NULL,
		&ioStatus,
		fileInfo,
		Length,
		FileBothDirectoryInformation,
		FALSE,
		NULL,
		FALSE);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(fileInfoBase);
		DbgPrint("ZwQueryDirectoryFile Failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&uOne,L".");
	RtlInitUnicodeString(&uTwo,L"..");
	while (TRUE) 
	{
		RtlZeroMemory(wFileName,1024);
		RtlCopyMemory(wFileName,fileInfo->FileName,fileInfo->FileNameLength);
		RtlInitUnicodeString(&uTemp,wFileName);
		//判断是否是上级目录或者本目录
		if (0 != RtlCompareUnicodeString(&uTemp,&uOne,TRUE) 
			&& 
			0 != RtlCompareUnicodeString(&uTemp,&uTwo,TRUE))
		{
			if (fileInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				//目录
				DbgPrint("[DIRECTORY]\t%wZ\n", &uTemp);
				//Delete folder , folder name is Temp + puFolderPath
				DbgPrint("uFullPath:%wZ\n",&uFullPath);
				DbgPrint("uTemp:%wZ\n",&uTemp);
				RtlAppendUnicodeToString(&uFullPath,L"\\");
				RtlAppendUnicodeStringToString(&uFullPath,&uTemp);
				DbgPrint("myDeleteFolder(%wZ)\n",&uFullPath);
				status = myDeleteFolder(&uFullPath);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("myDeleteFolder Failed\n");
					return status;
				}
			}
			else 
			{
				//文件
				DbgPrint("[FILE]\t\t%wZ\n", &uTemp);
				//Delete file , file name is Temp + upFolderPath
				DbgPrint("uFullPath:%wZ\n",&uFullPath);
				DbgPrint("uTemp:%wZ\n",&uTemp);
				RtlAppendUnicodeToString(&uFullPath,L"\\");
				RtlAppendUnicodeStringToString(&uFullPath,&uTemp);
				DbgPrint("myDeleteFile(%wZ)\n",&uFullPath);
				status = myDeleteFile(&uFullPath);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("myDeleteFile Failed\n");
					return status;
				}
			}
		}
		//遍历完成
		if (0 == fileInfo->NextEntryOffset)
		{
			break;
		}
		//临时节点指向链表的下一个节点
		fileInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileInfo + fileInfo->NextEntryOffset);
		//重置FolderPath
		RtlCopyUnicodeString(&uFullPath,puFolderPath);
	}

	ExFreePool(fileInfoBase);
	return STATUS_SUCCESS;

}


NTSTATUS myDeleteFolder(PUNICODE_STRING puFolderName) {
	HANDLE		hFolder;
	NTSTATUS	status = 0;

	if (!myIsDirectory(puFolderName))
	{
		myDeleteFile(puFolderName);
		return STATUS_SUCCESS;
	}
	
	//遍历文件夹
	status = myOpenFolder(puFolderName,&hFolder);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("myOpenFile Failed\n");
		return status;
	}
	DbgPrint("myQueryDirectoryFile(%wZ)\n",puFolderName);
	status = myQueryDirectoryFile(hFolder,puFolderName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("myQueryDirectoryFile Failed\n");
		ZwClose(hFolder);
		return status;
	}

	myDeleteFile(puFolderName);	
	ZwClose(hFolder);
	return status;
}