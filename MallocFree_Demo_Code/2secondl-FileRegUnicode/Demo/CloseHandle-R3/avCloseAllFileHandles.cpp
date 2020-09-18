#include "avCloseAllFileHandles.h"

ZWQUERYSYSTEMINFORMATION		NtQuerySystemInformation = NULL;
ZWQUERYOBJECT					NtQueryObject = NULL;
HMODULE							g_hNtDLL = NULL;

BOOL InitNTDLL()
{
	g_hNtDLL = LoadLibrary( "ntdll.dll" );
	if ( !g_hNtDLL )
	{
		return FALSE;
	}

	NtQuerySystemInformation =
		(ZWQUERYSYSTEMINFORMATION)GetProcAddress( g_hNtDLL, "NtQuerySystemInformation");

	NtQueryObject =
		(ZWQUERYOBJECT)GetProcAddress( g_hNtDLL, "NtQueryObject");

	if (NtQuerySystemInformation == NULL ||
		NtQueryObject == NULL)
	{
		return FALSE;
	}

	return TRUE;
}

VOID CloseNTDLL()
{
	if(g_hNtDLL != NULL)
	{
		FreeLibrary(g_hNtDLL);
	}
}

DWORD WINAPI IsHandleSafe(LPVOID lpParam)
{
    HANDLE hFile = (HANDLE)lpParam;
    GetFileType(hFile);
    return 0;
}

BOOL avCloseHandle(HANDLE Process, HANDLE Handle)
{
	BOOL rtn = FALSE;
	HANDLE h = 0;

	rtn = DuplicateHandle(Process, 
		Handle, 
		GetCurrentProcess( ), 
		&h, 
		0, 
		FALSE, 
		DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);

	if(rtn)
		CloseHandle(h);
	return rtn;
}

NTSTATUS avNtQueryObject(
	IN HANDLE ObjectHandle,
	IN ULONG ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL,
	IN	ULONG waitTime
    )
{
	DWORD 			dwTid=0;
	HANDLE 			hThread;
	DWORD 			dwEax;
	NTSTATUS		st;

	hThread = CreateThread(NULL,0,IsHandleSafe,ObjectHandle,0,&dwTid);
	dwEax = WaitForSingleObject(hThread,waitTime);

	if(dwEax == STATUS_TIMEOUT)
	{
		DWORD dwTimeOut = 0;

		GetExitCodeThread(hThread, &dwTimeOut);
		TerminateThread(hThread, dwTimeOut);

		CloseHandle(hThread);
		return STATUS_UNSUCCESSFUL;
	} 
	CloseHandle(hThread);
	st = NtQueryObject(ObjectHandle, ObjectInformationClass, ObjectInformation, 
		ObjectInformationLength, ReturnLength);
	return st;

}
BOOL avMatchRemoteFileByHandle(wchar_t *filename, HANDLE Process, HANDLE Handle)
{
	HANDLE			h = NULL;
	ULONG			ret = 0;
	char			*namebuf = NULL;
	BOOLEAN			bMatched = FALSE;
	NTSTATUS		st;
	wchar_t 		*outstr = NULL;

	if(DuplicateHandle(Process, 
		Handle, 
		GetCurrentProcess( ), 
		&h, 
		0, 
		FALSE, 
		DUPLICATE_SAME_ACCESS))
	{

		avNtQueryObject(h, FileNameInformation, NULL, 0, &ret, 100);
		if (ret == 0)
		{
			ret = MAX_PATH;
		}
		namebuf = new char[ret];
		if (namebuf == NULL)
		{
			DebugPrint("No memory available\n");
			CloseHandle(h);
			return FALSE;
		}
		st = avNtQueryObject(h, FileNameInformation, namebuf, ret, NULL, 100);
		POBJECT_NAME_INFORMATION name = (POBJECT_NAME_INFORMATION)namebuf;
		if (st >= 0)
		{	
			outstr = new wchar_t[MAX_PATH];
			if (outstr == NULL)
			{
				DebugPrint("No memory available");
				if (namebuf)
				{
					delete []namebuf;
				}
				CloseHandle(h);
				return FALSE;
			}
			memset(outstr, 0, MAX_PATH);
			outstr[0] = L'A';
			outstr[1] = L':';
			if (name->Name.Length > 23 && \
				memicmp(name->Name.Buffer, L"\\Device\\HardDiskVolume", 44) == 0)
			{
				outstr[0] = name->Name.Buffer[22] - L'1' + L'C';
				memcpy(&outstr[2], &name->Name.Buffer[23], name->Name.Length-23*2);
				outstr[name->Name.Length/2-21] = 0;
			}

			if (wcsncmp(outstr, filename, wcslen(filename)) == 0)
			{
				DebugPrint("Found:%ws\n",filename);
				bMatched = TRUE;
			}
			delete []outstr;
			outstr = NULL;
		}
		if (namebuf)
		{
			delete []namebuf;
		}
		CloseHandle(h);
		return bMatched;
	}

	return FALSE;
}

PULONG avGetHandleList()
{
   ULONG 			cbBuffer = 0x1000;
   PULONG 			pBuffer = new ULONG[cbBuffer];
   NTSTATUS 		Status;
   DWORD 			dwNumBytesRet = 0x10;
   do
   {
       Status = NtQuerySystemInformation(
		   SystemHandleInformation,
		   pBuffer,
		   cbBuffer * sizeof * pBuffer,
		   &dwNumBytesRet);

       if (Status == STATUS_INFO_LENGTH_MISMATCH)
       {
           delete [] pBuffer;
           pBuffer = new ULONG[cbBuffer *= 2];
       }
       else if (!NT_SUCCESS(Status))
       {
           delete [] pBuffer;
           return NULL;
       }
   } while (Status == STATUS_INFO_LENGTH_MISMATCH);

   return pBuffer;
}

BOOL avCloseAllHandlesForFile(wchar_t *filename)
{
	ULONG							dSize = 0;
    ULONG							dData = 0;
	ULONG							NumOfHandle = 0;
	BOOL							rtn = TRUE;
	ULONG							i;
	PSYSTEM_HANDLE_INFORMATION 		pSysHandleInfo;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO	handleTEI;
	char							*namebuf = NULL;
	char							namenull[1000];
	HANDLE							hTmp;
	UCHAR							TypeNum;
	HANDLE							hProcess;
	BOOLEAN							bClosed = FALSE;
	

	GetModuleFileName(NULL,namenull,MAX_PATH);
	hTmp = CreateFile(namenull,
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hTmp == 0)
	{
		return FALSE;
	}

	PULONG buf = avGetHandleList();
	if (buf == NULL)
	{
		CloseHandle(hTmp);
		return FALSE;
	}

	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)buf;
	NumOfHandle = pSysHandleInfo->NumberOfHandles;

	/* We get file object header type  dynamically */
	for (i = 0; i < NumOfHandle ;i++)
	{
		handleTEI = pSysHandleInfo->Handles[i];
		if (GetCurrentProcessId() == handleTEI.UniqueProcessId &&
			handleTEI.HandleValue == (USHORT)hTmp)
				TypeNum = handleTEI.ObjectTypeIndex;
	}
	CloseHandle(hTmp);

	for(i = 0; i < NumOfHandle ;i++)
	{
		handleTEI = pSysHandleInfo->Handles[i];
		if (handleTEI.ObjectTypeIndex != TypeNum)
			continue;

		hProcess = OpenProcess(PROCESS_ALL_ACCESS,
			FALSE,
			handleTEI.UniqueProcessId);
		if(hProcess)
		{
			if(avMatchRemoteFileByHandle(filename, hProcess, (HANDLE)handleTEI.HandleValue))
			{
				if (avCloseHandle(hProcess, (HANDLE)handleTEI.HandleValue)) 
				{
					DebugPrint("file:%ws handle closed\n", filename);
					bClosed = TRUE;
				}
			}
			CloseHandle(hProcess);
		}
	}
	if (buf)
	{
		delete [] buf;
	}
	return bClosed;
}

//We test the function avCloseAllHandlesForFile() here

int main(int argc, char *argv[])
{

	if (argc < 2)
	{
		DebugPrint("Please run it as: closehandle filename\n");
		exit(1);
	}

	wchar_t filename[MAX_PATH + 1];
	ZeroMemory(filename, MAX_PATH + 1);

	int num = MultiByteToWideChar(CP_OEMCP,MB_PRECOMPOSED,argv[1],
		strlen(argv[1]),filename,MAX_PATH + 1);

	filename[strlen(argv[1])] = L'\0';

	if (!InitNTDLL())
	{
		DebugPrint("%s\n","InitNTDLL() failed");
		exit(1);
	}

	if (avCloseAllHandlesForFile(filename))
	{
		DebugPrint("%s\n", "file handle closed");
	}
	else
	{
		DebugPrint("%s\n", "no file handle closed");
	}

	CloseNTDLL();
	return 0;
} 