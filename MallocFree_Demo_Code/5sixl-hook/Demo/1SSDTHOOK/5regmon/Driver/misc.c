#include "precomp.h"


BOOL MyProbeKeyHandle(HANDLE KeyHandle, DWORD Access)
{
	NTSTATUS status = 0;
	PVOID KeyObj = NULL;
	
	status = ObReferenceObjectByHandle(
		KeyHandle,
		Access,
		NULL,
		ExGetPreviousMode(),
		&KeyObj,
		NULL
		);
	
	if(NT_SUCCESS(status))
	{
		ObDereferenceObject(KeyObj);
		return TRUE;
	}
	if(status == STATUS_ACCESS_DENIED)
		return TRUE;
	
	return FALSE;
}

BOOL MyObQueryObjectName(HANDLE objHandle, PUNICODE_STRING objName, BOOL allocateName)
{
	PVOID buffer = NULL;
	DWORD reqSize = 0;
	NTSTATUS status = 0;
	__try
	{
		reqSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);
		
		buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'SGER');
		
		if(buffer == NULL)
			return FALSE;
		
		status = ZwQueryObject(objHandle, 
			ObjectNameInfo,
			buffer,
			reqSize,
			&reqSize);
		
		if((status == STATUS_INFO_LENGTH_MISMATCH) ||
			(status == STATUS_BUFFER_OVERFLOW) ||
			(status == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(buffer);
			buffer = NULL;
			
			buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'SGER');
			
			if(buffer == NULL)
			{
				return FALSE;
			}
			
			status = ZwQueryObject(objHandle, 
				ObjectNameInfo,
				buffer,
				reqSize,
				&reqSize);

		}
		
		if(NT_SUCCESS(status))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)buffer;
			
			if(allocateName)
			{
				objName->Buffer = ExAllocatePoolWithTag(PagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'SGER');
				
				if(objName->Buffer)
				{
					RtlZeroMemory(objName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					objName->Length = 0;
					objName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(objName, &pNameInfo->Name);
				}
				else
					status = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(objName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	
	if(buffer)
	{
		ExFreePool(buffer);
		buffer = NULL;
	}
	
	return NT_SUCCESS(status);
}

BOOL GetNameFromObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,
								   WCHAR * NameBuffer,
								   DWORD NameBufferSize)
{
	BOOL rtn = FALSE;
	UNICODE_STRING uTarget = {0,0,0};
	UNICODE_STRING CapturedName = {0,0,0};
	KPROCESSOR_MODE PrevMode = ExGetPreviousMode();
	OBJECT_ATTRIBUTES CapturedAttributes;
	BOOL bGotRootDirectory = FALSE;

	__try
	{
		if(PrevMode != KernelMode)
		{
			CapturedAttributes = ProbeAndReadObjectAttributes(ObjectAttributes);
		}
		else
			CapturedAttributes = *ObjectAttributes;

		if((CapturedAttributes.ObjectName == NULL) &&
		   (CapturedAttributes.RootDirectory == NULL))
		{
			return FALSE;
		}

		uTarget.Length = 0;
		uTarget.Buffer = NameBuffer;
		uTarget.MaximumLength = (USHORT)NameBufferSize;

		if(CapturedAttributes.RootDirectory)
		{
			PVOID Object = NULL;
			NTSTATUS status = 0;

			status = ObReferenceObjectByHandle(
					CapturedAttributes.RootDirectory,
					0,
					NULL,
					PrevMode,
					&Object,
					NULL
					);

			if(NT_SUCCESS(status))
			{
				if(MyObQueryObjectName(Object, &uTarget, FALSE) == FALSE)
				{
					ObDereferenceObject(Object);
					return FALSE;
				}

				bGotRootDirectory = TRUE;
				ObDereferenceObject(Object);
			}
			else
			{
				return FALSE;
			}

			if(CapturedAttributes.ObjectName)
				RtlAppendUnicodeToString(&uTarget, L"\\");
		}

		if(CapturedAttributes.ObjectName)
		{
			if(PrevMode != KernelMode)
			{
				CapturedName = ProbeAndReadUnicodeString(CapturedAttributes.ObjectName);

				ProbeForRead(CapturedName.Buffer,
							 CapturedName.Length,
							 sizeof(WCHAR));
			}
			else
				CapturedName = *CapturedAttributes.ObjectName;

			if(bGotRootDirectory)
			{
				RtlAppendUnicodeStringToString(&uTarget, &CapturedName);
			}
			else
			{
				RtlCopyUnicodeString(&uTarget, &CapturedName);
			}

			rtn = TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		rtn = FALSE;
	}

	return rtn;
}

NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
{

    HANDLE               hFile      = NULL;
    ULONG                nNeedSize	= 0;
    NTSTATUS             nStatus    = STATUS_SUCCESS;
    NTSTATUS             nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
    PEPROCESS            Process    = NULL;
    KAPC_STATE           ApcState   = {0};			
    PVOID                lpBuffer   = NULL;
    OBJECT_ATTRIBUTES	 ObjectAttributes = {0};
    IO_STATUS_BLOCK      IoStatus   = {0}; 
    PFILE_OBJECT         FileObject = NULL;
    PFILE_NAME_INFORMATION FileName = NULL;   
    WCHAR                FileBuffer[MAX_PATH] = {0};
    DECLARE_UNICODE_STRING_SIZE(ProcessPath,MAX_PATH);
    DECLARE_UNICODE_STRING_SIZE(DosDeviceName,MAX_PATH);
    
    PAGED_CODE();

    nStatus = PsLookupProcessByProcessId(nPid, &Process);
    if(NT_ERROR(nStatus))
    {
        KdPrint(("%s error PsLookupProcessByProcessId.\n",__FUNCTION__));
        return nStatus;
    }



    __try
    {

        KeStackAttachProcess(Process, &ApcState);
        
        nStatus = ZwQueryInformationProcess(
            NtCurrentProcess(),
            ProcessImageFileName,
            NULL,
            0,
            &nNeedSize
            );

        if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
        {
            KdPrint(("%s NtQueryInformationProcess error.\n",__FUNCTION__)); 
            nStatus = STATUS_MEMORY_NOT_ALLOCATED;
            __leave;

        }

        lpBuffer = ExAllocatePoolWithTag(NonPagedPool, nNeedSize,'GetP');
        if (lpBuffer == NULL)
        {
            KdPrint(("%s ExAllocatePoolWithTag error.\n",__FUNCTION__));
            nStatus = STATUS_MEMORY_NOT_ALLOCATED;
            __leave; 
        }

       nStatus =  ZwQueryInformationProcess(
           NtCurrentProcess(),
           ProcessImageFileName, 
           lpBuffer, 
           nNeedSize,
           &nNeedSize
           );

       if (NT_ERROR(nStatus))
       {
           KdPrint(("%s NtQueryInformationProcess error2.\n",__FUNCTION__));
           __leave;
       }

       RtlCopyUnicodeString(&ProcessPath,(PUNICODE_STRING)lpBuffer);
       InitializeObjectAttributes(
           &ObjectAttributes,
           &ProcessPath,
           OBJ_CASE_INSENSITIVE,
           NULL,
           NULL
           );

       nStatus = ZwCreateFile(
           &hFile,
           FILE_READ_ATTRIBUTES,
           &ObjectAttributes,
           &IoStatus,
           NULL,
           FILE_ATTRIBUTE_NORMAL,
           0,
           FILE_OPEN,
           FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
           NULL,
           0
           );  

       if (NT_ERROR(nStatus))
       {
           hFile = NULL;
           __leave;
       }

       nStatus = ObReferenceObjectByHandle(
           hFile, 
           0,
           *IoFileObjectType, 
           KernelMode, 
           (PVOID*)&FileObject,
           NULL
           );

       if (NT_ERROR(nStatus))
       {
           FileObject = NULL;
           __leave;
       }
       
       FileName = (PFILE_NAME_INFORMATION)FileBuffer;
       
       nStatus = ZwQueryInformationFile(
           hFile,
           &IoStatus,
           FileName,
           sizeof(WCHAR)*MAX_PATH,
           FileNameInformation
           );

       if (NT_ERROR(nStatus))
       {
           __leave;
       }

       if (FileObject->DeviceObject == NULL)
       {
           nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
           __leave;
       }

       nDeviceStatus = RtlVolumeDeviceToDosName(FileObject->DeviceObject,&DosDeviceName);

    }
    __finally
    {
        if (NULL != FileObject)
        {
            ObDereferenceObject(FileObject);
        }

        if (NULL != hFile)
        {
            ZwClose(hFile);
        }

        if (NULL != lpBuffer)
        {
            ExFreePool(lpBuffer);
        }

        KeUnstackDetachProcess(&ApcState);


    }

    if (NT_SUCCESS(nStatus))
    {
        RtlInitUnicodeString(&ProcessPath,FileName->FileName);

        if (NT_SUCCESS(nDeviceStatus))
        {
            RtlCopyUnicodeString(FullPath,&DosDeviceName);
            RtlUnicodeStringCat(FullPath,&ProcessPath);
        }
        else
        {
            RtlCopyUnicodeString(FullPath,&ProcessPath);
        }
    }


    return nStatus;
}