#include "precomp.h"

BOOL ntQueryObjectName(PVOID pObject, PUNICODE_STRING ustrObjName, BOOL bAllocateName)
{
	PVOID			pNameBuffer = NULL;
	DWORD			dwSize = 0;
	NTSTATUS		ntStatus = 0;
	__try
	{
		dwSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);

		pNameBuffer = ExAllocatePoolWithTag(PagedPool, dwSize, 'CORP');

		if(pNameBuffer == NULL)
			return FALSE;

		ntStatus = ObQueryNameString(pObject, 
								   pNameBuffer,
								   dwSize,
								   &dwSize);

		if((ntStatus == STATUS_INFO_LENGTH_MISMATCH) ||
		   (ntStatus == STATUS_BUFFER_OVERFLOW) ||
		   (ntStatus == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(pNameBuffer);
			pNameBuffer = NULL;

			pNameBuffer = ExAllocatePoolWithTag(PagedPool, dwSize, 'CORP');

			if(pNameBuffer == NULL)
			{
				return FALSE;
			}
			
			ntStatus = ObQueryNameString(pObject, 
								   pNameBuffer,
								   dwSize,
								   &dwSize);

		}

		if(NT_SUCCESS(ntStatus))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)pNameBuffer;

			if(bAllocateName)
			{
				ustrObjName->Buffer = ExAllocatePoolWithTag(PagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'rtpR');
		
				if(ustrObjName->Buffer)
				{
					RtlZeroMemory(ustrObjName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					ustrObjName->Length = 0;
					ustrObjName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(ustrObjName, &pNameInfo->Name);
				}
				else
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(ustrObjName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	if(pNameBuffer)
	{
		ExFreePool(pNameBuffer);
		pNameBuffer = NULL;
	}

	return NT_SUCCESS(ntStatus);
}

BOOL ntGetNameFromObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,
								   WCHAR * NameBuffer,
								   DWORD NameBufferSize)
{
	BOOL				bRtn				= FALSE;
	UNICODE_STRING		uTarget				= {0,0,0};
	UNICODE_STRING		ustrCapturedName	= {0,0,0};
	KPROCESSOR_MODE		PrevMode			= ExGetPreviousMode();
	OBJECT_ATTRIBUTES	oaAttributes		= {0};
	BOOL				bGotRootDir			= FALSE;

	__try
	{
		if(PrevMode != KernelMode)
		{
			oaAttributes = ProbeAndReadObjectAttributes(ObjectAttributes);
		}
		else
			oaAttributes = *ObjectAttributes;

		if((oaAttributes.ObjectName == NULL) &&
		   (oaAttributes.RootDirectory == NULL))
		{
			return FALSE;
		}

		uTarget.Length = 0;
		uTarget.Buffer = NameBuffer;
		uTarget.MaximumLength = (USHORT)NameBufferSize;

		if(oaAttributes.RootDirectory)
		{
			PVOID Object = NULL;
			NTSTATUS status = 0;

			status = ObReferenceObjectByHandle(
					oaAttributes.RootDirectory,
					0,
					NULL,
					PrevMode,
					&Object,
					NULL
					);

			if(NT_SUCCESS(status))
			{
				if(ntQueryObjectName(Object, &uTarget, FALSE) == FALSE)
				{
					ObDereferenceObject(Object);
					return FALSE;
				}

				bGotRootDir = TRUE;
				ObDereferenceObject(Object);
			}
			else
			{
				return FALSE;
			}

			if(oaAttributes.ObjectName)
				RtlAppendUnicodeToString(&uTarget, L"\\");
		}

		if(oaAttributes.ObjectName)
		{
			if(PrevMode != KernelMode)
			{
				ustrCapturedName = ProbeAndReadUnicodeString(oaAttributes.ObjectName);

				ProbeForRead(ustrCapturedName.Buffer,
							 ustrCapturedName.Length,
							 sizeof(WCHAR));
			}
			else
				ustrCapturedName = *oaAttributes.ObjectName;

			if(bGotRootDir)
			{
				RtlAppendUnicodeStringToString(&uTarget, &ustrCapturedName);
			}
			else
			{
				RtlCopyUnicodeString(&uTarget, &ustrCapturedName);
			}

			bRtn = TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		bRtn = FALSE;
	}

	return bRtn;
}

NTSTATUS  ntGetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
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