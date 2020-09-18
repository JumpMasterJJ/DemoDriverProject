#include <ntddk.h>
#include <ntimage.h>
#include <ntdef.h>
#include "DelFile.h"


PDEVICE_OBJECT	g_HookDevice;

NTSTATUS dfQuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
	)                                  
{
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;
    HANDLE handle;
   
    InitializeObjectAttributes(
		&oa, 
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
        0, 
		0);
   
    status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
   
    LinkTarget->MaximumLength = 1024*sizeof(WCHAR);
    LinkTarget->Length = 0;
    LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'A0');
    if (!LinkTarget->Buffer)
    {
        ZwClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);
   
    status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
    ZwClose(handle);
   
    if (!NT_SUCCESS(status))
    {
        ExFreePool(LinkTarget->Buffer);
    }
   
    return status;
}

BOOLEAN dfCloseFileHandle(WCHAR *name)
//第一次调用的参数:L"\\??\\c:\\ha ha.doc"
{
	
	NTSTATUS					 status;
	PVOID						 buf   = NULL;
	PSYSTEM_HANDLE_INFORMATION 	 pSysHandleInfo;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO handleTEI;

	ULONG						size  = 1;
	ULONG						NumOfHandle = 0;
	ULONG						i;
	CLIENT_ID 					cid;
	HANDLE						hHandle;
	HANDLE						hProcess;
	HANDLE 						hDupObj;
	HANDLE						hFile;
	HANDLE						link_handle;
	OBJECT_ATTRIBUTES 			oa;
	ULONG						FileType; 
	ULONG						processID;
	UNICODE_STRING 				uLinkName;
	UNICODE_STRING				uLink;
	OBJECT_ATTRIBUTES 			objectAttributes;
	IO_STATUS_BLOCK 		 	IoStatus;
	ULONG 						ulRet;
    PVOID    			 		fileObject;
	POBJECT_NAME_INFORMATION 	pObjName;
	UNICODE_STRING				delFileName = {0};
	int							length;
	WCHAR						wVolumeLetter[3];
	WCHAR						*pFilePath;
	UNICODE_STRING				uVolume;
	UNICODE_STRING				uFilePath;
	UNICODE_STRING 				NullString = RTL_CONSTANT_STRING(L"");
	BOOLEAN					bRet = FALSE;


	for ( size = 1; ; size *= 2 )
	{
		if ( NULL == ( buf = ExAllocatePoolWithTag(NonPagedPool,size, 'FILE') ) )
		{
			DbgPrint(("alloc mem failed\n"));
			goto Exit;
		}
		RtlZeroMemory( buf ,size );
		//得到的是全局句柄??? 还是所有进程的句柄表???
		status = ZwQuerySystemInformation( SystemHandleInformation, buf, size, NULL );
		if ( !NT_SUCCESS( status ) )
		{
			if ( STATUS_INFO_LENGTH_MISMATCH == status )
			{
				ExFreePool( buf );
				buf = NULL;
			}
			else
			{
				DbgPrint(( "ZwQuerySystemInformation() failed"));
				goto Exit;
			}
		}
		else
		{
			break;
		}
	}

	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)buf;
	NumOfHandle = pSysHandleInfo->NumberOfHandles;

	

	/* Get the volume character like C: */
	//\??\c:\haha.doc-->\device\harddiskvolume3\haha.doc
	//因为虽然两种文件路径格式都可以正确表示路径
	//但是在内核中通过函数获得的路径格式是第二种
	//所以需要转换格式来正确的比对文件

	wVolumeLetter[0] = name[4];
	wVolumeLetter[1] = name[5];
	wVolumeLetter[2] = 0;
	uLinkName.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256 + sizeof(ULONG), 'A1');
	uLinkName.MaximumLength = 256;
	RtlInitUnicodeString(&uVolume, wVolumeLetter);
	RtlInitUnicodeString( &uLink, L"\\DosDevices\\");
	RtlCopyUnicodeString(&uLinkName, &uLink);
	
	//uLinkname == "\\DosDevices\\C:\\"
	status = RtlAppendUnicodeStringToString(&uLinkName, &uVolume);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RtlAppendUnicodeStringToString() failed"));
		return FALSE;
	}
	
	//获取C盘的 Symbol_Link
	dfQuerySymbolicLink(&uLinkName, &delFileName);
	RtlFreeUnicodeString(&uLinkName);
	KdPrint(("delFileName:%wZ", &delFileName));

	pFilePath = (WCHAR *) &name[6];
	RtlInitUnicodeString( &uFilePath, pFilePath);

	//delFileName == C盘的Symbol_Link + "haha.doc"
	RtlAppendUnicodeStringToString(&delFileName, &uFilePath);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RtlAppendUnicodeStringToString() failed"));
		return FALSE;
	}

	KdPrint(("delFile:%wZ", &delFileName));

	for(i = 0; i < NumOfHandle ;i++)
	{
		handleTEI = pSysHandleInfo->Handles[i];

		//判断Handle的类型
		//如果不是文件句柄或者设备句柄直接Continue
		if (handleTEI.ObjectTypeIndex != 25 && handleTEI.ObjectTypeIndex != 28)//28文件,25设备对象
			continue;

		processID = (ULONG) handleTEI.UniqueProcessId;
		cid.UniqueProcess = (HANDLE)processID;
		cid.UniqueThread = (HANDLE)0;
		//对方进程的句柄,不能直接使用,自己的句柄表没有,需要复制
		hHandle = (HANDLE)handleTEI.HandleValue;
		InitializeObjectAttributes( &oa ,NULL ,0 ,NULL ,NULL );
		status = ZwOpenProcess( &hProcess ,PROCESS_DUP_HANDLE ,&oa ,&cid );
		if ( !NT_SUCCESS( status ) )
		{
			KdPrint(( "ZwOpenProcess:%d Fail ", processID));
			continue;
		}

		status = ZwDuplicateObject( hProcess ,hHandle ,NtCurrentProcess() ,&hDupObj ,\
		 PROCESS_ALL_ACCESS ,0 ,DUPLICATE_SAME_ACCESS );
		if ( !NT_SUCCESS( status ) )
		{
			DbgPrint(( "ZwDuplicateObject1 : Fail " ));
			continue;
		}
		status = ObReferenceObjectByHandle(
			  hDupObj,
			  FILE_ANY_ACCESS,
			  0,
			  KernelMode,
			  &fileObject,
			  NULL);
		
		if (!NT_SUCCESS(status))
		{
			DbgPrint(( "ObReferenceObjectByHandle : Fail " ));
			continue;
		}  

		pObjName = (POBJECT_NAME_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, \
		    sizeof (OBJECT_NAME_INFORMATION) + 1024 * sizeof (WCHAR), 'A1');

		if (STATUS_SUCCESS != (status = ObQueryNameString(fileObject, pObjName, \
		    sizeof (OBJECT_NAME_INFORMATION) + 1024 * sizeof (WCHAR), &ulRet)))
		{
			//Delete Object Before Query FileName Failed
		   ObDereferenceObject(fileObject);
		   continue;
		}
		if (RtlCompareUnicodeString(&pObjName->Name, &delFileName, TRUE) == 0)
		{
			//When You Found File

			ObDereferenceObject(fileObject);
			ZwClose(hDupObj);

			//Close Source Handle / Close Handle 
			status = ZwDuplicateObject( hProcess ,hHandle ,NtCurrentProcess() ,&hDupObj ,\
			 PROCESS_ALL_ACCESS ,0 ,DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE );
			if ( !NT_SUCCESS( status ) )
			{
				DbgPrint(( "ZwDuplicateObject2 : Fail " ));
				//return FALSE;
			}
			else
			{
				ZwClose(hDupObj);
				bRet = TRUE;
				//return TRUE;
			}
			break;

		}
			
		ExFreePool(pObjName);
		pObjName = NULL;

		ObDereferenceObject(fileObject);
		ZwClose( hDupObj );
		ZwClose( hProcess );

	}

Exit:
	if (pObjName != NULL)
	{
		ExFreePool(pObjName);
		pObjName = NULL;
	}
	if (delFileName.Buffer != NULL)
	{
		ExFreePool(delFileName.Buffer);	
	}
	if ( buf != NULL )
	{
		ExFreePool( buf );
		buf = NULL;
	}
	return(bRet);

}

NTSTATUS
dfOpenFile(WCHAR* name,PHANDLE phFileHandle, ACCESS_MASK access,ULONG share)
//第一次调用的参数:name, &handle, FILE_READ_ATTRIBUTES|DELETE,FILE_SHARE_DELETE
{

   IO_STATUS_BLOCK iosb;
   NTSTATUS stat;
   OBJECT_ATTRIBUTES oba;
   UNICODE_STRING nameus;

   //检查IRQL级别,IoCreateFile必须运行在PASSIVE_LEVEL
   if(KeGetCurrentIrql()>PASSIVE_LEVEL){return 0;}

   RtlInitUnicodeString(&nameus,name);

   InitializeObjectAttributes(
		&oba,
		&nameus,
		OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
		0,
		0);
   stat=IoCreateFile(
		phFileHandle,
		access,
		&oba,
		&iosb,
		0,
		FILE_ATTRIBUTE_NORMAL,
		share,
		FILE_OPEN,
		0,
		NULL,
		0,
		0,
		NULL,
		IO_NO_PARAMETER_CHECKING);

	return stat;
}

NTSTATUS
dfSkillSetFileCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    Irp->UserIosb->Status = Irp->IoStatus.Status;
    Irp->UserIosb->Information = Irp->IoStatus.Information;

    //Set Event Info To Noticefy Upper Driver, Complete Deletion
    KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

    IoFreeIrp(Irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN dfDelFile(WCHAR* name)
//第一次调用的参数:L"\\??\\c:\\ha ha.doc"
{
    NTSTATUS        ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT    fileObject;
    PDEVICE_OBJECT  DeviceObject;
    PIRP            Irp;
    KEVENT          event;
    FILE_DISPOSITION_INFORMATION  FileInformation;
    IO_STATUS_BLOCK ioStatus;
    PIO_STACK_LOCATION irpSp;
    PSECTION_OBJECT_POINTERS pSectionObjectPointer;
    HANDLE handle;


    ntStatus = dfOpenFile(name, &handle, FILE_READ_ATTRIBUTES|DELETE,FILE_SHARE_DELETE);
	if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND ||
		ntStatus == STATUS_OBJECT_PATH_NOT_FOUND )
	{
		KdPrint(("No such file"));
		return FALSE;
	}
	else if (!NT_SUCCESS(ntStatus))
	{
		//情况一:文件被其他进程打开,并独占
		if (dfCloseFileHandle(name))//遍历全局句柄表，关闭独占打开的句柄
		{
			ntStatus = dfOpenFile(name, &handle, FILE_READ_ATTRIBUTES|DELETE,FILE_SHARE_DELETE);
			if (!NT_SUCCESS(ntStatus))
				return FALSE;
		}
		else
		{
			return FALSE;
		}
	}

    ntStatus = ObReferenceObjectByHandle(handle,
        DELETE,
        *IoFileObjectType,
        KernelMode,
        &fileObject,
        NULL);

    if (!NT_SUCCESS(ntStatus))
    {
    	DbgPrint("ObReferenceObjectByHandle() Failed");
		ZwClose(handle);
        return FALSE;
    }  

    //找到文件对应的磁盘分区的设备对象
    DeviceObject = IoGetRelatedDeviceObject(fileObject);
    //构造IRP 来删除文件
    Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);

    if (Irp == NULL)
    {
        ObDereferenceObject(fileObject);
		ZwClose(handle);
        return FALSE;
    }

    //构建一个Delete Event完成线程同步
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
   
    FileInformation.DeleteFile = TRUE;

    //Init IRP
    Irp->AssociatedIrp.SystemBuffer = &FileInformation;
    Irp->UserEvent = &event;
    Irp->UserIosb = &ioStatus;
    Irp->Tail.Overlay.OriginalFileObject = fileObject;
    Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    Irp->RequestorMode = KernelMode;
   
    irpSp = IoGetNextIrpStackLocation(Irp);
    irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
    irpSp->DeviceObject = DeviceObject;
    irpSp->FileObject = fileObject;
    irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
    irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
    irpSp->Parameters.SetFile.FileObject = fileObject;

    //设置IRP完成后调用的函数
    IoSetCompletionRoutine(
            Irp,
            //File Delete Successfully Will Call This Func
            dfSkillSetFileCompletion,
            &event,
            TRUE,
            TRUE,
            TRUE);
	
	//情况二:正在运行的程序		
	//删除正在运行中的exe所做的处理
	//清空ImageSectionObject和DataSectionObject让系统误以为该程序没有运行
    pSectionObjectPointer = fileObject->SectionObjectPointer;
    if(pSectionObjectPointer)
	{
		pSectionObjectPointer->ImageSectionObject = 0;
		pSectionObjectPointer->DataSectionObject = 0;
	}
	//Call Lower Driver To Complete IRP
    ntStatus = IoCallDriver(DeviceObject, Irp); 
    if (!NT_SUCCESS(ntStatus))
    {
    	 ObDereferenceObject(fileObject);
		 ZwClose(handle);
         return FALSE;
    }  

    //等待删除完成
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
	//IoFreeIrp(Irp);
    ObDereferenceObject(fileObject);
    ZwClose(handle);
    return TRUE;

}


NTSTATUS OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING          deviceLinkUnicodeString;
	PDEVICE_OBJECT	   p_NextObj;


	DbgPrint("OnUnload called\n");

	p_NextObj = DriverObject->DeviceObject;

	if (p_NextObj != NULL)
	{

		RtlInitUnicodeString( &deviceLinkUnicodeString, deviceLinkBuffer );
		IoDeleteSymbolicLink( &deviceLinkUnicodeString );

		IoDeleteDevice( DriverObject->DeviceObject );
	}
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS                ntStatus;
	UNICODE_STRING          deviceNameUnicodeString;
    UNICODE_STRING          deviceLinkUnicodeString;

	RtlInitUnicodeString (&deviceNameUnicodeString,
	    deviceNameBuffer );
	RtlInitUnicodeString (&deviceLinkUnicodeString,
	    deviceLinkBuffer );

	ntStatus = IoCreateDevice ( DriverObject,
	    0,
	    &deviceNameUnicodeString,
	    FILE_DEVICE_SWAP,
	    0,
	    TRUE,
	    &g_HookDevice );

	if(! NT_SUCCESS(ntStatus))
	{
	      DbgPrint(("Failed to create device!\n"));
	      return ntStatus;
	 }

	/* We test the DelFile() function here */	
	if (dfDelFile(L"\\??\\c:\\ha ha.doc"))
	{
		KdPrint(("Deleted"));
	}
	else
	{
		KdPrint(("Failed"));
	}
	if (dfDelFile(L"\\??\\c:\\filedelet.exe"))
	{
		KdPrint(("Deleted"));
	}
	else
	{
		KdPrint(("Failed"));
	}

	ntStatus = IoCreateSymbolicLink (&deviceLinkUnicodeString,
	    &deviceNameUnicodeString );
	if(! NT_SUCCESS(ntStatus)) 
	{
		 IoDeleteEntryDevice(DriverObject->DeviceObject);
	        DbgPrint("Failed to create symbolic link!\n");
	        return ntStatus;
	 }

	DriverObject->DriverUnload  = OnUnload;
	return STATUS_SUCCESS;
}
