#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <ntimage.h>
#include "Ioctlcmd.h"
#include "main.h"
#include "hook.h"
#include "misc.h"

#define SEC_IMAGE    0x1000000 

NTSTATUS
NTAPI
ZwQueryInformationProcess(
						  __in HANDLE ProcessHandle,
						  __in PROCESSINFOCLASS ProcessInformationClass,
						  __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
						  __in ULONG ProcessInformationLength,
						  __out_opt PULONG ReturnLength
    );