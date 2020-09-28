#define ProbeAndReadUnicodeString(Source)  \
    (((Source) >= (UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) ? \
        (*(volatile UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) : (*(volatile UNICODE_STRING *)(Source)))

#define ProbeAndReadObjectAttributes(Source)  \
					(((Source) >= (OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) ? \
						(*( volatile OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) : (*( volatile OBJECT_ATTRIBUTES *)(Source)))

BOOL ntQueryObjectName(PVOID pObject, PUNICODE_STRING ustrObjName, BOOL bAllocateName);

BOOL ntGetNameFromObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,
								   WCHAR * NameBuffer,
								   DWORD NameBufferSize);
NTSTATUS  ntGetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
