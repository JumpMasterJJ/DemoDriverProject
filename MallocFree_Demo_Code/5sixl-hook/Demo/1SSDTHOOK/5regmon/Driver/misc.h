#define ProbeAndReadUnicodeString(Source)  \
    (((Source) >= (UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) ? \
        (*(volatile UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) : (*(volatile UNICODE_STRING *)(Source)))

#define ProbeAndReadObjectAttributes(Source)  \
					(((Source) >= (OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) ? \
						(*( volatile OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) : (*( volatile OBJECT_ATTRIBUTES *)(Source)))


typedef enum _OBJECT_INFO_CLASS {
    ObjectBasicInfo,
		ObjectNameInfo,
		ObjectTypeInfo,
		ObjectAllTypesInfo,
		ObjectProtectionInfo
} OBJECT_INFO_CLASS;

BOOL MyObQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName);

BOOL GetNameFromObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,
								   WCHAR * NameBuffer,
								   DWORD NameBufferSize);
NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
BOOL MyObQueryObjectName(HANDLE objHandle, PUNICODE_STRING objName, BOOL allocateName);
BOOL MyProbeKeyHandle(HANDLE KeyHandle, DWORD Access);
