#include <Ntifs.h>
#include <ntddk.h>
#include <windef.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Goodbye!\n");
}

BOOLEAN IsPatternMatch(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase)
{
	return FsRtlIsNameInExpression(
    			Expression,
    			Name,
    			IgnoreCase,//如果这里设置为TRUE,那么Expression必须是大写的
    			NULL
    			); 

}

BOOL PatternMatch(WCHAR * pat, WCHAR * str)
{
   register WCHAR * s;
   register WCHAR * p;
   BOOL star = FALSE;

loopStart:
   for (s = str, p = pat; *s; ++s, ++p) {
      switch (*p) {
         case L'?':
            if (*s == L'.') goto starCheck;
            break;
         case L'*':
            star = TRUE;
            str = s, pat = p;
            if (!*++pat) return TRUE;
            goto loopStart;
         default:
            //if (Lower(*s) != Lower(*p))
               goto starCheck;
            break;
      } 
   } 
   if (*p == L'*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   str++;
   goto loopStart;
}

BOOL PatternNMatch(WCHAR * pat, WCHAR * str, DWORD count)
{
   register WCHAR * s;
   register WCHAR * p;
   BOOL star = FALSE;
   DWORD dwCount = count;

loopStart:
   for (s = str, p = pat; dwCount>0; --dwCount, ++s, ++p) {
      switch (*p) {
         case L'?':
            if (*s == L'.') goto starCheck;
            break;
         case L'*':
            star = TRUE;
            str = s, pat = p;
            if (!*++pat) return TRUE;
            goto loopStart;
         default:
            //if (Lower(*s) != Lower(*p))
               goto starCheck;
            break;
      } 
   } 
   if (*p == L'*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   str++;
   dwCount--;
   goto loopStart;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{

	UNICODE_STRING uExpression = {0};
	UNICODE_STRING uName	   = {0};

	RtlInitUnicodeString(&uExpression, L"C:\\WINDOWS\\SYSTEM32\\*.SYS");
	RtlInitUnicodeString(&uName, L"c:\\Windows\\system32\\122222\\2.sys");

	if (IsPatternMatch(&uExpression, &uName, TRUE))
	{
		DbgPrint("Matched\n");
	}
	else
	{
		DbgPrint("Not Matched\n");
	}
	pDriverObject->DriverUnload = DriverUnload;
	
	return STATUS_SUCCESS;

}

